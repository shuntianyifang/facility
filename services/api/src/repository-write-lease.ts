import { newId } from "@facility/core";
import { type FacilityDb, insertAuditEvent, runRepositoryWriteLeases } from "@facility/db";
import { and, eq } from "drizzle-orm";
import { ApiError } from "./errors.js";

const GIT_SHA = /^[a-f0-9]{40}$/i;
export const REPOSITORY_WRITE_EXPIRY_SAFETY_MS = 5 * 60_000;

export type RepositoryWriteLeaseRow = Pick<
  typeof runRepositoryWriteLeases.$inferSelect,
  | "id"
  | "repoId"
  | "provider"
  | "status"
  | "requestedBranch"
  | "authorizedBranch"
  | "baseSha"
  | "permissions"
  | "issuedAt"
  | "expiresAt"
  | "failureReason"
>;

export type RepositoryWriteLeaseEligibility =
  | {
      eligible: true;
      remoteInspections: Array<{
        leaseId: string;
        repoId: string;
        authorizedBranch: string;
        baseSha: string;
      }>;
    }
  | {
      eligible: false;
      reason:
        | "repository_write_lease_malformed"
        | "repository_write_tracking_unavailable"
        | "repository_write_lease_reserved"
        | "repository_write_lease_ambiguous"
        | "repository_write_credential_persistent"
        | "repository_write_credential_unexpired";
      leaseId?: string;
      expiresAt?: Date;
    };

/**
 * Pure, fail-closed barrier consumed by the follow-up governed retry PR.
 * Every lease is inspected; a later installation token can never hide an
 * earlier persistent fallback or malformed reservation.
 */
export function repositoryWriteLeaseEligibility(
  values: readonly unknown[],
  now: Date,
  options: { trackingVersion: number },
): RepositoryWriteLeaseEligibility {
  if (options.trackingVersion !== 1) {
    return { eligible: false, reason: "repository_write_tracking_unavailable" };
  }
  const rows: RepositoryWriteLeaseRow[] = [];
  for (const value of values) {
    const parsed = repositoryWriteLeaseRow(value);
    if (!parsed) {
      return { eligible: false, reason: "repository_write_lease_malformed" };
    }
    rows.push(parsed);
  }

  const fallback = rows.find(
    (row) => row.status === "issued" && row.provider === "configured_fallback",
  );
  if (fallback) {
    return {
      eligible: false,
      reason: "repository_write_credential_persistent",
      leaseId: fallback.id,
    };
  }
  const reserved = rows.find((row) => row.status === "reserved");
  if (reserved) {
    return {
      eligible: false,
      reason: "repository_write_lease_reserved",
      leaseId: reserved.id,
    };
  }
  const failed = rows.find((row) => row.status === "failed");
  if (failed) {
    return {
      eligible: false,
      reason: "repository_write_lease_ambiguous",
      leaseId: failed.id,
    };
  }

  const active = rows
    .filter((row) => row.status === "issued")
    .filter(
      (row) =>
        (row.expiresAt?.getTime() ?? Number.POSITIVE_INFINITY) + REPOSITORY_WRITE_EXPIRY_SAFETY_MS >
        now.getTime(),
    )
    .sort(
      (left, right) =>
        (right.expiresAt?.getTime() ?? Number.POSITIVE_INFINITY) -
        (left.expiresAt?.getTime() ?? Number.POSITIVE_INFINITY),
    )[0];
  if (active) {
    return {
      eligible: false,
      reason: "repository_write_credential_unexpired",
      leaseId: active.id,
      ...(active.expiresAt ? { expiresAt: active.expiresAt } : {}),
    };
  }

  return {
    eligible: true,
    remoteInspections: rows
      .filter((row) => row.status === "issued")
      .map((row) => ({
        leaseId: row.id,
        repoId: row.repoId,
        authorizedBranch: row.authorizedBranch,
        baseSha: row.baseSha,
      })),
  };
}

export type RemoteRepositoryWriteState =
  | { state: "safe_absent"; pullRequestCount: 0 }
  | { state: "safe_unchanged"; headSha: string; pullRequestCount: 0 }
  | {
      state: "durable_output";
      refState: "absent" | "unchanged" | "changed";
      headSha?: string;
      pullRequestCount: number;
    }
  | { state: "indeterminate" };

export async function inspectRemoteRepositoryWriteOutput(
  client: {
    assertRepositoryAccessible: () => Promise<void>;
    getRef: (branch: string) => Promise<string>;
    listPullRequestsForHead: (
      branch: string,
    ) => Promise<{ pullRequests: readonly unknown[]; hasNextPage: boolean }>;
  },
  authorizedBranch: string,
  baseSha: string,
): Promise<RemoteRepositoryWriteState> {
  const normalizedBaseSha = normalizeGitSha(baseSha);
  if (!normalizedBaseSha || !validGithubBranch(authorizedBranch)) {
    return { state: "indeterminate" };
  }
  try {
    // A ref 404 alone is ambiguous: GitHub also uses it for an inaccessible
    // repository. Prove repository access first, then inspect the exact ref and
    // every PR state for the same head.
    await client.assertRepositoryAccessible();
    const [headResult, pullRequestPage] = await Promise.all([
      client
        .getRef(authorizedBranch)
        .then((headSha) => ({ found: true as const, headSha }))
        .catch((error) => {
          if (githubStatus(error) === 404) return { found: false as const, headSha: null };
          throw error;
        }),
      client.listPullRequestsForHead(authorizedBranch),
    ]);
    if (pullRequestPage.hasNextPage) return { state: "indeterminate" };
    const pullRequestCount = pullRequestPage.pullRequests.length;
    if (!headResult.found) {
      return pullRequestCount > 0
        ? { state: "durable_output", refState: "absent", pullRequestCount }
        : { state: "safe_absent", pullRequestCount: 0 };
    }
    const headSha = normalizeGitSha(headResult.headSha);
    if (!headSha) return { state: "indeterminate" };
    const refState = headSha === normalizedBaseSha ? "unchanged" : "changed";
    if (pullRequestCount > 0 || refState === "changed") {
      return { state: "durable_output", refState, headSha, pullRequestCount };
    }
    return { state: "safe_unchanged", headSha, pullRequestCount: 0 };
  } catch {
    return { state: "indeterminate" };
  }
}

export async function selectAvailableRepositoryWriteBranch(
  client: {
    assertRepositoryAccessible: () => Promise<void>;
    getRef: (branch: string) => Promise<string>;
    listPullRequestsForHead: (
      branch: string,
    ) => Promise<{ pullRequests: readonly unknown[]; hasNextPage: boolean }>;
  },
  requestedBranch: string,
  runId: string,
) {
  if (!validGithubBranch(requestedBranch)) {
    throw new ApiError(
      409,
      "repository_write_branch_unavailable",
      "Repository write branch is invalid",
    );
  }
  try {
    await client.assertRepositoryAccessible();
  } catch {
    throw new ApiError(
      409,
      "repository_write_branch_unavailable",
      "Facility could not verify repository access",
    );
  }
  // The run id is globally unique and part of the very first candidate. Two
  // independent Builders therefore cannot reserve the same future head after
  // both observe the human-requested semantic name as absent.
  const runSuffix = runId.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!runSuffix) {
    throw new ApiError(
      409,
      "repository_write_branch_unavailable",
      "Repository write run identity is invalid",
    );
  }
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const candidate = `${requestedBranch}-${runSuffix}${attempt === 0 ? "" : `-${attempt + 1}`}`;
    if (!validGithubBranch(candidate)) break;
    try {
      await client.getRef(candidate);
    } catch (error) {
      if (githubStatus(error) === 404) {
        try {
          const pullRequests = await client.listPullRequestsForHead(candidate);
          if (pullRequests.hasNextPage) {
            throw new Error("github_pull_request_pagination_ambiguous");
          }
          // A deleted ref may retain open, closed or merged PR history. Never
          // reuse that head name for a new run; move to a collision suffix.
          if (pullRequests.pullRequests.length === 0) return candidate;
          continue;
        } catch {
          throw new ApiError(
            409,
            "repository_write_branch_unavailable",
            "Facility could not verify repository branch pull-request history",
          );
        }
      }
      throw new ApiError(
        409,
        "repository_write_branch_unavailable",
        "Facility could not verify an available repository write branch",
      );
    }
  }
  throw new ApiError(
    409,
    "repository_write_branch_unavailable",
    "No collision-free repository write branch is available",
  );
}

export async function reserveRepositoryWriteLease(
  db: FacilityDb,
  input: {
    orgId: string;
    projectId: string;
    runId: string;
    repoId: string;
    requestedBranch: string;
    authorizedBranch: string;
    baseSha: string;
    permissions: string[];
    provider?: "github_installation" | "configured_fallback";
  },
) {
  const id = newId("rwl");
  const provider = input.provider ?? "github_installation";
  const permissions = canonicalPermissions(input.permissions);
  const baseSha = normalizeGitSha(input.baseSha);
  if (
    !baseSha ||
    !validGithubBranch(input.requestedBranch) ||
    !validGithubBranch(input.authorizedBranch) ||
    !permissions
  ) {
    throw new ApiError(
      409,
      "repository_write_lease_invalid",
      "Repository write lease evidence is invalid",
    );
  }
  const row = (
    await db
      .insert(runRepositoryWriteLeases)
      .values({
        id,
        orgId: input.orgId,
        projectId: input.projectId,
        runId: input.runId,
        repoId: input.repoId,
        provider,
        requestedBranch: input.requestedBranch,
        authorizedBranch: input.authorizedBranch,
        baseSha,
        permissions,
      })
      .returning()
  )[0];
  if (!row) throw new ApiError(500, "repository_write_lease_failed", "Lease was not reserved");
  await insertAuditEvent(db, {
    orgId: input.orgId,
    projectId: input.projectId,
    actor: { type: "agent", id: input.runId },
    action: "run.repository_write_reserved",
    target: { type: "run_repository_write_lease", id },
    payload: {
      runId: input.runId,
      repoId: input.repoId,
      provider,
      requestedBranch: input.requestedBranch,
      authorizedBranch: input.authorizedBranch,
      baseSha,
      permissions,
    },
  });
  return row;
}

export async function markRepositoryWriteLeaseIssued(
  db: FacilityDb,
  lease: typeof runRepositoryWriteLeases.$inferSelect,
  issuedAt: Date,
  expiresAt: Date | null,
) {
  const row = (
    await db
      .update(runRepositoryWriteLeases)
      .set({ status: "issued", issuedAt, expiresAt, updatedAt: issuedAt })
      .where(
        and(
          eq(runRepositoryWriteLeases.id, lease.id),
          eq(runRepositoryWriteLeases.runId, lease.runId),
          eq(runRepositoryWriteLeases.status, "reserved"),
        ),
      )
      .returning()
  )[0];
  if (!row) {
    throw new ApiError(409, "repository_write_lease_changed", "Lease changed before issuance");
  }
  await insertAuditEvent(db, {
    orgId: lease.orgId,
    projectId: lease.projectId,
    actor: { type: "agent", id: lease.runId },
    action: "run.repository_write_issued",
    target: { type: "run_repository_write_lease", id: lease.id },
    payload: {
      runId: lease.runId,
      repoId: lease.repoId,
      provider: lease.provider,
      requestedBranch: lease.requestedBranch,
      authorizedBranch: lease.authorizedBranch,
      baseSha: lease.baseSha,
      permissions: lease.permissions,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt?.toISOString() ?? null,
    },
  });
  return row;
}

export async function markRepositoryWriteLeaseFailed(
  db: FacilityDb,
  lease: typeof runRepositoryWriteLeases.$inferSelect,
  reason: string,
) {
  const failureReason = reason.replace(/[^a-z0-9_.:-]/gi, "_").slice(0, 120) || "issuance_failed";
  const row = (
    await db
      .update(runRepositoryWriteLeases)
      .set({ status: "failed", failureReason, updatedAt: new Date() })
      .where(
        and(
          eq(runRepositoryWriteLeases.id, lease.id),
          eq(runRepositoryWriteLeases.runId, lease.runId),
          eq(runRepositoryWriteLeases.status, "reserved"),
        ),
      )
      .returning({ id: runRepositoryWriteLeases.id })
  )[0];
  if (!row) {
    throw new ApiError(409, "repository_write_lease_changed", "Lease changed before failure");
  }
  await insertAuditEvent(db, {
    orgId: lease.orgId,
    projectId: lease.projectId,
    actor: { type: "agent", id: lease.runId },
    action: "run.repository_write_failed",
    target: { type: "run_repository_write_lease", id: lease.id },
    payload: { runId: lease.runId, repoId: lease.repoId, reason: failureReason },
  });
}

function repositoryWriteLeaseRow(value: unknown): RepositoryWriteLeaseRow | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const status = stringValue(row.status);
  const provider = stringValue(row.provider);
  const id = stringValue(row.id);
  const repoId = stringValue(row.repoId);
  const requestedBranch = stringValue(row.requestedBranch);
  const authorizedBranch = stringValue(row.authorizedBranch);
  const baseSha = normalizeGitSha(row.baseSha);
  const issuedAt = dateValue(row.issuedAt);
  const expiresAt = dateValue(row.expiresAt);
  const failureReason = nullableString(row.failureReason);
  const permissions = canonicalPermissions(row.permissions);
  if (
    !id ||
    !repoId ||
    !requestedBranch ||
    !validGithubBranch(requestedBranch) ||
    !authorizedBranch ||
    !validGithubBranch(authorizedBranch) ||
    !baseSha ||
    !permissions
  ) {
    return null;
  }
  if (status !== "reserved" && status !== "issued" && status !== "failed") return null;
  if (provider !== "github_installation" && provider !== "configured_fallback") return null;
  if ((row.issuedAt != null && !issuedAt) || (row.expiresAt != null && !expiresAt)) return null;
  if (row.failureReason != null && !failureReason) return null;
  if (status === "reserved" && (issuedAt || expiresAt || failureReason)) return null;
  if (status === "failed" && (issuedAt || expiresAt || !failureReason)) return null;
  if (status === "issued") {
    if (!issuedAt || failureReason) return null;
    if (provider === "github_installation" && (!expiresAt || expiresAt <= issuedAt)) return null;
    if (provider === "configured_fallback" && expiresAt) return null;
  }
  return {
    id,
    repoId,
    provider,
    status,
    requestedBranch,
    authorizedBranch,
    baseSha,
    permissions,
    issuedAt,
    expiresAt,
    failureReason,
  };
}

function canonicalPermissions(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  if (value.length === 1 && value[0] === "contents") return ["contents"];
  if (value.length === 2 && value[0] === "contents" && value[1] === "workflows") {
    return ["contents", "workflows"];
  }
  return null;
}

function dateValue(value: unknown) {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : typeof value === "string" ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? date : null;
}

function normalizeGitSha(value: unknown) {
  return typeof value === "string" && GIT_SHA.test(value) ? value.toLowerCase() : null;
}

function validGithubBranch(value: string) {
  if (value.length < 1 || value.length > 255 || value !== value.trim()) return false;
  if (value === "@" || value.startsWith("/") || value.endsWith("/") || value.endsWith(".")) {
    return false;
  }
  if (value.includes("..") || value.includes("@{") || value.includes("//")) return false;
  if (
    [...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x20 || codePoint === 0x7f || "~^:?*[\\".includes(character);
    })
  ) {
    return false;
  }
  return value.split("/").every((component) => component && !component.endsWith(".lock"));
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function nullableString(value: unknown) {
  return value === null || value === undefined ? null : stringValue(value);
}

function githubStatus(error: unknown) {
  return error && typeof error === "object" && "status" in error
    ? Number((error as { status?: unknown }).status)
    : undefined;
}
