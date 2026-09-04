import { describe, expect, it, vi } from "vitest";
import {
  inspectRemoteRepositoryWriteOutput,
  repositoryWriteLeaseEligibility,
  selectAvailableRepositoryWriteBranch,
} from "../src/repository-write-lease.js";

const NOW = new Date("2026-09-01T12:00:00.000Z");
const ISSUED_AT = new Date("2026-09-01T10:00:00.000Z");
const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

function issuedLease(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "lease_issued",
    repoId: "repo_primary",
    provider: "github_installation",
    status: "issued",
    requestedBranch: "feature/tracked-delivery",
    authorizedBranch: "feature/tracked-delivery",
    baseSha: SHA_A,
    permissions: ["contents"],
    issuedAt: ISSUED_AT,
    expiresAt: new Date("2026-09-01T11:05:00.000Z"),
    failureReason: null,
    ...overrides,
  };
}

function reservedLease(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "lease_reserved",
    repoId: "repo_primary",
    provider: "github_installation",
    status: "reserved",
    requestedBranch: "feature/tracked-delivery",
    authorizedBranch: "feature/tracked-delivery",
    baseSha: SHA_A,
    permissions: ["contents"],
    issuedAt: null,
    expiresAt: null,
    failureReason: null,
    ...overrides,
  };
}

function failedLease(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "lease_failed",
    repoId: "repo_primary",
    provider: "github_installation",
    status: "failed",
    requestedBranch: "feature/tracked-delivery",
    authorizedBranch: "feature/tracked-delivery",
    baseSha: SHA_A,
    permissions: ["contents"],
    issuedAt: null,
    expiresAt: null,
    failureReason: "token_factory_failed",
    ...overrides,
  };
}

function eligibility(values: readonly unknown[], trackingVersion = 1) {
  return repositoryWriteLeaseEligibility(values, NOW, { trackingVersion });
}

function githubError(status: number, message = `GitHub returned ${status}`) {
  return Object.assign(new Error(message), { status });
}

describe("repository write lease eligibility", () => {
  it("requires the authenticated runner tracking marker even when no token was requested", () => {
    expect(eligibility([], 0)).toEqual({
      eligible: false,
      reason: "repository_write_tracking_unavailable",
    });
    expect(eligibility([], 2)).toEqual({
      eligible: false,
      reason: "repository_write_tracking_unavailable",
    });
    expect(eligibility([], 1)).toEqual({ eligible: true, remoteInspections: [] });
  });

  it("accepts only the two canonical permission sets", () => {
    expect(eligibility([issuedLease({ permissions: ["contents"] })])).toMatchObject({
      eligible: true,
    });
    expect(eligibility([issuedLease({ permissions: ["contents", "workflows"] })])).toMatchObject({
      eligible: true,
    });

    for (const permissions of [
      undefined,
      null,
      "contents",
      [],
      ["workflows"],
      ["contents", "contents"],
      ["workflows", "contents"],
      ["contents", "administration"],
      ["contents", "workflows", "metadata"],
    ]) {
      expect(eligibility([issuedLease({ permissions })]), JSON.stringify(permissions)).toEqual({
        eligible: false,
        reason: "repository_write_lease_malformed",
      });
    }
  });

  it.each([
    ["unknown provider", issuedLease({ provider: "personal_access_token" })],
    ["unknown status", issuedLease({ status: "complete" })],
    ["invalid base SHA", issuedLease({ baseSha: "not-a-sha" })],
    ["missing requested branch", issuedLease({ requestedBranch: "" })],
    ["missing authorized branch", issuedLease({ authorizedBranch: "" })],
    ["padded requested branch", issuedLease({ requestedBranch: " feature/task" })],
    ["padded authorized branch", issuedLease({ authorizedBranch: "feature/task " })],
    ["control character in branch", issuedLease({ authorizedBranch: "feature/task\nother" })],
    ["oversized branch", issuedLease({ authorizedBranch: "a".repeat(256) })],
    ["leading slash branch", issuedLease({ authorizedBranch: "/feature/task" })],
    ["trailing slash branch", issuedLease({ authorizedBranch: "feature/task/" })],
    ["trailing dot branch", issuedLease({ authorizedBranch: "feature/task." })],
    ["lone at-sign branch", issuedLease({ authorizedBranch: "@" })],
    ["double-dot branch", issuedLease({ authorizedBranch: "feature/../task" })],
    ["reflog syntax branch", issuedLease({ authorizedBranch: "feature/@{task" })],
    ["empty path component branch", issuedLease({ authorizedBranch: "feature//task" })],
    ["forbidden ref character branch", issuedLease({ authorizedBranch: "feature/task?" })],
    ["lockfile component branch", issuedLease({ authorizedBranch: "feature/task.lock" })],
    ["invalid issued date", issuedLease({ issuedAt: "not-a-date" })],
    ["invalid expiry date", issuedLease({ expiresAt: "not-a-date" })],
    ["GitHub lease without expiry", issuedLease({ expiresAt: null })],
    ["GitHub lease expiring at issue time", issuedLease({ expiresAt: ISSUED_AT })],
    [
      "persistent fallback carrying an expiry",
      issuedLease({
        provider: "configured_fallback",
        expiresAt: new Date("2026-09-01T13:00:00.000Z"),
      }),
    ],
    ["reserved lease with issue time", reservedLease({ issuedAt: ISSUED_AT })],
    ["reserved lease with a failure", reservedLease({ failureReason: "unexpected" })],
    ["failed lease without a reason", failedLease({ failureReason: null })],
    ["failed lease with an issue time", failedLease({ issuedAt: ISSUED_AT })],
  ])("fails closed for a malformed %s", (_name, row) => {
    expect(eligibility([row])).toEqual({
      eligible: false,
      reason: "repository_write_lease_malformed",
    });
  });

  it("normalizes canonical string dates and SHA casing", () => {
    const result = eligibility([
      issuedLease({
        baseSha: SHA_A.toUpperCase(),
        issuedAt: "2026-09-01T10:00:00.000Z",
        expiresAt: "2026-09-01T11:54:59.000Z",
        requestedBranch: "feature/requested",
        authorizedBranch: "feature/requested-run12345",
      }),
    ]);

    expect(result).toEqual({
      eligible: true,
      remoteInspections: [
        {
          leaseId: "lease_issued",
          repoId: "repo_primary",
          authorizedBranch: "feature/requested-run12345",
          baseSha: SHA_A,
        },
      ],
    });
  });

  it("returns every expired issued lease and inspects the authorized branch", () => {
    const result = eligibility([
      issuedLease({
        id: "lease_first",
        repoId: "repo_first",
        requestedBranch: "feature/task",
        authorizedBranch: "feature/task-run00001",
      }),
      issuedLease({
        id: "lease_second",
        repoId: "repo_second",
        requestedBranch: "fix/task",
        authorizedBranch: "fix/task-run00002",
        baseSha: SHA_B,
        permissions: ["contents", "workflows"],
      }),
    ]);

    expect(result).toEqual({
      eligible: true,
      remoteInspections: [
        {
          leaseId: "lease_first",
          repoId: "repo_first",
          authorizedBranch: "feature/task-run00001",
          baseSha: SHA_A,
        },
        {
          leaseId: "lease_second",
          repoId: "repo_second",
          authorizedBranch: "fix/task-run00002",
          baseSha: SHA_B,
        },
      ],
    });
  });

  it("does not let a later expiring lease hide an earlier persistent fallback", () => {
    expect(
      eligibility([
        issuedLease({
          id: "lease_persistent",
          provider: "configured_fallback",
          expiresAt: null,
        }),
        issuedLease({
          id: "lease_later",
          issuedAt: new Date("2026-09-01T11:00:00.000Z"),
          expiresAt: new Date("2026-09-01T12:30:00.000Z"),
        }),
      ]),
    ).toEqual({
      eligible: false,
      reason: "repository_write_credential_persistent",
      leaseId: "lease_persistent",
    });
  });

  it("blocks an unresolved reservation wherever it appears in the lease history", () => {
    expect(
      eligibility([
        issuedLease({ id: "lease_expired" }),
        reservedLease({ id: "lease_unresolved" }),
      ]),
    ).toEqual({
      eligible: false,
      reason: "repository_write_lease_reserved",
      leaseId: "lease_unresolved",
    });
  });

  it("treats a failed issuance as ambiguous rather than assuming no credential escaped", () => {
    expect(
      eligibility([issuedLease({ id: "lease_expired" }), failedLease({ id: "lease_failed" })]),
    ).toEqual({
      eligible: false,
      reason: "repository_write_lease_ambiguous",
      leaseId: "lease_failed",
    });
  });

  it("blocks on the furthest live expiry through the conservative clock-skew window", () => {
    const nearer = new Date("2026-09-01T12:00:00.001Z");
    const furthest = new Date("2026-09-01T13:00:00.000Z");
    expect(
      eligibility([
        issuedLease({ id: "lease_boundary", expiresAt: NOW }),
        issuedLease({ id: "lease_nearer", expiresAt: nearer }),
        issuedLease({ id: "lease_furthest", expiresAt: furthest }),
      ]),
    ).toEqual({
      eligible: false,
      reason: "repository_write_credential_unexpired",
      leaseId: "lease_furthest",
      expiresAt: furthest,
    });

    expect(eligibility([issuedLease({ expiresAt: NOW })])).toMatchObject({
      eligible: false,
      reason: "repository_write_credential_unexpired",
    });
    expect(
      eligibility([issuedLease({ expiresAt: new Date(NOW.getTime() - 5 * 60_000 + 1) })]),
    ).toMatchObject({
      eligible: false,
      reason: "repository_write_credential_unexpired",
    });
    expect(
      eligibility([issuedLease({ expiresAt: new Date(NOW.getTime() - 5 * 60_000) })]),
    ).toMatchObject({ eligible: true });
  });

  it("gives malformed evidence precedence over otherwise recognizable blockers", () => {
    expect(
      eligibility([
        issuedLease({
          id: "lease_persistent",
          provider: "configured_fallback",
          expiresAt: null,
        }),
        reservedLease({ id: "lease_malformed", permissions: ["workflows"] }),
      ]),
    ).toEqual({
      eligible: false,
      reason: "repository_write_lease_malformed",
    });
  });
});

describe("remote repository write inspection", () => {
  function client(input: {
    accessError?: unknown;
    headSha?: string;
    refError?: unknown;
    pullRequests?: unknown[];
    hasNextPage?: boolean;
    pullError?: unknown;
  }) {
    return {
      assertRepositoryAccessible: vi.fn(async () => {
        if (input.accessError) throw input.accessError;
      }),
      getRef: vi.fn(async () => {
        if (input.refError) throw input.refError;
        return input.headSha ?? SHA_A;
      }),
      listPullRequestsForHead: vi.fn(async () => {
        if (input.pullError) throw input.pullError;
        return {
          pullRequests: input.pullRequests ?? [],
          hasNextPage: input.hasNextPage ?? false,
        };
      }),
    };
  }

  it("reports a safely absent branch only after repository access and PR lookup succeed", async () => {
    const github = client({ refError: githubError(404), pullRequests: [] });
    await expect(
      inspectRemoteRepositoryWriteOutput(github, "feature/task", SHA_A),
    ).resolves.toEqual({ state: "safe_absent", pullRequestCount: 0 });
    expect(github.assertRepositoryAccessible).toHaveBeenCalledOnce();
    expect(github.getRef).toHaveBeenCalledWith("feature/task");
    expect(github.listPullRequestsForHead).toHaveBeenCalledWith("feature/task");
  });

  it("distinguishes a safely unchanged branch from durable PR output", async () => {
    await expect(
      inspectRemoteRepositoryWriteOutput(
        client({ headSha: SHA_A.toUpperCase(), pullRequests: [] }),
        "feature/task",
        SHA_A,
      ),
    ).resolves.toEqual({ state: "safe_unchanged", headSha: SHA_A, pullRequestCount: 0 });

    await expect(
      inspectRemoteRepositoryWriteOutput(
        client({ headSha: SHA_A, pullRequests: [{ number: 71 }] }),
        "feature/task",
        SHA_A,
      ),
    ).resolves.toEqual({
      state: "durable_output",
      refState: "unchanged",
      headSha: SHA_A,
      pullRequestCount: 1,
    });
  });

  it("treats a changed branch as durable output even without a pull request", async () => {
    await expect(
      inspectRemoteRepositoryWriteOutput(
        client({ headSha: SHA_B, pullRequests: [] }),
        "feature/task",
        SHA_A,
      ),
    ).resolves.toEqual({
      state: "durable_output",
      refState: "changed",
      headSha: SHA_B,
      pullRequestCount: 0,
    });
  });

  it("treats a pull request as durable output even when the branch is absent", async () => {
    await expect(
      inspectRemoteRepositoryWriteOutput(
        client({ refError: githubError(404), pullRequests: [{ number: 72 }] }),
        "feature/task",
        SHA_A,
      ),
    ).resolves.toEqual({
      state: "durable_output",
      refState: "absent",
      pullRequestCount: 1,
    });
  });

  it.each([
    ["invalid approved base", client({}), "invalid-sha"],
    ["malformed remote head", client({ headSha: "short" }), SHA_A],
    ["inaccessible repository", client({ accessError: githubError(404) }), SHA_A],
    ["permission or provider error", client({ refError: githubError(403) }), SHA_A],
    ["transport error", client({ refError: new Error("network unavailable") }), SHA_A],
    ["pull-request lookup error", client({ pullError: new Error("PR lookup unavailable") }), SHA_A],
    ["pagination ambiguity", client({ hasNextPage: true }), SHA_A],
  ])("fails closed as indeterminate on %s", async (_name, github, baseSha) => {
    await expect(
      inspectRemoteRepositoryWriteOutput(github, "feature/task", baseSha),
    ).resolves.toEqual({ state: "indeterminate" });
  });

  it("does not consult GitHub when the approved base is malformed", async () => {
    const github = client({});
    await inspectRemoteRepositoryWriteOutput(github, "feature/task", "invalid");
    expect(github.assertRepositoryAccessible).not.toHaveBeenCalled();
    expect(github.getRef).not.toHaveBeenCalled();
    expect(github.listPullRequestsForHead).not.toHaveBeenCalled();
  });

  it("does not consult GitHub when the authorized branch is malformed", async () => {
    const github = client({});
    await expect(
      inspectRemoteRepositoryWriteOutput(github, " feature/task", SHA_A),
    ).resolves.toEqual({ state: "indeterminate" });
    expect(github.assertRepositoryAccessible).not.toHaveBeenCalled();
    expect(github.getRef).not.toHaveBeenCalled();
    expect(github.listPullRequestsForHead).not.toHaveBeenCalled();
  });

  it("does not inspect refs or pull requests unless repository access is proven", async () => {
    const github = client({ accessError: githubError(404) });
    await expect(
      inspectRemoteRepositoryWriteOutput(github, "feature/task", SHA_A),
    ).resolves.toEqual({ state: "indeterminate" });
    expect(github.assertRepositoryAccessible).toHaveBeenCalledOnce();
    expect(github.getRef).not.toHaveBeenCalled();
    expect(github.listPullRequestsForHead).not.toHaveBeenCalled();
  });
});

describe("repository write branch selection", () => {
  it("rejects a malformed requested branch before consulting GitHub", async () => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async () => SHA_A);
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task?",
        "run_12345678",
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "repository_write_branch_unavailable",
    });
    expect(assertRepositoryAccessible).not.toHaveBeenCalled();
    expect(getRef).not.toHaveBeenCalled();
    expect(listPullRequestsForHead).not.toHaveBeenCalled();
  });

  it("authorizes a run-scoped first candidate when it is absent", async () => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async () => {
      throw githubError(404);
    });
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_12345678",
      ),
    ).resolves.toBe("feature/task-run12345678");
    expect(assertRepositoryAccessible).toHaveBeenCalledOnce();
    expect(getRef).toHaveBeenCalledTimes(1);
    expect(getRef).toHaveBeenCalledWith("feature/task-run12345678");
    expect(listPullRequestsForHead).toHaveBeenCalledWith("feature/task-run12345678");
  });

  it("selects a deterministic numeric suffix after run-scoped collisions", async () => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async (branch: string) => {
      if (branch === "feature/task-runabcdefgh" || branch === "feature/task-runabcdefgh-2") {
        return SHA_B;
      }
      throw githubError(404);
    });
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_abcdefgh",
      ),
    ).resolves.toBe("feature/task-runabcdefgh-3");
    expect(getRef.mock.calls.map(([branch]) => branch)).toEqual([
      "feature/task-runabcdefgh",
      "feature/task-runabcdefgh-2",
      "feature/task-runabcdefgh-3",
    ]);
    expect(listPullRequestsForHead).toHaveBeenCalledWith("feature/task-runabcdefgh-3");
  });

  it("gives distinct runs distinct first candidates for the same requested branch", async () => {
    const newClient = () => ({
      assertRepositoryAccessible: vi.fn(async () => undefined),
      getRef: vi.fn(async (_branch: string) => {
        throw githubError(404);
      }),
      listPullRequestsForHead: vi.fn(async (_branch: string) => ({
        pullRequests: [],
        hasNextPage: false,
      })),
    });
    const firstClient = newClient();
    const secondClient = newClient();

    const candidates = await Promise.all([
      selectAvailableRepositoryWriteBranch(firstClient, "feature/task", "run_alpha-123"),
      selectAvailableRepositoryWriteBranch(secondClient, "feature/task", "run_beta-456"),
    ]);

    expect(candidates).toEqual(["feature/task-runalpha123", "feature/task-runbeta456"]);
    expect(new Set(candidates).size).toBe(2);
    expect(firstClient.getRef).toHaveBeenCalledWith(candidates[0]);
    expect(secondClient.getRef).toHaveBeenCalledWith(candidates[1]);
  });

  it("does not reuse an absent branch with durable pull-request history", async () => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async (_branch: string) => {
      throw githubError(404);
    });
    const listPullRequestsForHead = vi.fn(async (branch: string) => ({
      pullRequests: branch === "feature/task-runabcdefgh" ? [{ number: 71 }] : [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_abcdefgh",
      ),
    ).resolves.toBe("feature/task-runabcdefgh-2");
    expect(getRef.mock.calls.map(([branch]) => branch)).toEqual([
      "feature/task-runabcdefgh",
      "feature/task-runabcdefgh-2",
    ]);
    expect(listPullRequestsForHead.mock.calls.map(([branch]) => branch)).toEqual([
      "feature/task-runabcdefgh",
      "feature/task-runabcdefgh-2",
    ]);
  });

  it("fails closed immediately when branch availability cannot be proven", async () => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async () => {
      throw githubError(503);
    });
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_abcdefgh",
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "repository_write_branch_unavailable",
    });
    expect(getRef).toHaveBeenCalledTimes(1);
    expect(listPullRequestsForHead).not.toHaveBeenCalled();
  });

  it.each([
    ["incomplete pull-request pagination", async () => ({ pullRequests: [], hasNextPage: true })],
    ["pull-request lookup failure", async () => Promise.reject(new Error("unavailable"))],
  ])("fails closed on %s for an absent ref", async (_name, lookup) => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async () => {
      throw githubError(404);
    });
    const listPullRequestsForHead = vi.fn(lookup);

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_abcdefgh",
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "repository_write_branch_unavailable",
    });
    expect(getRef).toHaveBeenCalledTimes(1);
  });

  it("stops after the bounded collision budget", async () => {
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async (_branch: string) => SHA_B);
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_abcdefgh",
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "repository_write_branch_unavailable",
    });
    expect(getRef).toHaveBeenCalledTimes(10);
    expect(getRef.mock.calls.at(-1)?.[0]).toBe("feature/task-runabcdefgh-10");
    expect(listPullRequestsForHead).not.toHaveBeenCalled();
  });

  it("never returns a collision suffix outside the durable branch bound", async () => {
    const requestedBranch = `feature/${"a".repeat(247)}`;
    expect(requestedBranch).toHaveLength(255);
    const assertRepositoryAccessible = vi.fn(async () => undefined);
    const getRef = vi.fn(async (branch: string) => {
      if (branch === requestedBranch) return SHA_A;
      throw githubError(404);
    });
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        requestedBranch,
        "run_abcdefgh",
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "repository_write_branch_unavailable",
    });
    expect(getRef).not.toHaveBeenCalled();
    expect(listPullRequestsForHead).not.toHaveBeenCalled();
  });

  it("fails closed before ref inspection when repository access cannot be proven", async () => {
    const assertRepositoryAccessible = vi.fn(async () => {
      throw githubError(404);
    });
    const getRef = vi.fn(async () => SHA_A);
    const listPullRequestsForHead = vi.fn(async (_branch: string) => ({
      pullRequests: [],
      hasNextPage: false,
    }));

    await expect(
      selectAvailableRepositoryWriteBranch(
        { assertRepositoryAccessible, getRef, listPullRequestsForHead },
        "feature/task",
        "run_abcdefgh",
      ),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "repository_write_branch_unavailable",
    });
    expect(getRef).not.toHaveBeenCalled();
    expect(listPullRequestsForHead).not.toHaveBeenCalled();
  });
});
