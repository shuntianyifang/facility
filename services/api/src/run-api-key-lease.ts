import type { FacilityDb } from "@facility/db";
import { sql } from "drizzle-orm";
import type postgres from "postgres";
import { ApiError } from "./errors.js";

const DEFAULT_LOCK_TIMEOUT_MS = 30_000;

export function runApiKeyLeaseName(runId: string) {
  return `facility:run-api-key:${runId}`;
}

export type RunApiKeyLeaseIdentity = {
  keyId: string;
  runId: string;
  orgId: string;
  projectId: string | null | undefined;
};

export async function acquireExclusiveRunTransitionRequestLease(
  client: postgres.Sql,
  runId: string,
  options: { timeoutMs?: number } = {},
) {
  const { release } = await acquireSessionRunLease(client, runId, "exclusive", options.timeoutMs);
  return release;
}

/** Shared session lease for any authenticated mutation attached to an active run. */
export async function acquireSharedRunRequestLease(
  client: postgres.Sql,
  runId: string,
  options: { timeoutMs?: number } = {},
) {
  const { release } = await acquireSessionRunLease(client, runId, "shared", options.timeoutMs);
  return release;
}

/**
 * Hold a shared session advisory lock for the complete run-scoped API-key request.
 * Future terminal/retry transitions take the matching exclusive lock, so a
 * key that authenticated before revocation cannot finish a mutation after a
 * successor run becomes active.
 */
export async function acquireRunApiKeyRequestLease(
  client: postgres.Sql,
  identity: RunApiKeyLeaseIdentity,
  options: { timeoutMs?: number } = {},
): Promise<() => Promise<void>> {
  const { reserved, release } = await acquireSessionRunLease(
    client,
    identity.runId,
    "shared",
    options.timeoutMs,
  );
  try {
    const rows = await reserved<
      Array<{
        key_id: string;
        key_org_id: string;
        key_project_id: string | null;
        run_id: string;
        run_org_id: string;
        run_project_id: string;
        run_status: string;
      }>
    >`
      select
        k.id as key_id,
        k.org_id as key_org_id,
        k.project_id as key_project_id,
        r.id as run_id,
        r.org_id as run_org_id,
        r.project_id as run_project_id,
        r.status as run_status
      from api_keys as k
      join runs as r on r.id = k.run_id
      where k.id = ${identity.keyId}
        and k.run_id = ${identity.runId}
        and k.scope_type = 'project'
        and k.revoked_at is null
        and (k.expires_at is null or k.expires_at > now())
      limit 1
    `;
    const row = rows[0];
    if (
      !row ||
      !identity.projectId ||
      row.key_org_id !== identity.orgId ||
      row.key_project_id !== identity.projectId ||
      row.run_org_id !== identity.orgId ||
      row.run_project_id !== identity.projectId ||
      row.run_status !== "running"
    ) {
      throw new ApiError(
        409,
        "run_key_inactive",
        "The run-scoped API key is no longer attached to an active run",
      );
    }

    return release;
  } catch (error) {
    await release().catch(() => undefined);
    throw error;
  }
}

async function acquireSessionRunLease(
  client: postgres.Sql,
  runId: string,
  mode: "shared" | "exclusive",
  configuredTimeoutMs?: number,
): Promise<{ reserved: postgres.ReservedSql; release: () => Promise<void> }> {
  const reserved = await client.reserve();
  let locked = false;
  let releasePromise: Promise<void> | null = null;
  const release = () => {
    releasePromise ??= (async () => {
      let reusable = false;
      try {
        if (locked) {
          // This connection is dedicated to exactly one run lease, so clearing
          // all session advisory locks is both safer and easier to verify than
          // returning a pooled session after a mismatched unlock.
          await reserved`select pg_advisory_unlock_all()`;
          locked = false;
        }
        await reserved`select set_config('lock_timeout', '0', false)`;
        reusable = true;
      } finally {
        // postgres.js ReservedSql has no reliable per-session end() API. A
        // failed unlock therefore quarantines this dedicated pool slot instead
        // of returning a possibly locked connection to the pool. Process/app
        // shutdown closes every quarantined session and its advisory locks.
        if (reusable) reserved.release();
      }
    })();
    return releasePromise;
  };

  try {
    const timeoutMs = Math.max(1, configuredTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS);
    await reserved`select set_config('lock_timeout', ${`${timeoutMs}ms`}, false)`;
    if (mode === "shared") {
      await reserved`select pg_advisory_lock_shared(hashtextextended(${runApiKeyLeaseName(
        runId,
      )}, 0))`;
    } else {
      await reserved`select pg_advisory_lock(hashtextextended(${runApiKeyLeaseName(runId)}, 0))`;
    }
    locked = true;
    return { reserved, release };
  } catch (error) {
    await release().catch(() => undefined);
    if (postgresErrorCode(error) === "55P03") {
      throw new ApiError(
        503,
        "run_key_lease_timeout",
        "The active run request could not acquire its execution lease",
      );
    }
    throw error;
  }
}

/** Matching exclusive transition primitive for terminal/retry code. */
export async function acquireExclusiveRunTransitionTransactionLease(
  db: Pick<FacilityDb, "execute">,
  runId: string,
  options: { timeoutMs?: number } = {},
) {
  const timeoutMs = Math.max(1, options.timeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS);
  await db.execute(sql`select set_config('lock_timeout', ${`${timeoutMs}ms`}, true)`);
  try {
    await db.execute(
      sql`select pg_advisory_xact_lock(hashtextextended(${runApiKeyLeaseName(runId)}, 0))`,
    );
  } catch (error) {
    if (postgresErrorCode(error) === "55P03") {
      throw new ApiError(
        503,
        "run_transition_lease_timeout",
        "Run transition is waiting for an active run request",
      );
    }
    throw error;
  }
}

/** Transaction wrapper used when the caller does not already own a transaction. */
export async function withExclusiveRunTransitionLease<T>(
  db: FacilityDb,
  runId: string,
  callback: (tx: FacilityDb) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    const database = tx as unknown as FacilityDb;
    await acquireExclusiveRunTransitionTransactionLease(database, runId);
    return callback(database);
  });
}

function postgresErrorCode(error: unknown) {
  return error && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code ?? "")
    : null;
}
