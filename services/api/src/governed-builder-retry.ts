import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { newId } from "@facility/core";
import {
  agentDefs,
  apiKeys,
  type FacilityDb,
  insertAuditEvent,
  outcomes,
  proposals,
  repos,
  runDeliveries,
  runEvents,
  runRepositoryWriteLeases,
  runs,
  virtualKeys,
} from "@facility/db";
import { agentDefTriggersBuilder, isBuilderMode } from "@facility/run-objective";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import {
  type BuilderPlanFreshnessEvidence,
  type BuilderPlanFreshnessOptions,
  resolveBuilderPlanFreshnessForRun,
} from "./builder-plan-freshness.js";
import {
  assertBuilderPlanDispatch,
  builderPlanDenialCode,
  builderPlanRequired,
  lockBuilderPlanPolicy,
  recordBuilderPlanDenial,
} from "./builder-plan-policy.js";
import { ApiError } from "./errors.js";
import { laneFor } from "./github/agent-routing.js";
import {
  createGithubClientFactory,
  type FacilityGithubClient,
  type GithubClientFactory,
} from "./github/client.js";
import { createGithubClientForRepo } from "./github/kickstart.js";
import {
  inspectRemoteRepositoryWriteOutput,
  repositoryWriteLeaseEligibility,
} from "./repository-write-lease.js";
import { acquireExclusiveRunTransitionTransactionLease } from "./run-api-key-lease.js";
import { readSandbox } from "./sandbox/state.js";
import type { AppConfig } from "./types.js";

type RunRow = typeof runs.$inferSelect;
type RetryActor = { type: "user" | "key" | "system"; id: string };
type EligibleRepositoryWriteEvidence = Extract<
  ReturnType<typeof repositoryWriteLeaseEligibility>,
  { eligible: true }
>;

export type GovernedRetryExternalOptions = BuilderPlanFreshnessOptions & {
  config?: AppConfig;
  githubFactory?: GithubClientFactory;
  repositoryWriteClient?: {
    repoId: string;
    client: Pick<
      FacilityGithubClient,
      "assertRepositoryAccessible" | "getRef" | "listPullRequestsForHead"
    >;
  };
};

export type GovernedRetryLineage = {
  attempt: RunRow;
  parent: RunRow | null;
  root: RunRow;
  /** Current attempt followed by every immutable ancestor through the root. */
  attempts: RunRow[];
  /** Number of immutable retry edges between this attempt and the root. */
  depth: number;
};

export type GovernedRetryEvidence = {
  freshness: BuilderPlanFreshnessEvidence;
  /** Digest of every completed attempt's repository-write evidence in lineage order. */
  repositoryLeaseChainDigest: string;
};

export type GovernedRetryCreation = {
  run: RunRow;
  created: boolean;
};

const FINGERPRINT_MAX_AGE_MS = 5 * 60_000;
const MAX_LINEAGE_DEPTH = 100;
const GOVERNED_RETRY_DENIAL_CODES = new Set([
  "governed_retry_agent_invalid",
  "governed_retry_cleanup_incomplete",
  "governed_retry_durable_output",
  "governed_retry_lane_invalid",
  "governed_retry_lineage_invalid",
  "governed_retry_output_indeterminate",
  "governed_retry_parent_not_found",
  "governed_retry_parent_not_retryable",
  "governed_retry_policy_required",
  "governed_retry_repository_write_blocked",
  "governed_retry_requires_fresh_gate1",
]);
const GOVERNED_RETRY_DENIAL_REASONS = new Set([
  "ancestor_not_failed",
  "base_or_issue_revision_changed",
  "builder_agent_disabled_or_changed",
  "delivery_or_outcome_exists",
  "execution_identity_changed",
  "github_client_repo_mismatch",
  "github_client_unavailable",
  "github_issue_identity_missing",
  "legacy_resume_descendant_exists",
  "legacy_repository_write_tracking_unavailable",
  "lineage_changed",
  "lineage_cycle_or_depth",
  "lineage_depth_exceeded",
  "parent_not_failed",
  "parent_not_failed_plan_builder",
  "parent_not_found",
  "project_policy_not_required",
  "proposal_not_found",
  "proposal_repository_invalid",
  "recorded_repository_output",
  "remote_branch_or_pull_request_exists",
  "remote_state_unavailable",
  "repository_fingerprint_unverified",
  "repository_issue_changed",
  "repository_lane_changed",
  "repository_not_found",
  "repository_write_credential_persistent",
  "repository_write_credential_unexpired",
  "repository_write_lease_ambiguous",
  "repository_write_lease_malformed",
  "repository_write_lease_reserved",
  "repository_write_tracking_unavailable",
  "retry_parent_missing",
  "root_not_plan_builder",
  "run_credentials_live",
  "sandbox_not_destroyed",
  "successor_not_clean",
  "write_base_changed",
  "write_evidence_changed",
]);

/** Resolve and revalidate the immutable root -> ... -> attempt chain. */
export async function resolveGovernedRetryLineage(
  db: FacilityDb,
  attempt: RunRow,
): Promise<GovernedRetryLineage> {
  const seen = new Set<string>([attempt.id]);
  const attempts = [attempt];
  let child = attempt;
  let directParent: RunRow | null = null;
  let depth = 0;
  while (child.retryOfRunId) {
    if (depth >= MAX_LINEAGE_DEPTH || seen.has(child.retryOfRunId)) {
      throw retryError("governed_retry_lineage_invalid", "lineage_cycle_or_depth");
    }
    const parent = (
      await db
        .select()
        .from(runs)
        .where(
          and(
            eq(runs.orgId, attempt.orgId),
            eq(runs.projectId, attempt.projectId),
            eq(runs.id, child.retryOfRunId),
          ),
        )
        .limit(1)
    )[0];
    if (!parent) throw retryError("governed_retry_lineage_invalid", "parent_not_found");
    if (parent.status !== "failed") {
      throw retryError("governed_retry_lineage_invalid", "ancestor_not_failed");
    }
    assertSameExecutionIdentity(child, parent);
    if (!directParent) directParent = parent;
    seen.add(parent.id);
    attempts.push(parent);
    child = parent;
    depth += 1;
  }
  if (objectValue(child.trigger).source !== "plan_acceptance" || !isBuilderMode(child.mode)) {
    throw retryError("governed_retry_lineage_invalid", "root_not_plan_builder");
  }
  return { attempt, parent: directParent, root: child, attempts, depth };
}

/**
 * Resolve GitHub freshness and every repository-write lease for all completed
 * attempts in a retry chain. Tracking version zero is rejected before any
 * network lookup.
 */
export async function resolveGovernedRetryEvidence(
  db: FacilityDb,
  completedAttempts: readonly RunRow[],
  root: RunRow,
  options: GovernedRetryExternalOptions = {},
): Promise<GovernedRetryEvidence> {
  const parent = completedAttempts[0];
  if (!parent) throw retryError("governed_retry_lineage_invalid", "parent_not_found");
  assertRetryableParent(parent);
  await assertNoLegacyResumeDescendants(db, completedAttempts);

  const leaseEvidence: Array<{
    attempt: RunRow;
    rows: (typeof runRepositoryWriteLeases.$inferSelect)[];
    eligibility: EligibleRepositoryWriteEvidence;
  }> = [];
  const now = new Date();
  await assertNoDurableRetryOutput(db, completedAttempts);
  const leasesByAttempt = await loadRepositoryWriteLeases(db, completedAttempts);
  for (const attempt of completedAttempts) {
    const rows = leasesByAttempt.get(attempt.id) ?? [];
    const eligibility = repositoryWriteLeaseEligibility(rows, now, {
      trackingVersion: attempt.repositoryWriteTrackingVersion,
    });
    if (!eligibility.eligible) {
      if (eligibility.reason === "repository_write_tracking_unavailable") {
        throw new ApiError(
          409,
          "governed_retry_requires_fresh_gate1",
          "This historical Builder run cannot prove complete repository-write tracking",
          {
            reason: "legacy_repository_write_tracking_unavailable",
            requiredAction: "run_architect_and_approve_new_plan",
          },
        );
      }
      throw retryError("governed_retry_repository_write_blocked", eligibility.reason);
    }
    leaseEvidence.push({ attempt, rows, eligibility });
  }

  const freshness = await resolveBuilderPlanFreshnessForRun(db, root, options);
  for (const { attempt, eligibility } of leaseEvidence) {
    for (const inspection of eligibility.remoteInspections) {
      if (inspection.baseSha.toLowerCase() !== freshness.baseSha.toLowerCase()) {
        throw retryError("governed_retry_repository_write_blocked", "write_base_changed");
      }
      const repo = (
        await db
          .select()
          .from(repos)
          .where(
            and(
              eq(repos.orgId, attempt.orgId),
              eq(repos.projectId, attempt.projectId),
              eq(repos.id, inspection.repoId),
            ),
          )
          .limit(1)
      )[0];
      if (!repo) throw retryError("governed_retry_output_indeterminate", "repository_not_found");
      const client = await repositoryWriteClient(db, repo, options);
      const remote = await inspectRemoteRepositoryWriteOutput(
        client,
        inspection.authorizedBranch,
        inspection.baseSha,
      );
      if (remote.state === "indeterminate") {
        throw retryError("governed_retry_output_indeterminate", "remote_state_unavailable");
      }
      if (remote.state === "durable_output") {
        throw retryError("governed_retry_durable_output", "remote_branch_or_pull_request_exists");
      }
    }
  }
  return {
    freshness,
    repositoryLeaseChainDigest: repositoryLeaseChainDigest(leaseEvidence),
  };
}

/** Revalidate all durable state after the project and parent locks are held. */
export async function assertGovernedRetryLockedAdmission(
  db: FacilityDb,
  completedAttempts: readonly RunRow[],
  root: RunRow,
  evidence: GovernedRetryEvidence,
  actor: RetryActor,
  source: string,
): Promise<void> {
  const parent = completedAttempts[0];
  if (!parent) throw retryError("governed_retry_lineage_invalid", "parent_not_found");
  assertRetryableParent(parent);
  await assertNoLegacyResumeDescendants(db, completedAttempts);
  const now = new Date();
  const leaseEvidence: Array<{
    attempt: RunRow;
    rows: (typeof runRepositoryWriteLeases.$inferSelect)[];
  }> = [];
  await assertNoDurableRetryOutput(db, completedAttempts);
  const leasesByAttempt = await loadRepositoryWriteLeases(db, completedAttempts);
  for (const attempt of completedAttempts) {
    const rows = leasesByAttempt.get(attempt.id) ?? [];
    const eligibility = repositoryWriteLeaseEligibility(rows, now, {
      trackingVersion: attempt.repositoryWriteTrackingVersion,
    });
    if (!eligibility.eligible) {
      throw retryError("governed_retry_repository_write_blocked", "write_evidence_changed");
    }
    leaseEvidence.push({ attempt, rows });
  }
  if (repositoryLeaseChainDigest(leaseEvidence) !== evidence.repositoryLeaseChainDigest) {
    throw retryError("governed_retry_repository_write_blocked", "write_evidence_changed");
  }
  if (!(await builderPlanRequired(db, parent.orgId, parent.projectId))) {
    throw retryError("governed_retry_policy_required", "project_policy_not_required");
  }
  const trigger = objectValue(root.trigger);
  const proposalId = stringValue(trigger.proposalId);
  const proposal = proposalId
    ? (
        await db
          .select()
          .from(proposals)
          .where(
            and(
              eq(proposals.orgId, parent.orgId),
              eq(proposals.projectId, parent.projectId),
              eq(proposals.id, proposalId),
            ),
          )
          .limit(1)
      )[0]
    : undefined;
  if (!proposal) throw retryError("governed_retry_lineage_invalid", "proposal_not_found");
  const payload = objectValue(proposal.payload);
  const repoId = stringValue(payload.repoId);
  const repo = repoId
    ? (
        await db
          .select()
          .from(repos)
          .where(
            and(
              eq(repos.orgId, parent.orgId),
              eq(repos.projectId, parent.projectId),
              eq(repos.id, repoId),
            ),
          )
          .limit(1)
      )[0]
    : undefined;
  if (!repo) throw retryError("governed_retry_lineage_invalid", "proposal_repository_invalid");
  const gh = objectValue(root.gh);
  if (
    gh.owner !== repo.owner ||
    gh.repo !== repo.name ||
    positiveInteger(gh.issueNumber) !== positiveInteger(payload.issueNumber)
  ) {
    throw retryError("governed_retry_lineage_invalid", "repository_issue_changed");
  }
  const agent = root.agentDefId
    ? (
        await db
          .select()
          .from(agentDefs)
          .where(
            and(
              eq(agentDefs.orgId, root.orgId),
              eq(agentDefs.projectId, root.projectId),
              eq(agentDefs.id, root.agentDefId),
            ),
          )
          .limit(1)
      )[0]
    : undefined;
  if (
    !agent?.enabled ||
    agent.engine !== root.engine ||
    !(
      isBuilderMode(root.mode) ||
      isBuilderMode(agent.name) ||
      agentDefTriggersBuilder(agent.triggers)
    )
  ) {
    throw retryError("governed_retry_agent_invalid", "builder_agent_disabled_or_changed");
  }
  if (laneFor(repo, root.mode) !== "platform") {
    throw retryError("governed_retry_lane_invalid", "repository_lane_changed");
  }
  const verifiedAt = repo.fingerprintVerifiedAt?.getTime() ?? Number.NaN;
  if (
    !repo.fingerprint ||
    repo.fingerprintStatus !== "ok" ||
    !Number.isFinite(verifiedAt) ||
    verifiedAt < Date.now() - FINGERPRINT_MAX_AGE_MS ||
    verifiedAt > Date.now() + 30_000
  ) {
    throw retryError("governed_retry_lane_invalid", "repository_fingerprint_unverified");
  }
  await assertBuilderPlanDispatch(db, {
    orgId: root.orgId,
    projectId: root.projectId,
    mode: root.mode,
    agentDefId: root.agentDefId,
    trigger: root.trigger,
    gh: root.gh,
    runId: root.id,
    actor,
    source,
    freshnessEvidence: evidence.freshness,
  });
}

export async function createGovernedBuilderRetry(
  db: FacilityDb,
  transitionDb: FacilityDb,
  input: {
    orgId: string;
    projectId?: string | null;
    parentRunId: string;
    actor: RetryActor;
    reason?: string;
  },
  options: GovernedRetryExternalOptions = {},
): Promise<GovernedRetryCreation> {
  const parent = await loadScopedRun(db, input.orgId, input.projectId, input.parentRunId);
  const existing = await loadRetryChild(db, parent);
  if (existing) {
    assertSameExecutionIdentity(existing, parent);
    return { run: existing, created: false };
  }
  let lineage: GovernedRetryLineage | undefined;
  let evidence: GovernedRetryEvidence | undefined;
  try {
    lineage = await resolveGovernedRetryLineage(db, parent);
    if (lineage.depth >= MAX_LINEAGE_DEPTH) {
      throw retryError("governed_retry_lineage_invalid", "lineage_depth_exceeded");
    }
    evidence = await resolveGovernedRetryEvidence(db, lineage.attempts, lineage.root, options);
    const admissionEvidence = evidence;

    return await transitionDb.transaction(async (tx) => {
      const lockedDb = tx as unknown as FacilityDb;
      await lockBuilderPlanPolicy(lockedDb, parent.orgId, parent.projectId);
      await acquireExclusiveRunTransitionTransactionLease(lockedDb, parent.id);
      const lockedParent = (
        await lockedDb
          .select()
          .from(runs)
          .where(
            and(
              eq(runs.orgId, parent.orgId),
              eq(runs.projectId, parent.projectId),
              eq(runs.id, parent.id),
            ),
          )
          .for("update")
          .limit(1)
      )[0];
      if (!lockedParent) throw retryError("governed_retry_parent_not_found", "parent_not_found");
      const winningChild = await loadRetryChild(lockedDb, lockedParent);
      if (winningChild) {
        assertSameExecutionIdentity(winningChild, lockedParent);
        return { run: winningChild, created: false };
      }
      const lockedLineage = await resolveGovernedRetryLineage(lockedDb, lockedParent);
      if (lockedLineage.depth >= MAX_LINEAGE_DEPTH) {
        throw retryError("governed_retry_lineage_invalid", "lineage_depth_exceeded");
      }
      await assertGovernedRetryLockedAdmission(
        lockedDb,
        lockedLineage.attempts,
        lockedLineage.root,
        admissionEvidence,
        input.actor,
        "governed_retry_admission",
      );

      // builder-plan-preflight: governed_builder_retry
      const child = (
        await lockedDb
          .insert(runs)
          .values({
            id: newId("run"),
            orgId: lockedParent.orgId,
            projectId: lockedParent.projectId,
            agentDefId: lockedParent.agentDefId,
            mode: lockedParent.mode,
            engine: lockedParent.engine,
            retryOfRunId: lockedParent.id,
            trigger: lockedParent.trigger,
            gh: minimalGithubIdentity(lockedLineage.root.gh),
            createdBy: input.actor,
          })
          .returning()
      )[0];
      if (!child) throw new ApiError(500, "run_create_failed", "Retry run could not be created");
      const trigger = objectValue(lockedLineage.root.trigger);
      await lockedDb.insert(runEvents).values({
        orgId: child.orgId,
        runId: child.id,
        seq: 1,
        type: "queued",
        data: {
          queue: "runs.dispatch",
          source: "governed_retry",
          rootRunId: lockedLineage.root.id,
          parentRunId: lockedParent.id,
          proposalId: stringValue(trigger.proposalId),
          architectRunId: stringValue(trigger.architectRunId),
        },
      });
      await insertAuditEvent(lockedDb, {
        orgId: child.orgId,
        projectId: child.projectId,
        actor: input.actor,
        action: "run.retried",
        target: { type: "run", id: child.id },
        payload: {
          rootRunId: lockedLineage.root.id,
          parentRunId: lockedParent.id,
          childRunId: child.id,
          proposalId: stringValue(trigger.proposalId),
          architectRunId: stringValue(trigger.architectRunId),
          planSha256: sha256Value(trigger.planSha256),
          baseSha: admissionEvidence.freshness.baseSha,
          issueRevisionSha256: admissionEvidence.freshness.issueRevisionSha256,
          ...(sanitizedReason(input.reason) ? { reason: sanitizedReason(input.reason) } : {}),
        },
      });
      return { run: child, created: true };
    });
  } catch (error) {
    const planCode = error instanceof ApiError ? builderPlanDenialCode(error.code) : null;
    if (planCode && lineage) {
      await recordBuilderPlanDenial(
        db,
        {
          orgId: lineage.root.orgId,
          projectId: lineage.root.projectId,
          mode: lineage.root.mode,
          agentDefId: lineage.root.agentDefId,
          trigger: lineage.root.trigger,
          gh: lineage.root.gh,
          runId: lineage.root.id,
          actor: input.actor,
          source: "governed_retry_admission",
          freshnessEvidence: evidence?.freshness,
        },
        planCode,
        governedReason(error, "transactional_retry_preflight_denied"),
      ).catch(() => undefined);
    }
    await recordGovernedRetryDenial(
      db,
      parent,
      input.actor,
      "governed_retry_admission",
      error,
    ).catch(() => undefined);
    throw error;
  }
}

export function governedRetryDenial(error: unknown): { code: string; reason: string } | null {
  if (!(error instanceof ApiError) || !GOVERNED_RETRY_DENIAL_CODES.has(error.code)) return null;
  return { code: error.code, reason: governedReason(error, "denied") };
}

export async function recordGovernedRetryDenial(
  db: FacilityDb,
  run: Pick<RunRow, "id" | "orgId" | "projectId" | "retryOfRunId">,
  actor: RetryActor,
  source: string,
  error: unknown,
): Promise<void> {
  const denial = governedRetryDenial(error);
  if (!denial) return;
  await insertAuditEvent(db, {
    orgId: run.orgId,
    projectId: run.projectId,
    actor,
    action: "run.governed_retry_denied",
    target: { type: "run", id: run.id },
    payload: {
      code: denial.code,
      reason: denial.reason,
      source,
      parentRunId: run.retryOfRunId,
    },
  });
}

export async function validateGovernedRetryForDispatch(
  db: FacilityDb,
  run: RunRow,
  options: GovernedRetryExternalOptions = {},
): Promise<{ lineage: GovernedRetryLineage; evidence: GovernedRetryEvidence }> {
  if (!run.retryOfRunId) {
    throw retryError("governed_retry_lineage_invalid", "retry_parent_missing");
  }
  const lineage = await resolveGovernedRetryLineage(db, run);
  if (lineage.parent?.status !== "failed") {
    throw retryError("governed_retry_lineage_invalid", "parent_not_failed");
  }
  assertSameExecutionIdentity(run, lineage.parent);
  if (["queued", "provisioning"].includes(run.status))
    assertUnprovisionedRetryChild(run, lineage.root);
  const evidence = await resolveGovernedRetryEvidence(
    db,
    lineage.attempts.slice(1),
    lineage.root,
    options,
  );
  return { lineage, evidence };
}

export async function assertGovernedRetryDispatchState(
  db: FacilityDb,
  run: RunRow,
  expected: { lineage: GovernedRetryLineage; evidence: GovernedRetryEvidence },
): Promise<void> {
  const currentLineage = await resolveGovernedRetryLineage(db, run);
  if (
    !isDeepStrictEqual(
      currentLineage.attempts.map((attempt) => attempt.id),
      expected.lineage.attempts.map((attempt) => attempt.id),
    )
  ) {
    throw retryError("governed_retry_lineage_invalid", "lineage_changed");
  }
  assertUnprovisionedRetryChild(run, currentLineage.root);
  if (!currentLineage.parent) {
    throw retryError("governed_retry_lineage_invalid", "parent_not_found");
  }
  await assertGovernedRetryLockedAdmission(
    db,
    currentLineage.attempts.slice(1),
    currentLineage.root,
    expected.evidence,
    { type: "system", id: "runs.dispatch" },
    "governed_retry_worker",
  );
}

async function loadScopedRun(
  db: FacilityDb,
  orgId: string,
  projectId: string | null | undefined,
  runId: string,
) {
  const row = (
    await db
      .select()
      .from(runs)
      .where(
        and(
          eq(runs.orgId, orgId),
          eq(runs.id, runId),
          ...(projectId ? [eq(runs.projectId, projectId)] : []),
        ),
      )
      .limit(1)
  )[0];
  if (!row) throw new ApiError(404, "run_not_found", "Run not found");
  return row;
}

async function loadRetryChild(db: FacilityDb, parent: RunRow) {
  return (
    await db
      .select()
      .from(runs)
      .where(
        and(
          eq(runs.orgId, parent.orgId),
          eq(runs.projectId, parent.projectId),
          eq(runs.retryOfRunId, parent.id),
        ),
      )
      .limit(1)
  )[0];
}

async function loadRepositoryWriteLeases(db: FacilityDb, attempts: readonly RunRow[]) {
  const first = assertSameLineageScope(attempts);
  const rows = await db
    .select()
    .from(runRepositoryWriteLeases)
    .where(
      and(
        eq(runRepositoryWriteLeases.orgId, first.orgId),
        eq(runRepositoryWriteLeases.projectId, first.projectId),
        inArray(
          runRepositoryWriteLeases.runId,
          attempts.map((attempt) => attempt.id),
        ),
      ),
    );
  const byAttempt = new Map<string, (typeof runRepositoryWriteLeases.$inferSelect)[]>();
  for (const row of rows) {
    const attemptRows = byAttempt.get(row.runId) ?? [];
    attemptRows.push(row);
    byAttempt.set(row.runId, attemptRows);
  }
  return byAttempt;
}

async function assertNoLegacyResumeDescendants(
  db: FacilityDb,
  completedAttempts: readonly RunRow[],
) {
  const first = assertSameLineageScope(completedAttempts);
  const attemptIds = completedAttempts.map((attempt) => attempt.id);
  const legacy = await db
    .select({ id: runs.id })
    .from(runs)
    .where(
      and(
        eq(runs.orgId, first.orgId),
        eq(runs.projectId, first.projectId),
        isNull(runs.retryOfRunId),
        inArray(sql<string>`${runs.trigger}->>'resumeOf'`, attemptIds),
      ),
    )
    .limit(1);
  if (legacy.length) {
    throw retryError("governed_retry_durable_output", "legacy_resume_descendant_exists");
  }
}

async function assertNoDurableRetryOutput(db: FacilityDb, attempts: readonly RunRow[]) {
  const first = assertSameLineageScope(attempts);
  const attemptIds = attempts.map((attempt) => attempt.id);
  for (const attempt of attempts) {
    const gh = objectValue(attempt.gh);
    const receiptGithub = objectValue(objectValue(attempt.receipt).github);
    if (
      stringValue(gh.branch) ||
      stringValue(gh.headSha) ||
      Object.keys(objectValue(gh.pr)).length > 0 ||
      positiveInteger(receiptGithub.pr)
    ) {
      throw retryError("governed_retry_durable_output", "recorded_repository_output");
    }
    const sandbox = readSandbox(attempt.sandbox);
    if (sandbox.ref && (!sandbox.destroyedAt || sandbox.lastStatus !== "destroyed")) {
      throw retryError("governed_retry_cleanup_incomplete", "sandbox_not_destroyed");
    }
  }
  const [delivery, outcome, livePlatformKey, liveVirtualKey] = await Promise.all([
    db
      .select({ runId: runDeliveries.runId })
      .from(runDeliveries)
      .where(and(eq(runDeliveries.orgId, first.orgId), inArray(runDeliveries.runId, attemptIds)))
      .limit(1),
    db
      .select({ id: outcomes.id })
      .from(outcomes)
      .where(and(eq(outcomes.orgId, first.orgId), inArray(outcomes.runId, attemptIds)))
      .limit(1),
    db
      .select({ id: apiKeys.id })
      .from(apiKeys)
      .where(
        and(
          eq(apiKeys.orgId, first.orgId),
          inArray(apiKeys.runId, attemptIds),
          isNull(apiKeys.revokedAt),
        ),
      )
      .limit(1),
    db
      .select({ id: virtualKeys.id })
      .from(virtualKeys)
      .where(
        and(
          eq(virtualKeys.orgId, first.orgId),
          inArray(virtualKeys.runId, attemptIds),
          isNull(virtualKeys.revokedAt),
        ),
      )
      .limit(1),
  ]);
  if (delivery.length || outcome.length) {
    throw retryError("governed_retry_durable_output", "delivery_or_outcome_exists");
  }
  if (livePlatformKey.length || liveVirtualKey.length) {
    throw retryError("governed_retry_cleanup_incomplete", "run_credentials_live");
  }
}

function assertSameLineageScope(attempts: readonly RunRow[]) {
  const first = attempts[0];
  if (
    !first ||
    attempts.some(
      (attempt) => attempt.orgId !== first.orgId || attempt.projectId !== first.projectId,
    )
  ) {
    throw retryError("governed_retry_lineage_invalid", "lineage_changed");
  }
  return first;
}

function assertRetryableParent(parent: RunRow) {
  if (
    parent.status !== "failed" ||
    !isBuilderMode(parent.mode) ||
    objectValue(parent.trigger).source !== "plan_acceptance"
  ) {
    throw retryError("governed_retry_parent_not_retryable", "parent_not_failed_plan_builder");
  }
}

function assertSameExecutionIdentity(child: RunRow, parent: RunRow) {
  if (
    child.orgId !== parent.orgId ||
    child.projectId !== parent.projectId ||
    child.retryOfRunId !== parent.id ||
    child.agentDefId !== parent.agentDefId ||
    child.mode !== parent.mode ||
    child.engine !== parent.engine ||
    !isDeepStrictEqual(child.trigger, parent.trigger)
  ) {
    throw retryError("governed_retry_lineage_invalid", "execution_identity_changed");
  }
}

function assertUnprovisionedRetryChild(child: RunRow, root: RunRow) {
  if (
    !["queued", "provisioning"].includes(child.status) ||
    !isDeepStrictEqual(objectValue(child.gh), minimalGithubIdentity(root.gh)) ||
    Object.keys(readSandbox(child.sandbox)).length > 0 ||
    child.receipt !== null ||
    child.engineSessionId !== null ||
    child.transcriptUri !== null ||
    child.sessionStateUri !== null ||
    child.workspaceBaseSha !== null ||
    child.error !== null
  ) {
    throw retryError("governed_retry_lineage_invalid", "successor_not_clean");
  }
}

function minimalGithubIdentity(value: unknown) {
  const gh = objectValue(value);
  const owner = stringValue(gh.owner);
  const repo = stringValue(gh.repo);
  const issueNumber = positiveInteger(gh.issueNumber);
  if (!owner || !repo || !issueNumber) {
    throw retryError("governed_retry_lineage_invalid", "github_issue_identity_missing");
  }
  return { owner, repo, issueNumber };
}

async function repositoryWriteClient(
  db: FacilityDb,
  repo: typeof repos.$inferSelect,
  options: GovernedRetryExternalOptions,
) {
  if (options.repositoryWriteClient) {
    if (options.repositoryWriteClient.repoId !== repo.id) {
      throw retryError("governed_retry_output_indeterminate", "github_client_repo_mismatch");
    }
    return options.repositoryWriteClient.client;
  }
  const factory =
    options.githubFactory ??
    (options.config?.githubAppId && options.config.githubAppPrivateKey
      ? createGithubClientFactory(options.config)
      : null);
  if (!factory) {
    throw retryError("governed_retry_output_indeterminate", "github_client_unavailable");
  }
  try {
    return await createGithubClientForRepo(db, factory, repo);
  } catch {
    throw retryError("governed_retry_output_indeterminate", "github_client_unavailable");
  }
}

function repositoryLeaseChainDigest(
  evidence: readonly {
    attempt: RunRow;
    rows: readonly (typeof runRepositoryWriteLeases.$inferSelect)[];
  }[],
) {
  return createHash("sha256")
    .update(
      JSON.stringify(
        evidence.map(({ attempt, rows }) => ({
          runId: attempt.id,
          trackingVersion: attempt.repositoryWriteTrackingVersion,
          leases: [...rows]
            .sort((left, right) => left.id.localeCompare(right.id))
            .map((row) => ({
              id: row.id,
              repoId: row.repoId,
              provider: row.provider,
              status: row.status,
              requestedBranch: row.requestedBranch,
              authorizedBranch: row.authorizedBranch,
              baseSha: row.baseSha,
              permissions: row.permissions,
              issuedAt: row.issuedAt?.toISOString() ?? null,
              expiresAt: row.expiresAt?.toISOString() ?? null,
              failureReason: row.failureReason,
            })),
        })),
      ),
    )
    .digest("hex");
}

function sanitizedReason(value: string | undefined) {
  const normalized = value?.trim().replaceAll(/\p{Cc}/gu, " ");
  return normalized ? normalized.slice(0, 500) : null;
}

function retryError(code: string, reason: string) {
  return new ApiError(409, code, "Governed Builder retry was denied", { reason });
}

function governedReason(error: unknown, fallback: string) {
  const reason = stringValue(objectValue(error instanceof ApiError ? error.details : null).reason);
  return reason && GOVERNED_RETRY_DENIAL_REASONS.has(reason) ? reason : fallback;
}

function objectValue(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function positiveInteger(value: unknown) {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

function sha256Value(value: unknown) {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : null;
}
