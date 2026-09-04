import { open, verifyKey } from "@facility/core";
import {
  type FacilityDb,
  githubInstallations,
  insertAuditEvent,
  repos,
  runs,
  steerMessages,
} from "@facility/db";
import { isBuilderMode } from "@facility/run-objective";
import { and, asc, eq, gt, inArray, isNull, sql } from "drizzle-orm";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  readSessionStateObject,
  writeSessionStateObject,
  writeTranscriptObject,
} from "../envelopes.js";
import { ApiError, notFound } from "../errors.js";
import {
  createGithubClientFactory,
  createGithubInstallationTokenFactory,
  FacilityGithubClient,
  type GithubInstallationTokenFactory,
} from "../github/client.js";
import { collectGithubSecuritySweepEvidence } from "../github/security-sweep.js";
import {
  markRepositoryWriteLeaseIssued,
  reserveRepositoryWriteLease,
  selectAvailableRepositoryWriteBranch,
} from "../repository-write-lease.js";
import { finishRun, updateGithubRunProgress } from "../sandbox/orchestrator.js";
import {
  appendRunEvents,
  type RunSandboxState,
  readSandbox,
  terminalStatus,
} from "../sandbox/state.js";
import type { AppConfig } from "../types.js";

const Params = z.object({ runId: z.string() });
const GitCommitSha = z.string().regex(/^[0-9a-f]{40}$/i);
const TrackedPushTokenRequest = z
  .object({
    workflowWrite: z.boolean().optional(),
    requestedBranch: z.string().min(1).max(255),
    baseSha: GitCommitSha,
  })
  .strict();
const PushTokenRequest = z
  .union([TrackedPushTokenRequest, z.object({ workflowWrite: z.boolean().optional() }).strict()])
  .nullish();
const TRANSCRIPT_MAX_BYTES = 50 * 1024 * 1024;
const SESSION_STATE_MAX_BYTES = 200 * 1024 * 1024;
const EventBatch = z.array(
  z.object({
    type: z.string().min(1),
    data: z.record(z.string(), z.unknown()).optional(),
    ts: z.string().optional(),
  }),
);

type RunnerRequest = FastifyRequest & {
  runnerRun?: typeof runs.$inferSelect;
};

export async function registerInternalRoutes(app: FastifyInstance, config: AppConfig) {
  const db = app.facilityDb;

  if (!app.hasContentTypeParser("application/x-ndjson")) {
    app.addContentTypeParser(
      "application/x-ndjson",
      { parseAs: "buffer", bodyLimit: TRANSCRIPT_MAX_BYTES },
      (_request, body, done) => done(null, body),
    );
  }
  if (!app.hasContentTypeParser("application/gzip")) {
    app.addContentTypeParser(
      "application/gzip",
      { parseAs: "buffer", bodyLimit: SESSION_STATE_MAX_BYTES },
      (_request, body, done) => done(null, body),
    );
  }

  async function authenticate(request: FastifyRequest) {
    const { runId } = request.params as { runId: string };
    const token = bearer(request.headers.authorization);
    if (!token) throw new ApiError(401, "unauthorized", "Runner token required");
    const run = (await db.select().from(runs).where(eq(runs.id, runId)).limit(1))[0];
    if (!run) throw notFound("Run not found");
    if (terminalStatus(run.status)) throw new ApiError(409, "run_terminal", "Run is terminal");
    const sandbox = readSandbox(run.sandbox);
    if (!sandbox.runnerTokenHash || !(await verifyKey(token, sandbox.runnerTokenHash))) {
      throw new ApiError(401, "unauthorized", "Invalid runner token");
    }
    (request as RunnerRequest).runnerRun = run;
  }

  async function leaseRunnerMutation(request: FastifyRequest) {
    const endOperation = app.beginRunRequestOperation(request);
    const snapshot = (request as RunnerRequest).runnerRun;
    try {
      if (!snapshot) throw notFound("Run not found");
      const snapshotSandbox = readSandbox(snapshot.sandbox);
      if (!snapshotSandbox.runnerTokenHash) {
        throw new ApiError(401, "unauthorized", "Runner token required");
      }
      const release = await app.acquireRunRequestLease(snapshot.id);
      request.releaseRunnerRunRequestLease = release;
      if (request.runRequestAborted || request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
      const current = (
        await db
          .select()
          .from(runs)
          .where(
            and(
              eq(runs.id, snapshot.id),
              eq(runs.orgId, snapshot.orgId),
              eq(runs.projectId, snapshot.projectId),
              eq(runs.status, "running"),
            ),
          )
          .limit(1)
      )[0];
      const sandbox = current ? readSandbox(current.sandbox) : null;
      if (
        !current ||
        !sandbox?.runnerTokenHash ||
        sandbox.runnerTokenHash !== snapshotSandbox.runnerTokenHash
      ) {
        throw new ApiError(
          409,
          "runner_callback_inactive",
          "Runner callback is no longer attached to an active run",
        );
      }
      if (request.runRequestAborted || request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
      (request as RunnerRequest).runnerRun = current;
    } finally {
      await endOperation();
    }
  }

  app.post(
    "/internal/runs/:runId/hello",
    {
      config: { public: true },
      preHandler: authenticate,
      schema: {
        params: Params,
        // Optional for a rolling upgrade: old runners remain usable, but their
        // runs retain tracking version 0 and therefore fail closed for retry.
        body: z
          .object({ repositoryWriteTrackingVersion: z.literal(1) })
          .strict()
          .nullish(),
        response: { 200: z.record(z.string(), z.unknown()) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const sandbox = readSandbox(run.sandbox);
      if (!sandbox.bundle || !sandbox.sealedVirtualKey) {
        throw new ApiError(409, "not_ready", "Run bundle is not ready");
      }
      if (sandbox.virtualKeyRevealedAt) {
        throw new ApiError(409, "virtual_key_revealed", "Run credentials were already revealed");
      }
      const securitySweepEvidence = isSecuritySweepMode(run.mode)
        ? await securitySweepEvidenceForRun(run, sandbox)
        : null;
      const repositoryWriteTrackingVersion = (
        request.body as { repositoryWriteTrackingVersion?: number } | null | undefined
      )?.repositoryWriteTrackingVersion;
      const acceptedRepositoryWriteTrackingVersion =
        config.repositoryWriteTrackingPromotionEnabled && repositoryWriteTrackingVersion === 1
          ? 1
          : 0;
      const virtualKeyRevealedAt = new Date().toISOString();
      // Claim the transition to running only if the run is still active. A cancel
      // that lands between the auth snapshot and here must win — we must not
      // resurrect a terminal run, and (critically) must not hand its sandbox the
      // sealed credentials after it was told to stop.
      const [claimed] = await db
        .update(runs)
        .set({
          status: "running",
          startedAt: run.startedAt ?? new Date(),
          repositoryWriteTrackingVersion: acceptedRepositoryWriteTrackingVersion,
          // launch() and /hello race on fast providers. Merge only the field
          // owned by this endpoint so a provider ref attached after the auth
          // snapshot cannot be erased by this one-shot credential claim.
          sandbox: sql`${runs.sandbox} || ${JSON.stringify({ virtualKeyRevealedAt })}::jsonb`,
          updatedAt: new Date(),
        })
        .where(and(eq(runs.id, run.id), eq(runs.status, "provisioning")))
        .returning({ id: runs.id });
      if (!claimed) {
        throw new ApiError(
          409,
          "run_credentials_already_released",
          "Run credentials are no longer available",
        );
      }
      // /hello is the sole provisioning -> running handshake. Take the shared
      // callback lease only after that CAS, then revalidate under it before any
      // one-shot credential is revealed. A concurrent cancel either waits for
      // the response or wins first and makes this fail closed.
      await leaseRunnerMutation(request);
      await appendRunEvents(db, run.orgId, run.id, [{ type: "hello", data: {} }]);
      await updateGithubRunProgress(db, run.id, "running", {
        config,
        githubClientFactory: app.githubClientFactory,
      }).catch(() => undefined);
      return {
        // Sandbox-facing URL — the container reaches the API via this host, not
        // the operator's public URL (which may be localhost).
        bundleUrl: `${config.sandboxApiUrl.replace(/\/$/, "")}/internal/runs/${run.id}/bundle`,
        virtualKey: await open(sandbox.sealedVirtualKey, config.secretMasterKey),
        // Least-privilege platform key (KB + tasks, project-scoped) for a
        // harness agent to maintain the KB via the /v1 API. Revoked at run end.
        platformKey: sandbox.sealedPlatformKey
          ? await open(sandbox.sealedPlatformKey, config.secretMasterKey)
          : null,
        platformApiUrl: config.sandboxApiUrl.replace(/\/$/, ""),
        projectId: sandbox.projectId ?? run.projectId,
        // Short-lived clone credential for private repos. In production this is
        // a per-run GitHub App installation token; here it falls back to a
        // configured token for self-host / validation.
        repoToken: await repoTokenForRun(run, sandbox),
        // Released through the same one-shot authenticated handshake as the
        // virtual and clone keys, and only when this run has a dedicated
        // dependency-install phase. The sandbox task itself has no IAM access
        // to the registry secret.
        packageRegistryToken: sandbox.bundle.packageInstallCmd
          ? (config.packageRegistryToken ?? null)
          : null,
        securitySweepEvidence,
        gatewayUrls: sandbox.bundle.gatewayUrls,
        repositoryWriteTrackingVersion: acceptedRepositoryWriteTrackingVersion,
      };
    },
  );

  app.get(
    "/internal/runs/:runId/bundle",
    {
      config: { public: true },
      preHandler: authenticate,
      schema: {
        params: Params,
        response: { 200: z.record(z.string(), z.unknown()) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const bundle = readSandbox(run.sandbox).bundle;
      if (!bundle) throw notFound("Bundle not found");
      return bundle as unknown as Record<string, unknown>;
    },
  );

  app.post(
    "/internal/runs/:runId/workspace",
    {
      config: { public: true },
      preHandler: [authenticate, leaseRunnerMutation],
      schema: {
        params: Params,
        body: z.object({ baseSha: GitCommitSha }),
        response: { 200: z.object({ baseSha: GitCommitSha }) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const baseSha = (request.body as { baseSha: string }).baseSha.toLowerCase();
      const [recorded] = await db
        .update(runs)
        .set({ workspaceBaseSha: baseSha, updatedAt: new Date() })
        .where(and(eq(runs.orgId, run.orgId), eq(runs.id, run.id), isNull(runs.workspaceBaseSha)))
        .returning({ baseSha: runs.workspaceBaseSha });
      if (recorded?.baseSha) return { baseSha: recorded.baseSha };

      // Runner lifecycle requests may be replayed after a lost response. The
      // checkpoint is immutable: an exact replay succeeds, while a different
      // SHA cannot rewrite the provenance already bound to this run.
      const [current] = await db
        .select({ baseSha: runs.workspaceBaseSha })
        .from(runs)
        .where(and(eq(runs.orgId, run.orgId), eq(runs.id, run.id)))
        .limit(1);
      if (current?.baseSha === baseSha) return { baseSha };
      throw new ApiError(
        409,
        "workspace_base_mismatch",
        "Run workspace base commit was already recorded",
      );
    },
  );

  app.post(
    "/internal/runs/:runId/events",
    {
      config: { public: true },
      preHandler: [authenticate, leaseRunnerMutation],
      schema: {
        params: Params,
        body: EventBatch,
        response: { 200: z.object({ count: z.number().int() }) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const events = await appendRunEvents(
        db,
        run.orgId,
        run.id,
        request.body as z.infer<typeof EventBatch>,
      );
      const sessionId = events
        .filter((event) => event.type === "session")
        .map((event) =>
          event.data && typeof event.data === "object" && !Array.isArray(event.data)
            ? (event.data as Record<string, unknown>).engine_session_id
            : undefined,
        )
        .find(
          (value): value is string =>
            typeof value === "string" && value.trim().length > 0 && value.length <= 255,
        );
      if (sessionId) {
        // Persist the provider session as soon as it is observed. A provider
        // lease can disappear before /result, but that must remain a resumable
        // interruption rather than erase the continuation handle.
        await db
          .update(runs)
          .set({ engineSessionId: sessionId.trim(), updatedAt: new Date() })
          .where(and(eq(runs.orgId, run.orgId), eq(runs.id, run.id), isNull(runs.engineSessionId)));
      }
      if (events.some((event) => event.type === "agent_progress")) {
        await updateGithubRunProgress(db, run.id, "running", {
          config,
          githubClientFactory: app.githubClientFactory,
        }).catch(() => undefined);
      }
      return { count: events.length };
    },
  );

  app.get(
    "/internal/runs/:runId/steer",
    {
      config: { public: true },
      // Polling is read-only and may wait for 25 seconds. Acquire the shared
      // run lease only once there is a message to claim, so long polls cannot
      // exhaust the callback lease pool.
      preHandler: authenticate,
      schema: {
        params: Params,
        querystring: z.object({ afterId: z.string().optional() }),
        response: { 200: z.array(z.record(z.string(), z.unknown())) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const { afterId } = request.query as { afterId?: string };
      const deadline = Date.now() + 25_000;
      while (Date.now() < deadline) {
        const clauses = [eq(steerMessages.runId, run.id), isNull(steerMessages.deliveredAt)];
        if (afterId) clauses.push(gt(steerMessages.id, afterId));
        const messages = await db
          .select()
          .from(steerMessages)
          .where(and(...clauses))
          .orderBy(asc(steerMessages.createdAt))
          .limit(10);
        if (messages.length > 0) {
          await leaseRunnerMutation(request);
          const activeRun = (request as RunnerRequest).runnerRun;
          if (!activeRun) throw notFound("Run not found");
          const claimed = await db
            .update(steerMessages)
            .set({ deliveredAt: new Date() })
            .where(
              and(
                eq(steerMessages.runId, activeRun.id),
                isNull(steerMessages.deliveredAt),
                inArray(
                  steerMessages.id,
                  messages.map((message) => message.id),
                ),
              ),
            )
            .returning();
          const claimedIds = new Set(claimed.map((message) => message.id));
          return messages.filter((message) => claimedIds.has(message.id));
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
      return [];
    },
  );

  app.post(
    "/internal/runs/:runId/push-token",
    {
      config: { public: true },
      preHandler: authenticate,
      schema: {
        params: Params,
        body: PushTokenRequest,
        response: {
          200: z.object({
            token: z.string(),
            authorizedBranch: z.string().min(1).max(255).nullable(),
          }),
        },
      },
    },
    async (request) => {
      const authenticatedRun = (request as RunnerRequest).runnerRun;
      if (!authenticatedRun) throw notFound("Run not found");
      const authenticatedSandbox = readSandbox(authenticatedRun.sandbox);
      if (!authenticatedSandbox.runnerTokenHash) {
        throw new ApiError(401, "unauthorized", "Runner token required");
      }
      const body = (request.body ?? {}) as NonNullable<z.infer<typeof PushTokenRequest>>;
      const releaseTransitionLease = await app.acquireRunTransitionLease(authenticatedRun.id);
      request.releaseRunTransitionLease = releaseTransitionLease;
      if (request.runRequestAborted || request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
      const loadIssuanceContext = async (database: FacilityDb) => {
        const run = (
          await database
            .select()
            .from(runs)
            .where(
              and(
                eq(runs.id, authenticatedRun.id),
                eq(runs.orgId, authenticatedRun.orgId),
                eq(runs.projectId, authenticatedRun.projectId),
              ),
            )
            .limit(1)
        )[0];
        if (run?.status !== "running") {
          throw new ApiError(409, "run_terminal", "Run is not active for repository writes");
        }
        const sandbox = readSandbox(run.sandbox);
        if (sandbox.runnerTokenHash !== authenticatedSandbox.runnerTokenHash) {
          throw new ApiError(409, "runner_callback_inactive", "Runner credential changed");
        }
        if (!isBuilderMode(run.mode) && !repairRepositoryMode(run.mode)) {
          throw new ApiError(
            409,
            "repository_write_mode_forbidden",
            "Run mode is not allowed to request repository write credentials",
          );
        }
        const repoRef = await repoForRun(run, sandbox, database);
        if (!repoRef?.installationId) {
          throw new ApiError(409, "no_installation", "Run repository has no GitHub installation");
        }
        if (run.repositoryWriteTrackingVersion === 1) {
          if (!isTrackedPushTokenRequest(body)) {
            throw new ApiError(
              409,
              "repository_write_tracking_required",
              "Tracked runner omitted its durable repository write intent",
            );
          }
          assertRepositoryWriteIntent(run, sandbox, body.requestedBranch, body.baseSha);
        }
        const installation = (
          await database
            .select()
            .from(githubInstallations)
            .where(
              and(
                eq(githubInstallations.id, repoRef.installationId),
                eq(githubInstallations.orgId, run.orgId),
                sql`lower(${githubInstallations.accountLogin}) = lower(${repoRef.owner})`,
                isNull(githubInstallations.suspendedAt),
              ),
            )
            .limit(1)
        )[0];
        if (!installation) {
          throw new ApiError(409, "no_installation", "Run repository has no GitHub installation");
        }
        return { run, sandbox, repoRef, installation };
      };

      const initial = await loadIssuanceContext(db);
      const workflowWrite = body.workflowWrite ?? false;
      const permissions: Record<string, string> = workflowWrite
        ? { contents: "write", workflows: "write" }
        : { contents: "write" };
      const permissionNames = Object.keys(permissions);
      const tokenFactory =
        app.githubInstallationTokenFactory ?? createGithubInstallationTokenFactory(config);
      if (initial.run.repositoryWriteTrackingVersion !== 1) {
        if (isTrackedPushTokenRequest(body)) {
          throw new ApiError(
            409,
            "repository_write_tracking_required",
            "Run did not negotiate durable repository write tracking",
          );
        }
        const credential = await mintRepositoryWriteCredential(tokenFactory, initial, permissions);
        const { issuedAt, expiresAt } = exactCredentialTimes(credential);
        await insertAuditEvent(db, {
          orgId: initial.run.orgId,
          projectId: initial.run.projectId,
          actor: { type: "agent", id: initial.run.id },
          action: "run.push_token_issued",
          target: { type: "run", id: initial.run.id },
          payload: {
            repoId: initial.repoRef.id,
            provider: "github_installation",
            permissions: permissionNames,
            issuedAt: issuedAt.toISOString(),
            expiresAt: expiresAt.toISOString(),
            repositoryWriteTrackingVersion: 0,
          },
        });
        // Rolling-deploy compatibility only. There is deliberately no
        // invented branch evidence, and tracking version 0 makes this run
        // permanently fail closed for governed retry.
        return { token: credential.token, authorizedBranch: null };
      }
      if (!isTrackedPushTokenRequest(body)) {
        throw new ApiError(
          409,
          "repository_write_tracking_required",
          "Tracked runner omitted its durable repository write intent",
        );
      }
      const githubFactory = app.githubClientFactory ?? createGithubClientFactory(config);
      const github = new FacilityGithubClient(
        await githubFactory(initial.installation.installationId),
        {
          owner: initial.repoRef.owner,
          repo: initial.repoRef.name,
          defaultBranch: initial.repoRef.defaultBranch,
        },
      );
      const authorizedBranch = repairRepositoryMode(initial.run.mode)
        ? await verifyExistingRepositoryWriteBranch(
            github,
            initial.run,
            initial.repoRef,
            body.requestedBranch,
            body.baseSha,
          )
        : await selectAvailableRepositoryWriteBranch(github, body.requestedBranch, initial.run.id);

      // Transaction 1 commits durable evidence before any provider call. If
      // token minting becomes ambiguous, this reservation remains and later
      // retry admission fails closed until explicit reconciliation.
      const lease = await db.transaction(async (transaction) => {
        const tx = transaction as unknown as FacilityDb;
        const current = await loadIssuanceContext(tx);
        if (
          current.repoRef.id !== initial.repoRef.id ||
          current.installation.id !== initial.installation.id
        ) {
          throw new ApiError(
            409,
            "repository_write_context_changed",
            "Repository write context changed before reservation",
          );
        }
        return reserveRepositoryWriteLease(tx, {
          orgId: current.run.orgId,
          projectId: current.run.projectId,
          runId: current.run.id,
          repoId: current.repoRef.id,
          requestedBranch: body.requestedBranch,
          authorizedBranch,
          baseSha: body.baseSha,
          permissions: permissionNames,
        });
      });

      let credential: Awaited<ReturnType<typeof tokenFactory>>;
      try {
        credential = await mintRepositoryWriteCredential(tokenFactory, initial, permissions);
      } catch {
        throw new ApiError(
          503,
          "repository_write_credential_indeterminate",
          "Repository write credential issuance is indeterminate",
          undefined,
          true,
        );
      }
      const { issuedAt, expiresAt } = exactCredentialTimes(credential);

      // Transaction 2 makes the exact provider expiry and audit durable. A
      // commit failure leaves transaction 1's reservation visible and the
      // credential is never returned to the runner.
      await db.transaction(async (transaction) => {
        const tx = transaction as unknown as FacilityDb;
        await markRepositoryWriteLeaseIssued(tx, lease, issuedAt, expiresAt);
        await insertAuditEvent(tx, {
          orgId: initial.run.orgId,
          projectId: initial.run.projectId,
          actor: { type: "agent", id: initial.run.id },
          action: "run.push_token_issued",
          target: { type: "run", id: initial.run.id },
          payload: {
            leaseId: lease.id,
            repoId: initial.repoRef.id,
            requestedBranch: body.requestedBranch,
            authorizedBranch,
            baseSha: body.baseSha.toLowerCase(),
            provider: "github_installation",
            permissions: permissionNames,
            issuedAt: issuedAt.toISOString(),
            expiresAt: expiresAt.toISOString(),
          },
        });
      });
      return { token: credential.token, authorizedBranch };
    },
  );

  app.post(
    "/internal/runs/:runId/transcript",
    {
      config: { public: true },
      preHandler: [authenticate, leaseRunnerMutation],
      schema: {
        params: Params,
        response: { 200: z.object({ uri: z.string() }) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      if (!Buffer.isBuffer(request.body)) {
        throw new ApiError(400, "invalid_transcript", "Transcript body must be ndjson bytes");
      }
      if (request.body.length > TRANSCRIPT_MAX_BYTES) {
        throw new ApiError(413, "payload_too_large", "Transcript exceeds 50 MB");
      }
      const uri = await writeTranscriptObject({
        config,
        orgId: run.orgId,
        runId: run.id,
        body: request.body,
      });
      await db
        .update(runs)
        .set({ transcriptUri: uri, updatedAt: new Date() })
        .where(and(eq(runs.orgId, run.orgId), eq(runs.id, run.id)));
      return { uri };
    },
  );

  app.post(
    "/internal/runs/:runId/session-state",
    {
      config: { public: true },
      preHandler: [authenticate, leaseRunnerMutation],
      schema: {
        params: Params,
        response: { 200: z.object({ uri: z.string() }) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      if (!Buffer.isBuffer(request.body)) {
        throw new ApiError(400, "invalid_session_state", "Session state body must be gzip bytes");
      }
      if (request.body.length > SESSION_STATE_MAX_BYTES) {
        throw new ApiError(413, "payload_too_large", "Session state exceeds 200 MB");
      }
      const uri = await writeSessionStateObject({
        config,
        orgId: run.orgId,
        runId: run.id,
        body: request.body,
      });
      await db
        .update(runs)
        .set({ sessionStateUri: uri, updatedAt: new Date() })
        .where(and(eq(runs.orgId, run.orgId), eq(runs.id, run.id)));
      return { uri };
    },
  );

  app.get(
    "/internal/runs/:runId/session-state",
    {
      config: { public: true },
      preHandler: authenticate,
      schema: { params: Params },
    },
    async (request, reply) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const sandbox = readSandbox(run.sandbox);
      const resume = sandbox.bundle?.resume;
      if (!resume?.sessionStateFrom) throw notFound("Session state not found");
      const parent = (
        await db
          .select()
          .from(runs)
          .where(
            and(
              eq(runs.orgId, run.orgId),
              eq(runs.projectId, run.projectId),
              run.agentDefId ? eq(runs.agentDefId, run.agentDefId) : isNull(runs.agentDefId),
              eq(runs.id, resume.sessionStateFrom),
            ),
          )
          .limit(1)
      )[0];
      if (!parent) throw notFound("Session state not found");
      const body = await readSessionStateObject(config, parent.sessionStateUri, parent.orgId);
      return reply.type("application/gzip").send(body);
    },
  );

  app.post(
    "/internal/runs/:runId/result",
    {
      config: { public: true },
      preHandler: authenticate,
      schema: {
        params: Params,
        body: z.object({
          status: z.enum(["succeeded", "failed", "canceled"]),
          receipt: z.record(z.string(), z.unknown()).optional(),
          error: z.string().optional(),
          git: z
            .object({
              branch: z.string().optional(),
              headSha: z.string().optional(),
              baseSha: GitCommitSha.optional(),
              changed: z.boolean(),
              pushError: z.string().optional(),
              pullRequestTitle: z.string().optional(),
              pullRequestBody: z.string().optional(),
            })
            .optional(),
          engineSessionId: z.string().optional(),
          securityReport: z.unknown().optional(),
        }),
        response: { 200: z.record(z.string(), z.unknown()) },
      },
    },
    async (request) => {
      const run = (request as RunnerRequest).runnerRun;
      if (!run) throw notFound("Run not found");
      const body = request.body as {
        status: "succeeded" | "failed" | "canceled";
        receipt?: Record<string, unknown>;
        error?: string;
        git?: {
          branch?: string;
          headSha?: string;
          baseSha?: string;
          changed: boolean;
          pushError?: string;
          pullRequestTitle?: string;
          pullRequestBody?: string;
        };
        engineSessionId?: string;
        securityReport?: unknown;
      };
      return (await finishRun(db, run, body, {
        config,
        githubClientFactory: app.githubClientFactory,
        transitionDb: app.runTransitionDb,
        enqueue: app.enqueue,
      })) as unknown as Record<string, unknown>;
    },
  );

  // The global clone token is a dev / single-tenant convenience. In a
  // production-serious deployment (no internal test session, !facilityInsecureDev) it would
  // let any tenant clone an arbitrary repo they named with a shared token, so it
  // is refused there — a repo needs a real GitHub App installation instead. This
  // mirrors the doctor's production posture and the gateway's dev-key fallback.
  const cloneTokenFallback = (): string | null =>
    config.facilityInsecureDev ? (config.githubCloneToken ?? null) : null;

  async function repoTokenForRun(
    run: typeof runs.$inferSelect,
    sandbox: RunSandboxState,
  ): Promise<string | null> {
    const bundleRepo = sandbox.bundle?.repo;
    if (!bundleRepo?.installationTokenRef || !bundleRepo.cloneUrl) return cloneTokenFallback();
    const parsed = parseGithubCloneUrl(bundleRepo.cloneUrl);
    if (!parsed) return cloneTokenFallback();
    const boundRepo = await repoForRun(run, sandbox);
    if (!boundRepo || boundRepo.installationId !== bundleRepo.installationTokenRef) {
      return cloneTokenFallback();
    }
    const installation = (
      await db
        .select()
        .from(githubInstallations)
        .where(
          and(
            eq(githubInstallations.id, bundleRepo.installationTokenRef),
            eq(githubInstallations.orgId, run.orgId),
            sql`lower(${githubInstallations.accountLogin}) = lower(${parsed.owner})`,
            isNull(githubInstallations.suspendedAt),
          ),
        )
        .limit(1)
    )[0];
    if (!installation) return cloneTokenFallback();
    const tokenFactory =
      app.githubInstallationTokenFactory ??
      (config.githubAppId && config.githubAppPrivateKey
        ? createGithubInstallationTokenFactory(config)
        : null);
    if (!tokenFactory) return cloneTokenFallback();
    const credential = await tokenFactory({
      installationId: installation.installationId,
      owner: parsed.owner,
      repo: parsed.repo,
      permissions: { contents: "read" },
    });
    return credential.token;
  }

  async function repoForRun(
    run: typeof runs.$inferSelect,
    sandbox: RunSandboxState,
    database: FacilityDb = db,
  ) {
    const parsed = sandbox.bundle?.repo?.cloneUrl
      ? parseGithubCloneUrl(sandbox.bundle.repo.cloneUrl)
      : null;
    if (!parsed) return null;
    return (
      await database
        .select()
        .from(repos)
        .where(
          and(
            eq(repos.orgId, run.orgId),
            eq(repos.projectId, run.projectId),
            eq(repos.owner, parsed.owner),
            eq(repos.name, parsed.repo),
          ),
        )
        .limit(1)
    )[0];
  }

  function assertRepositoryWriteIntent(
    run: typeof runs.$inferSelect,
    sandbox: RunSandboxState,
    requestedBranch: string,
    baseSha: string,
  ) {
    const normalizedBaseSha = baseSha.toLowerCase();
    const workspaceBaseSha = gitCommitSha(run.workspaceBaseSha);
    const bundleBaseSha = gitCommitSha(sandbox.bundle?.repo.expectedHeadSha);
    const checkoutBranch = sandbox.bundle?.repo.branch;
    if (
      !workspaceBaseSha ||
      normalizedBaseSha !== workspaceBaseSha ||
      (bundleBaseSha && bundleBaseSha !== normalizedBaseSha) ||
      !checkoutBranch
    ) {
      throw new ApiError(
        409,
        "repository_write_base_mismatch",
        "Repository write intent does not match the verified workspace base",
      );
    }
    if (repairRepositoryMode(run.mode)) {
      const expectedBranch = stringValue(objectValue(run.gh).branch);
      if (
        !expectedBranch ||
        requestedBranch !== expectedBranch ||
        requestedBranch !== checkoutBranch
      ) {
        throw new ApiError(
          409,
          "repository_write_branch_mismatch",
          "Repository repair must target the exact admitted pull-request branch",
        );
      }
      assertGithubRefName(requestedBranch);
      return;
    }
    if (
      !isBuilderMode(run.mode) ||
      requestedBranch === checkoutBranch ||
      !/^(feature|fix|chore|ci|docs|refactor|perf|test|build|revert)\/[a-z0-9][a-z0-9._/-]*$/.test(
        requestedBranch,
      )
    ) {
      throw new ApiError(
        409,
        "repository_write_branch_mismatch",
        "Builder repository writes require a new semantic branch",
      );
    }
    assertGithubRefName(requestedBranch);
  }

  async function securitySweepEvidenceForRun(
    run: typeof runs.$inferSelect,
    sandbox: RunSandboxState,
  ) {
    const repo = await repoForRun(run, sandbox);
    if (!repo?.installationId) {
      throw new ApiError(
        409,
        "security_sweep_repo_unavailable",
        "Security sweep repository installation is unavailable",
      );
    }
    const installation = (
      await db
        .select()
        .from(githubInstallations)
        .where(
          and(
            eq(githubInstallations.id, repo.installationId),
            eq(githubInstallations.orgId, run.orgId),
            isNull(githubInstallations.suspendedAt),
          ),
        )
        .limit(1)
    )[0];
    if (!installation) {
      throw new ApiError(
        409,
        "security_sweep_installation_unavailable",
        "Security sweep GitHub installation is unavailable",
      );
    }
    const factory =
      app.githubClientFactory ??
      (config.githubAppId && config.githubAppPrivateKey ? createGithubClientFactory(config) : null);
    if (!factory) {
      throw new ApiError(
        409,
        "security_sweep_github_unavailable",
        "Security sweep GitHub client is unavailable",
      );
    }
    const ref = sandbox.bundle?.repo.branch;
    if (!ref) {
      throw new ApiError(
        409,
        "security_sweep_ref_unavailable",
        "Security sweep repository ref is unavailable",
      );
    }
    return collectGithubSecuritySweepEvidence({
      octokit: await factory(installation.installationId),
      runId: run.id,
      owner: repo.owner,
      repo: repo.name,
      ref,
    });
  }
}

function bearer(value: string | undefined) {
  if (!value?.startsWith("Bearer ")) return null;
  return value.slice("Bearer ".length);
}

function isTrackedPushTokenRequest(
  value: NonNullable<z.infer<typeof PushTokenRequest>>,
): value is z.infer<typeof TrackedPushTokenRequest> {
  return "requestedBranch" in value && "baseSha" in value;
}

async function mintRepositoryWriteCredential(
  tokenFactory: GithubInstallationTokenFactory,
  context: {
    installation: { installationId: number };
    repoRef: { owner: string; name: string };
  },
  permissions: Record<string, string>,
) {
  try {
    return await tokenFactory({
      installationId: context.installation.installationId,
      owner: context.repoRef.owner,
      repo: context.repoRef.name,
      permissions,
    });
  } catch {
    throw new ApiError(
      503,
      "repository_write_credential_indeterminate",
      "Repository write credential issuance is indeterminate",
      undefined,
      true,
    );
  }
}

function exactCredentialTimes(credential: { token: string; expiresAt: string }) {
  const issuedAt = new Date();
  const expiresAt = new Date(credential.expiresAt);
  if (
    !credential.token ||
    !Number.isFinite(expiresAt.getTime()) ||
    expiresAt.getTime() <= issuedAt.getTime()
  ) {
    throw new ApiError(
      503,
      "repository_write_credential_indeterminate",
      "Repository write credential expiry is indeterminate",
      undefined,
      true,
    );
  }
  return { issuedAt, expiresAt };
}

function parseGithubCloneUrl(value: string): { owner: string; repo: string } | null {
  const match = value.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!match?.[1] || !match[2]) return null;
  return { owner: match[1], repo: match[2] };
}

function isSecuritySweepMode(mode: string) {
  return ["security", "security_sweep"].includes(mode.replace(/^codex-/, "").replace(/-/g, "_"));
}

function repairRepositoryMode(mode: string) {
  return ["address_review", "ci_doctor"].includes(mode.replace(/^codex-/, "").replace(/-/g, "_"));
}

async function verifyExistingRepositoryWriteBranch(
  github: FacilityGithubClient,
  run: typeof runs.$inferSelect,
  repo: typeof repos.$inferSelect,
  branch: string,
  baseSha: string,
) {
  await github.assertRepositoryAccessible();
  const triggerPullRequest = objectValue(objectValue(run.trigger).pullRequest);
  const pullNumber = numberValue(triggerPullRequest.number);
  const admittedHead = stringValue(triggerPullRequest.head);
  const admittedHeadSha = gitCommitSha(triggerPullRequest.headSha);
  const admittedBase = stringValue(triggerPullRequest.base);
  if (
    !pullNumber ||
    admittedHead !== branch ||
    admittedHeadSha !== gitCommitSha(baseSha) ||
    admittedBase !== repo.defaultBranch ||
    numberValue(objectValue(run.gh).issueNumber) !== pullNumber
  ) {
    throw new ApiError(
      409,
      "repository_write_pull_request_mismatch",
      "Repository repair is not bound to its admitted pull request",
    );
  }
  try {
    const [headSha, pullRequest] = await Promise.all([
      github.getRef(branch),
      github.getPullRequestWriteTarget(pullNumber),
    ]);
    const repository = `${repo.owner}/${repo.name}`.toLowerCase();
    if (
      gitCommitSha(headSha) !== gitCommitSha(baseSha) ||
      pullRequest.number !== pullNumber ||
      pullRequest.state !== "open" ||
      pullRequest.mergedAt !== null ||
      pullRequest.headRepo.toLowerCase() !== repository ||
      pullRequest.baseRepo.toLowerCase() !== repository ||
      pullRequest.headRef !== branch ||
      gitCommitSha(pullRequest.headSha) !== gitCommitSha(baseSha) ||
      pullRequest.baseRef !== admittedBase
    ) {
      throw new Error("pull_request_write_target_changed");
    }
  } catch {
    throw new ApiError(
      409,
      "repository_write_pull_request_mismatch",
      "Repository repair pull request could not be verified",
    );
  }
  return branch;
}

function assertGithubRefName(branch: string) {
  if (
    !branch ||
    branch.length > 255 ||
    branch.startsWith("/") ||
    branch.endsWith("/") ||
    branch.endsWith(".") ||
    branch.includes("..") ||
    branch.includes("@{") ||
    [...branch].some((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code <= 32 || code === 127;
    }) ||
    ["~", "^", ":", "?", "*", "[", "\\"].some((character) => branch.includes(character))
  ) {
    throw new ApiError(
      409,
      "repository_write_branch_mismatch",
      "Repository write branch is not a valid GitHub ref name",
    );
  }
}

function gitCommitSha(value: unknown) {
  return typeof value === "string" && /^[a-f0-9]{40}$/i.test(value) ? value.toLowerCase() : null;
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function numberValue(value: unknown) {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null;
}
