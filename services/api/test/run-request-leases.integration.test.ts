import { request as httpRequest } from "node:http";
import { generateApiKey, hashKey, newId, seal } from "@facility/core";
import {
  actionTypes,
  apiKeys,
  createDb,
  githubInstallations,
  idempotencyRecords,
  migrate,
  orgs,
  poTasks,
  projects,
  proposalEvents,
  proposals,
  repos,
  roles,
  runEvents,
  runRepositoryWriteLeases,
  runs,
  seed,
  steerMessages,
} from "@facility/db";
import { and, eq } from "drizzle-orm";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { AppConfig } from "../src/types.js";

const databaseUrl =
  process.env.DATABASE_URL ?? "postgres://facility:facility@127.0.0.1:5461/facility_test";
const masterKey = Buffer.alloc(32, 19).toString("base64");

async function canConnect() {
  const client = postgres(databaseUrl, { max: 1, connect_timeout: 10 });
  try {
    await client`select 1`;
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => undefined);
  }
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function outcomeWithin<T>(promise: Promise<T>, timeoutMs: number) {
  const pending = Symbol("pending");
  return Promise.race([
    promise,
    new Promise<typeof pending>((resolve) => setTimeout(() => resolve(pending), timeoutMs)),
  ]);
}

describe("active-run request leases", async () => {
  const reachable = await canConnect();
  if (!reachable) {
    it.skip("Postgres is unreachable at DATABASE_URL; request lease tests skipped", () =>
      undefined);
    return;
  }

  const config = (promotion: boolean): AppConfig => ({
    databaseUrl,
    secretMasterKey: masterKey,
    port: 4419,
    publicUrl: "http://127.0.0.1:0",
    sandboxApiUrl: "http://127.0.0.1:0",
    sandboxGatewayUrl: "http://127.0.0.1:0",
    gatewayUrl: "http://127.0.0.1:0",
    sandboxRunnerImage: "facility-runner:test",
    sandboxDriver: "docker",
    repositoryWriteTrackingPromotionEnabled: promotion,
    facilityInsecureDev: true,
    logLevel: "silent",
  });

  const { db, client } = createDb(databaseUrl);
  const defaultApp = await buildApp(config(false));
  const promotedApp = await buildApp(config(true));
  let handlerCommitBarrier:
    | { entered: ReturnType<typeof deferred>; release: ReturnType<typeof deferred> }
    | undefined;
  defaultApp.post(
    "/__test/run-mutation-after-commit",
    { config: { permission: "tasks:write", auditAction: "test.run_mutation" } },
    async (request, reply) => {
      const body = request.body as { projectId: string; title: string };
      await db.insert(poTasks).values({
        id: newId("task"),
        orgId: request.principal?.orgId ?? "",
        projectId: body.projectId,
        title: body.title,
        bodyMd: "committed before disconnect",
        status: "draft",
        wsjf: {},
      });
      handlerCommitBarrier?.entered.resolve();
      await handlerCommitBarrier?.release.promise;
      // Model a transport pipeline that is gone before onSend: the production
      // request wrapper must seal the idempotency key in its handler-finally
      // fallback rather than rely on response hooks that will never execute.
      reply.hijack();
      return reply;
    },
  );
  defaultApp.post(
    "/__test/run-mutation-server-error",
    { config: { permission: "tasks:write", auditAction: "test.run_mutation_error" } },
    async (request, reply) => {
      const body = request.body as { projectId: string; title: string };
      await db.insert(poTasks).values({
        id: newId("task"),
        orgId: request.principal?.orgId ?? "",
        projectId: body.projectId,
        title: body.title,
        bodyMd: "committed before server error",
        status: "draft",
        wsjf: {},
      });
      return reply.status(503).send({
        error: { code: "test_post_commit_failure", message: "Post-commit failure" },
      });
    },
  );
  let barrier: ((request: { url: string }) => Promise<void>) | undefined;
  for (const app of [defaultApp, promotedApp]) {
    app.addHook("onSend", async (request, _reply, payload) => {
      await barrier?.(request);
      return payload;
    });
  }

  let orgId = "";
  let projectId = "";
  let cookie = "";
  let baseUrl = "";

  beforeAll(async () => {
    await migrate(databaseUrl);
    await seed(databaseUrl);
    await defaultApp.ready();
    await promotedApp.ready();
    const login = await defaultApp.inject({
      method: "POST",
      url: "/__test/session",
      payload: { email: `run-lease-${Date.now()}@example.com` },
    });
    expect(login.statusCode).toBe(200);
    cookie = login.cookies.map((item) => `${item.name}=${item.value}`).join("; ");
    orgId = login.json().orgId;
    const [project] = await db
      .insert(projects)
      .values({
        id: newId("proj"),
        orgId,
        name: "Run request lease integration",
        slug: `run-request-lease-${Date.now()}`,
        settings: {},
      })
      .returning();
    if (!project) throw new Error("project fixture missing");
    projectId = project.id;
    const address = await defaultApp.listen({ host: "127.0.0.1", port: 0 });
    baseUrl = address;
  });

  afterAll(async () => {
    barrier = undefined;
    // The abort regression intentionally destroys a response socket while a
    // pre-handler is blocked. Do not let Node's test server keep that dead
    // transport in its graceful-close accounting after the lease assertion.
    defaultApp.server.closeAllConnections();
    await defaultApp.close();
    await promotedApp.close();
    await client.end();
  });

  async function insertRunnerRun(
    token: string,
    status: "provisioning" | "running" = "provisioning",
    overrides: Partial<typeof runs.$inferInsert> = {},
  ) {
    const runId = newId("run");
    const [run] = await db
      .insert(runs)
      .values({
        id: runId,
        orgId,
        projectId,
        mode: "builder",
        engine: "byo",
        status,
        trigger: {},
        sandbox: {
          runnerTokenHash: await hashKey(token),
          sealedVirtualKey: await seal(`fvk_${runId}`, masterKey),
          bundle: {
            runId,
            mode: "builder",
            engine: "byo",
            contract: "Build the requested change.",
            skills: [],
            engineConfig: {},
            repo: {
              cloneUrl: null,
              branch: null,
              expectedHeadSha: null,
              installationTokenRef: null,
            },
            packageInstallCmd: null,
            provisionCmd: null,
            checkCmds: [],
            gatewayUrls: { anthropic: "http://gateway/anthropic", openai: "http://gateway/openai" },
            scope: {},
            timeoutMin: 10,
          },
        },
        createdBy: { type: "user", id: "test" },
        ...overrides,
      })
      .returning();
    if (!run) throw new Error("run fixture missing");
    return run;
  }

  it("negotiates tracking only after promotion and preserves legacy null/no-body hello", async () => {
    const legacyToken = `frt_legacy_null_${Date.now()}`;
    const legacyRun = await insertRunnerRun(legacyToken);
    const legacy = await defaultApp.inject({
      method: "POST",
      url: `/internal/runs/${legacyRun.id}/hello`,
      headers: {
        authorization: `Bearer ${legacyToken}`,
        "content-type": "application/json",
      },
      payload: "null",
    });
    expect(legacy.statusCode, legacy.body).toBe(200);
    expect(legacy.json().repositoryWriteTrackingVersion).toBe(0);

    const disabledToken = `frt_disabled_promotion_${Date.now()}`;
    const disabledRun = await insertRunnerRun(disabledToken);
    const disabled = await defaultApp.inject({
      method: "POST",
      url: `/internal/runs/${disabledRun.id}/hello`,
      headers: { authorization: `Bearer ${disabledToken}` },
      payload: { repositoryWriteTrackingVersion: 1 },
    });
    expect(disabled.statusCode, disabled.body).toBe(200);
    expect(disabled.json().repositoryWriteTrackingVersion).toBe(0);

    const promotedToken = `frt_enabled_promotion_${Date.now()}`;
    const promotedRun = await insertRunnerRun(promotedToken);
    const promoted = await promotedApp.inject({
      method: "POST",
      url: `/internal/runs/${promotedRun.id}/hello`,
      headers: { authorization: `Bearer ${promotedToken}` },
      payload: { repositoryWriteTrackingVersion: 1 },
    });
    expect(promoted.statusCode, promoted.body).toBe(200);
    expect(promoted.json().repositoryWriteTrackingVersion).toBe(1);

    const stored = await db
      .select({ id: runs.id, version: runs.repositoryWriteTrackingVersion })
      .from(runs)
      .where(eq(runs.projectId, projectId));
    expect(stored.find((run) => run.id === legacyRun.id)?.version).toBe(0);
    expect(stored.find((run) => run.id === disabledRun.id)?.version).toBe(0);
    expect(stored.find((run) => run.id === promotedRun.id)?.version).toBe(1);
  });

  it("keeps the hello credential lease through onSend before cancel can win", async () => {
    const token = `frt_hello_barrier_${Date.now()}`;
    const run = await insertRunnerRun(token);
    const entered = deferred();
    const release = deferred();
    barrier = async (request) => {
      if (request.url !== `/internal/runs/${run.id}/hello`) return;
      entered.resolve();
      await release.promise;
    };

    const helloPromise = promotedApp.inject({
      method: "POST",
      url: `/internal/runs/${run.id}/hello`,
      headers: { authorization: `Bearer ${token}` },
      payload: { repositoryWriteTrackingVersion: 1 },
    });
    await entered.promise;
    const cancelPromise = promotedApp.inject({
      method: "POST",
      url: `/v1/runs/${run.id}/cancel`,
      headers: { cookie },
    });
    expect(await outcomeWithin(cancelPromise, 100)).toBeTypeOf("symbol");

    release.resolve();
    const hello = await helloPromise;
    const cancel = await cancelPromise;
    barrier = undefined;
    expect(hello.statusCode, hello.body).toBe(200);
    expect(hello.json().virtualKey).toMatch(/^fvk_/);
    expect(cancel.statusCode, cancel.body).toBe(200);
    expect(cancel.json().status).toBe("canceled");
  });

  it("keeps the repository write lease through onSend before cancel can win", async () => {
    const owner = `write-lease-${Date.now()}`;
    const [installation] = await db
      .insert(githubInstallations)
      .values({
        id: newId("int"),
        orgId,
        installationId: Date.now(),
        accountLogin: owner,
        targetType: "Organization",
      })
      .returning();
    if (!installation) throw new Error("installation fixture missing");
    const [repo] = await db
      .insert(repos)
      .values({
        id: newId("repo"),
        orgId,
        projectId,
        installationId: installation.id,
        owner,
        name: "repo",
        defaultBranch: "main",
      })
      .returning();
    if (!repo) throw new Error("repo fixture missing");
    const token = `frt_push_barrier_${Date.now()}`;
    const baseSha = "a".repeat(40);
    const run = await insertRunnerRun(token, "provisioning", {
      workspaceBaseSha: baseSha,
      sandbox: {
        runnerTokenHash: await hashKey(token),
        bundle: {
          repo: {
            cloneUrl: `https://github.com/${owner}/repo.git`,
            branch: "main",
            expectedHeadSha: baseSha,
            installationTokenRef: installation.id,
          },
        },
      },
    });
    await db
      .update(runs)
      .set({ status: "running", repositoryWriteTrackingVersion: 1 })
      .where(eq(runs.id, run.id));
    promotedApp.githubClientFactory = async () =>
      ({
        rest: {
          repos: {
            get: async () => ({ data: { name: "repo", owner: { login: owner } } }),
          },
          git: {
            getRef: async () => {
              throw Object.assign(new Error("Not Found"), { status: 404 });
            },
          },
          pulls: {
            list: async () => ({ data: [], headers: {} }),
          },
        },
      }) as never;
    const mintEntered = deferred();
    const releaseMint = deferred();
    promotedApp.githubInstallationTokenFactory = async () => {
      mintEntered.resolve();
      await releaseMint.promise;
      return {
        token: "github-write-token",
        expiresAt: "2099-01-01T00:00:00.000Z",
      };
    };
    const entered = deferred();
    const release = deferred();
    barrier = async (request) => {
      if (request.url !== `/internal/runs/${run.id}/push-token`) return;
      entered.resolve();
      await release.promise;
    };

    const pushPromise = promotedApp.inject({
      method: "POST",
      url: `/internal/runs/${run.id}/push-token`,
      headers: { authorization: `Bearer ${token}` },
      payload: { requestedBranch: "feature/task", baseSha },
    });
    await mintEntered.promise;
    expect(
      await db
        .select({ status: runRepositoryWriteLeases.status })
        .from(runRepositoryWriteLeases)
        .where(eq(runRepositoryWriteLeases.runId, run.id)),
    ).toEqual([{ status: "reserved" }]);
    releaseMint.resolve();
    await entered.promise;
    const cancelPromise = promotedApp.inject({
      method: "POST",
      url: `/v1/runs/${run.id}/cancel`,
      headers: { cookie },
    });
    expect(await outcomeWithin(cancelPromise, 100)).toBeTypeOf("symbol");

    release.resolve();
    const push = await pushPromise;
    const cancel = await cancelPromise;
    barrier = undefined;
    promotedApp.githubInstallationTokenFactory = undefined;
    promotedApp.githubClientFactory = undefined;
    expect(push.statusCode, push.body).toBe(200);
    const authorizedBranch = `feature/task-${run.id.toLowerCase().replace(/[^a-z0-9]/g, "")}`;
    expect(push.json()).toEqual({ token: "github-write-token", authorizedBranch });
    expect(
      await db
        .select()
        .from(runRepositoryWriteLeases)
        .where(eq(runRepositoryWriteLeases.runId, run.id)),
    ).toEqual([
      expect.objectContaining({
        status: "issued",
        requestedBranch: "feature/task",
        authorizedBranch,
        baseSha,
        permissions: ["contents"],
      }),
    ]);
    expect(cancel.statusCode, cancel.body).toBe(200);
    expect(cancel.json().status).toBe("canceled");
  });

  it("denies legacy repository-write tokens to read-only run modes", async () => {
    const owner = `read-only-write-denied-${crypto.randomUUID().slice(0, 8)}`;
    const [installation] = await db
      .insert(githubInstallations)
      .values({
        id: newId("int"),
        orgId,
        installationId: Date.now() + 10_000,
        accountLogin: owner,
        targetType: "Organization",
      })
      .returning();
    if (!installation) throw new Error("read-only installation fixture missing");
    await db.insert(repos).values({
      id: newId("repo"),
      orgId,
      projectId,
      installationId: installation.id,
      owner,
      name: "repo",
      defaultBranch: "main",
    });
    const token = `frt_read_only_write_denied_${Date.now()}`;
    const run = await insertRunnerRun(token, "running", {
      mode: "architect",
      sandbox: {
        runnerTokenHash: await hashKey(token),
        bundle: {
          repo: {
            cloneUrl: `https://github.com/${owner}/repo.git`,
            branch: "main",
            expectedHeadSha: "a".repeat(40),
            installationTokenRef: installation.id,
          },
        },
      },
    });
    let tokenFactoryCalls = 0;
    defaultApp.githubInstallationTokenFactory = async () => {
      tokenFactoryCalls += 1;
      return { token: "must-not-be-issued", expiresAt: "2099-01-01T00:00:00.000Z" };
    };
    const response = await defaultApp.inject({
      method: "POST",
      url: `/internal/runs/${run.id}/push-token`,
      headers: { authorization: `Bearer ${token}` },
    });
    defaultApp.githubInstallationTokenFactory = undefined;
    expect(response.statusCode, response.body).toBe(409);
    expect(response.json().error.code).toBe("repository_write_mode_forbidden");
    expect(tokenFactoryCalls).toBe(0);
  });

  it("reads terminal evidence only after shared mutations drain and never deadlocks with cancel", async () => {
    const token = `frt_terminal_evidence_${Date.now()}`;
    const run = await insertRunnerRun(token, "running");
    const releaseMutation = await defaultApp.acquireRunRequestLease(run.id);
    const resultPromise = defaultApp.inject({
      method: "POST",
      url: `/internal/runs/${run.id}/result`,
      headers: { authorization: `Bearer ${token}` },
      payload: { status: "failed", error: "test terminal boundary" },
    });
    expect(await outcomeWithin(resultPromise, 100)).toBeTypeOf("symbol");
    await db.insert(runEvents).values({
      orgId,
      runId: run.id,
      seq: 1,
      type: "check",
      data: { command: "late shared check", status: "passed", self_reported: false },
    });
    await releaseMutation();
    const result = await outcomeWithin(resultPromise, 2_000);
    expect(result).not.toBeTypeOf("symbol");
    if (typeof result !== "symbol") expect(result.statusCode, result.body).toBe(200);
    const [stored] = await db.select().from(runs).where(eq(runs.id, run.id));
    expect(stored?.status).toBe("failed");
    expect((stored?.receipt as { events?: { count?: number } })?.events?.count).toBe(1);

    const raceToken = `frt_result_cancel_race_${Date.now()}`;
    const raceRun = await insertRunnerRun(raceToken, "running");
    const raced = Promise.all([
      defaultApp.inject({
        method: "POST",
        url: `/internal/runs/${raceRun.id}/result`,
        headers: { authorization: `Bearer ${raceToken}` },
        payload: { status: "failed", error: "runner terminal race" },
      }),
      defaultApp.inject({
        method: "POST",
        url: `/v1/runs/${raceRun.id}/cancel`,
        headers: { cookie },
      }),
    ]);
    const raceResult = await outcomeWithin(raced, 2_000);
    expect(raceResult).not.toBeTypeOf("symbol");
    if (typeof raceResult !== "symbol") {
      const statuses = raceResult.map((response) => response.statusCode);
      expect(statuses).toContain(200);
      expect(statuses.every((status) => status === 200 || status === 409)).toBe(true);
    }
    const [racedStored] = await db.select().from(runs).where(eq(runs.id, raceRun.id));
    expect(["failed", "canceled"]).toContain(racedStored?.status);
  });

  it("keeps callbacks live while the dedicated transition pool is saturated", async () => {
    const blockedRuns = await Promise.all(
      Array.from({ length: 2 }, async (_, index) => {
        const token = `frt_transition_pool_blocked_${index}_${Date.now()}`;
        const run = await insertRunnerRun(token, "running");
        const release = await defaultApp.acquireRunRequestLease(run.id);
        return { run, token, release };
      }),
    );
    const terminalWaiters = blockedRuns.map(({ run, token }) =>
      defaultApp.inject({
        method: "POST",
        url: `/internal/runs/${run.id}/result`,
        headers: { authorization: `Bearer ${token}` },
        payload: { status: "failed", error: "transition pool saturation fixture" },
      }),
    );
    let released = false;
    try {
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(await outcomeWithin(Promise.all(terminalWaiters), 100)).toBeTypeOf("symbol");

      const callbackToken = `frt_transition_pool_callback_${Date.now()}`;
      const callbackRun = await insertRunnerRun(callbackToken, "running");
      const callback = defaultApp.inject({
        method: "POST",
        url: `/internal/runs/${callbackRun.id}/events`,
        headers: { authorization: `Bearer ${callbackToken}` },
        payload: [{ type: "phase", data: { name: "main-pool-still-live" } }],
      });
      const callbackResult = await outcomeWithin(callback, 2_000);
      expect(callbackResult).not.toBeTypeOf("symbol");
      if (typeof callbackResult !== "symbol") {
        expect(callbackResult.statusCode, callbackResult.body).toBe(200);
      }

      const queuedTerminal = defaultApp.inject({
        method: "POST",
        url: `/v1/runs/${callbackRun.id}/cancel`,
        headers: { cookie },
      });
      expect(await outcomeWithin(queuedTerminal, 100)).toBeTypeOf("symbol");
      await Promise.all(blockedRuns.map(({ release }) => release()));
      released = true;
      const completed = await outcomeWithin(
        Promise.all([...terminalWaiters, queuedTerminal]),
        2_000,
      );
      expect(completed).not.toBeTypeOf("symbol");
      if (typeof completed !== "symbol") {
        expect(completed.map((response) => response.statusCode)).toEqual([200, 200, 200]);
      }
    } finally {
      if (!released) await Promise.all(blockedRuns.map(({ release }) => release()));
    }
  });

  it("releases an aborted callback that was waiting in its pre-handler", async () => {
    const token = `frt_abort_prehandler_${Date.now()}`;
    const run = await insertRunnerRun(token, "running");
    const releaseBlocker = await defaultApp.acquireRunTransitionLease(run.id);
    const requestFinished = new Promise<void>((resolve) => {
      const request = httpRequest(
        `${baseUrl}/internal/runs/${run.id}/events`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
        },
        (response) => {
          response.resume();
          response.on("end", resolve);
        },
      );
      request.on("error", () => resolve());
      request.end(JSON.stringify([{ type: "phase", data: { shouldNotPersist: true } }]));
      setTimeout(() => request.destroy(), 75);
    });
    await new Promise((resolve) => setTimeout(resolve, 125));
    await releaseBlocker();
    await requestFinished;

    const secondExclusive = defaultApp.acquireRunTransitionLease(run.id);
    const acquired = await outcomeWithin(secondExclusive, 2_000);
    expect(acquired).not.toBeTypeOf("symbol");
    if (typeof acquired === "function") await acquired();
    const persisted = await db.select().from(runEvents).where(eq(runEvents.runId, run.id));
    expect(persisted.some((event) => event.type === "phase")).toBe(false);
  });

  it("abandons idempotency before releasing an aborted run-scoped platform request", async () => {
    const run = await insertRunnerRun(`frt_platform_abort_${Date.now()}`, "running");
    const [role] = await db
      .insert(roles)
      .values({
        id: newId("key"),
        orgId,
        name: `run-platform-writer-${Date.now()}`,
        permissions: ["org:read", "tasks:write"],
      })
      .returning();
    if (!role) throw new Error("role fixture missing");
    const key = await generateApiKey("fak");
    await db.insert(apiKeys).values({
      id: key.id,
      orgId,
      projectId,
      roleId: role.id,
      runId: run.id,
      name: "aborted run platform key",
      prefix: key.lookup,
      last4: key.last4,
      hash: key.hash,
      scopeType: "project",
      expiresAt: new Date(Date.now() + 60_000),
    });
    const releaseBlocker = await defaultApp.acquireRunTransitionLease(run.id);
    const title = `must-not-persist-${Date.now()}`;
    const idempotencyKey = `abort-platform-${crypto.randomUUID()}`;
    const requestFinished = new Promise<void>((resolve) => {
      const request = httpRequest(
        `${baseUrl}/v1/projects/${projectId}/tasks`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${key.secret}`,
            "content-type": "application/json",
            "idempotency-key": idempotencyKey,
          },
        },
        (response) => {
          response.resume();
          response.on("end", resolve);
        },
      );
      request.on("error", () => resolve());
      request.end(JSON.stringify({ title, bodyMd: "must not persist", status: "draft" }));
      setTimeout(() => request.destroy(), 100);
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    await releaseBlocker();
    await requestFinished;

    const secondExclusive = defaultApp.acquireRunTransitionLease(run.id);
    const acquired = await outcomeWithin(secondExclusive, 2_000);
    expect(acquired).not.toBeTypeOf("symbol");
    if (typeof acquired === "function") await acquired();
    expect(await db.select().from(poTasks).where(eq(poTasks.title, title))).toHaveLength(0);
    expect(
      await db
        .select()
        .from(idempotencyRecords)
        .where(eq(idempotencyRecords.principalId, `key:${key.id}`)),
    ).toHaveLength(0);

    const committedTitle = `committed-before-disconnect-${Date.now()}`;
    const committedIdempotencyKey = `committed-disconnect-${crypto.randomUUID()}`;
    handlerCommitBarrier = { entered: deferred(), release: deferred() };
    let committedRequest: ReturnType<typeof httpRequest> | undefined;
    const disconnected = new Promise<void>((resolve) => {
      committedRequest = httpRequest(
        `${baseUrl}/__test/run-mutation-after-commit`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${key.secret}`,
            "content-type": "application/json",
            "idempotency-key": committedIdempotencyKey,
          },
        },
        (response) => {
          response.resume();
          response.on("end", resolve);
        },
      );
      committedRequest.on("error", () => resolve());
      committedRequest.end(JSON.stringify({ projectId, title: committedTitle }));
    });
    await handlerCommitBarrier.entered.promise;
    committedRequest?.destroy();
    await disconnected;
    handlerCommitBarrier.release.resolve();
    const exclusiveAfterCommit = defaultApp.acquireRunTransitionLease(run.id);
    const acquiredAfterCommit = await outcomeWithin(exclusiveAfterCommit, 2_000);
    expect(acquiredAfterCommit).not.toBeTypeOf("symbol");
    if (typeof acquiredAfterCommit === "function") await acquiredAfterCommit();
    handlerCommitBarrier = undefined;

    const sealed = await db
      .select()
      .from(idempotencyRecords)
      .where(eq(idempotencyRecords.principalId, `key:${key.id}`));
    expect(sealed).toEqual([
      expect.objectContaining({
        state: "completed",
        statusCode: 409,
        responseBody: expect.objectContaining({
          error: expect.objectContaining({ code: "idempotency_outcome_indeterminate" }),
        }),
      }),
    ]);
    const replay = await defaultApp.inject({
      method: "POST",
      url: "/__test/run-mutation-after-commit",
      headers: {
        authorization: `Bearer ${key.secret}`,
        "idempotency-key": committedIdempotencyKey,
      },
      payload: { projectId, title: committedTitle },
    });
    expect(replay.statusCode, replay.body).toBe(409);
    expect(replay.json().error.code).toBe("idempotency_outcome_indeterminate");
    expect(await db.select().from(poTasks).where(eq(poTasks.title, committedTitle))).toHaveLength(
      1,
    );

    const failedTitle = `committed-before-5xx-${Date.now()}`;
    const failedIdempotencyKey = `committed-5xx-${crypto.randomUUID()}`;
    const failed = await defaultApp.inject({
      method: "POST",
      url: "/__test/run-mutation-server-error",
      headers: {
        authorization: `Bearer ${key.secret}`,
        "idempotency-key": failedIdempotencyKey,
      },
      payload: { projectId, title: failedTitle },
    });
    expect(failed.statusCode, failed.body).toBe(503);
    const failedReplay = await defaultApp.inject({
      method: "POST",
      url: "/__test/run-mutation-server-error",
      headers: {
        authorization: `Bearer ${key.secret}`,
        "idempotency-key": failedIdempotencyKey,
      },
      payload: { projectId, title: failedTitle },
    });
    expect(failedReplay.statusCode, failedReplay.body).toBe(503);
    expect(failedReplay.headers["idempotency-status"]).toBe("replayed");
    expect(await db.select().from(poTasks).where(eq(poTasks.title, failedTitle))).toHaveLength(1);

    // Even if a run-key pending row is older than the ordinary 15-minute
    // reclaim window, the same key must remain fail closed: the original
    // handler may have committed before losing its transport.
    const sealedId = sealed[0]?.id;
    if (!sealedId) throw new Error("sealed idempotency fixture missing");
    await db
      .update(idempotencyRecords)
      .set({
        state: "pending",
        statusCode: null,
        responseBody: null,
        updatedAt: new Date(Date.now() - 16 * 60_000),
      })
      .where(eq(idempotencyRecords.id, sealedId));
    const staleReplay = await defaultApp.inject({
      method: "POST",
      url: "/__test/run-mutation-after-commit",
      headers: {
        authorization: `Bearer ${key.secret}`,
        "idempotency-key": committedIdempotencyKey,
      },
      payload: { projectId, title: committedTitle },
    });
    expect(staleReplay.statusCode, staleReplay.body).toBe(409);
    expect(staleReplay.json().error.code).toBe("idempotency_in_progress");
    expect(await db.select().from(poTasks).where(eq(poTasks.title, committedTitle))).toHaveLength(
      1,
    );

    const proposedTitle = `run-key-proposal-${Date.now()}`;
    const deniedProposal = await defaultApp.inject({
      method: "POST",
      url: "/v1/mcp/tool-proposals",
      headers: { authorization: `Bearer ${key.secret}` },
      payload: {
        toolName: "facility_create_task",
        permission: "tasks:write",
        projectId,
        summary: "This deferred mutation must be denied",
        args: { projectId, title: proposedTitle, bodyMd: "denied" },
      },
    });
    expect(deniedProposal.statusCode, deniedProposal.body).toBe(403);
    expect(deniedProposal.json().error.code).toBe("run_key_deferred_mcp_forbidden");
    expect(await db.select().from(proposals).where(eq(proposals.runId, run.id))).toHaveLength(0);

    const actionType = (
      await db
        .select()
        .from(actionTypes)
        .where(and(eq(actionTypes.orgId, orgId), eq(actionTypes.name, "mcp_tool_call")))
        .limit(1)
    )[0];
    if (!actionType) throw new Error("mcp_tool_call action type missing");
    const historicalTitle = `historical-run-key-proposal-${Date.now()}`;
    const [historical] = await db
      .insert(proposals)
      .values({
        id: newId("prop"),
        orgId,
        projectId,
        runId: run.id,
        actionTypeId: actionType.id,
        payload: {
          toolName: "facility_create_task",
          permission: "tasks:write",
          args: { projectId, title: historicalTitle, bodyMd: "must not execute" },
          targetProjectId: projectId,
          requestedBy: { type: "key", id: key.id },
        },
        contextMd: "Historical run-key proposal",
        expiresAt: new Date(Date.now() + 60_000),
      })
      .returning();
    if (!historical) throw new Error("historical proposal missing");
    await db.insert(proposalEvents).values({
      orgId,
      proposalId: historical.id,
      seq: 1,
      type: "open",
      actor: { type: "key", id: key.id },
      data: {},
    });
    const decision = await defaultApp.inject({
      method: "POST",
      url: `/v1/proposals/${historical.id}/decide`,
      headers: { cookie },
      payload: { decision: "approve" },
    });
    expect(decision.statusCode, decision.body).toBe(200);
    expect(decision.json().state).toBe("execution_failed");
    expect(await db.select().from(poTasks).where(eq(poTasks.title, historicalTitle))).toHaveLength(
      0,
    );
  });

  it("binds hello clone tokens to the run tenant, repository owner, and live installation", async () => {
    const scopeSuffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
    const [foreignOrg] = await db
      .insert(orgs)
      .values({
        id: newId("org"),
        name: "Foreign clone-token org",
        slug: `foreign-clone-token-${Date.now()}`,
      })
      .returning();
    if (!foreignOrg) throw new Error("foreign org fixture missing");
    let tokenFactoryCalls = 0;
    defaultApp.githubInstallationTokenFactory = async () => {
      tokenFactoryCalls += 1;
      return { token: "must-not-be-issued", expiresAt: "2099-01-01T00:00:00.000Z" };
    };
    const cases = [
      { name: "foreign tenant", installationOrgId: foreignOrg.id, accountLogin: "bound-owner" },
      { name: "wrong owner", installationOrgId: orgId, accountLogin: "other-owner" },
      {
        name: "suspended",
        installationOrgId: orgId,
        accountLogin: "bound-owner",
        suspendedAt: new Date(),
      },
    ];
    for (const [index, fixture] of cases.entries()) {
      const owner = `bound-owner-${scopeSuffix}-${index}`;
      const [installation] = await db
        .insert(githubInstallations)
        .values({
          id: newId("int"),
          orgId: fixture.installationOrgId,
          installationId: Date.now() + 100 + index,
          accountLogin: fixture.name === "wrong owner" ? "other-owner" : owner,
          targetType: "Organization",
          suspendedAt: fixture.suspendedAt,
        })
        .returning();
      if (!installation) throw new Error(`${fixture.name} installation missing`);
      await db.insert(repos).values({
        id: newId("repo"),
        orgId,
        projectId,
        installationId: installation.id,
        owner,
        name: `repo-${scopeSuffix}-${index}`,
        defaultBranch: "main",
      });
      const token = `frt_clone_scope_${index}_${Date.now()}`;
      const run = await insertRunnerRun(token, "provisioning", {
        sandbox: {
          runnerTokenHash: await hashKey(token),
          sealedVirtualKey: await seal(`fvk_clone_scope_${index}`, masterKey),
          bundle: {
            repo: {
              cloneUrl: `https://github.com/${owner}/repo-${scopeSuffix}-${index}.git`,
              branch: "main",
              expectedHeadSha: null,
              installationTokenRef: installation.id,
            },
          },
        },
      });
      const response = await defaultApp.inject({
        method: "POST",
        url: `/internal/runs/${run.id}/hello`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode, `${fixture.name}: ${response.body}`).toBe(200);
      expect(response.json().repoToken).toBeNull();
    }
    defaultApp.githubInstallationTokenFactory = undefined;
    expect(tokenFactoryCalls).toBe(0);
  });

  it("does not hold shared leases while steering polls are idle", async () => {
    const pollingRuns = await Promise.all(
      Array.from({ length: 4 }, async (_, index) => {
        const token = `frt_steer_poll_${index}_${Date.now()}`;
        return { token, run: await insertRunnerRun(token, "running") };
      }),
    );
    const callbackToken = `frt_callback_after_polls_${Date.now()}`;
    const callbackRun = await insertRunnerRun(callbackToken, "running");
    const polls = pollingRuns.map(({ run, token }) =>
      defaultApp.inject({
        method: "GET",
        url: `/internal/runs/${run.id}/steer`,
        headers: { authorization: `Bearer ${token}` },
      }),
    );
    await new Promise((resolve) => setTimeout(resolve, 150));

    const callback = defaultApp.inject({
      method: "POST",
      url: `/internal/runs/${callbackRun.id}/events`,
      headers: { authorization: `Bearer ${callbackToken}` },
      payload: [{ type: "phase", data: { name: "not-starved" } }],
    });
    const completed = await outcomeWithin(callback, 2_000);
    expect(completed).not.toBeTypeOf("symbol");
    if (typeof completed !== "symbol") expect(completed.statusCode, completed.body).toBe(200);

    await db.insert(steerMessages).values(
      pollingRuns.map(({ run }, index) => ({
        id: newId("evt"),
        orgId,
        runId: run.id,
        kind: "steer",
        body: `wake-${index}`,
      })),
    );
    const responses = await Promise.all(polls);
    expect(responses.every((response) => response.statusCode === 200)).toBe(true);
  });
});
