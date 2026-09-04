import { can, keyLookup, newId, open, seal, verifyKey } from "@facility/core";
import {
  apiKeys,
  createDb,
  githubInstallations,
  insertAuditEvent,
  orgMembers,
  orgs,
  projects,
  roles as rolesTable,
  userIdentities,
  users,
} from "@facility/db";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import {
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
} from "fastify-type-provider-zod";
import type { JWTVerifyGetKey } from "jose";
import PgBoss from "pg-boss";
import { uuidv7 } from "uuidv7";
import { z } from "zod";
import { registerAuthorizationServer } from "./auth/authorization-server.js";
import { readConfig } from "./config.js";
import { ApiError, sendError } from "./errors.js";
import {
  abandonIdempotentRequest,
  beginIdempotentRequest,
  completeIdempotentRequest,
  finalizeIndeterminateIdempotentRequest,
} from "./idempotency.js";
import { looksLikeJwt, oauthConfigFromApp, verifyAccessToken } from "./oauth.js";
import {
  enrichOpenApi,
  type OpenApiDocument,
  type OpenApiRouteRecord,
} from "./openapi-contract.js";
import { assertPreviewOriginSurface } from "./previews.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerGithubRoutes } from "./routes/github.js";
import { registerInternalRoutes } from "./routes/internal.js";
import { registerV1Routes } from "./routes/v1.js";
import { registerWebhookRoutes } from "./routes/webhooks.js";
import {
  acquireExclusiveRunTransitionRequestLease,
  acquireRunApiKeyRequestLease,
  acquireSharedRunRequestLease,
} from "./run-api-key-lease.js";
import type { AppConfig, Principal } from "./types.js";

const publicRoutes = new Set([
  "GET /health",
  "GET /auth/login",
  "GET /auth/callback",
  "POST /auth/logout",
]);
const publicPrefixes = ["/docs"];

export async function buildApp(
  config: AppConfig = readConfig(),
  deps: { oauthJwks?: JWTVerifyGetKey; rateLimitMax?: number; authFetch?: typeof fetch } = {},
): Promise<FastifyInstance> {
  const oauthConfig = oauthConfigFromApp(config);
  const app = Fastify({
    logger: { level: config.logLevel },
    genReqId: () => uuidv7(),
  });
  const routeRecords: OpenApiRouteRecord[] = [];
  const { db, client } = createDb(config.databaseUrl);
  // Session advisory locks intentionally outlive individual SQL statements.
  // Keep them on a small dedicated pool so slow run-key requests can never
  // consume the application's query pool and deadlock their own handlers.
  const { client: runRequestLeaseClient } = createDb(config.databaseUrl, { max: 4 });
  // Writers need a distinct pool: if every shared slot is held by a long
  // callback, an exclusive transition must still connect and wait on the
  // advisory lock instead of starving behind the pool's FIFO queue.
  const { db: runTransitionDb, client: runTransitionLeaseClient } = createDb(config.databaseUrl, {
    max: 2,
  });
  app.decorate("facilityDb", db);
  app.decorate("githubClientFactory", undefined);
  app.decorate("githubInstallationTokenFactory", undefined);
  app.decorate("githubAppMetadataReader", undefined);
  app.decorate("runTransitionDb", runTransitionDb);
  app.decorate("acquireRunTransitionLease", (runId: string) =>
    acquireExclusiveRunTransitionRequestLease(runTransitionLeaseClient, runId),
  );
  app.decorate("acquireRunRequestLease", (runId: string) =>
    acquireSharedRunRequestLease(runRequestLeaseClient, runId),
  );

  // Producer-only pg-boss handle: routes enqueue, the worker consumes.
  const boss = new PgBoss({ connectionString: config.databaseUrl });
  boss.on("error", (error) => app.log.error({ err: error }, "pg-boss producer error"));
  let bossStarted = false;
  app.decorate("enqueue", async (queue: string, data: Record<string, unknown>) => {
    if (!bossStarted) {
      await boss.start();
      await boss.createQueue(queue);
      bossStarted = true;
    }
    return boss.send(queue, data);
  });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  app.addHook("onRoute", (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const method of methods) {
      routeRecords.push({
        method,
        url: route.url,
        permission: route.config?.permission as string | string[] | undefined,
        public: route.config?.public as boolean | undefined,
        idempotent: route.config?.idempotent as boolean | undefined,
      });
    }
  });

  app.setErrorHandler((error, request, reply) => {
    const err = error as Error & {
      statusCode?: number;
      code?: string;
      validation?: unknown;
      validationContext?: string;
      cause?: { code?: string };
    };
    if (error instanceof ApiError) {
      return sendError(reply, error);
    }
    const databaseCode = err.code ?? err.cause?.code;
    if (databaseCode === "23505") {
      return reply.status(409).send({
        error: { code: "conflict", message: "A resource with these values already exists" },
      });
    }
    if (databaseCode === "23503") {
      return reply.status(400).send({
        error: { code: "invalid_reference", message: "A referenced resource does not exist" },
      });
    }
    if (["23514", "22P02", "22007", "22008"].includes(databaseCode ?? "")) {
      return reply.status(400).send({
        error: { code: "bad_request", message: "Request values are invalid" },
      });
    }
    const status = typeof err.statusCode === "number" ? err.statusCode : 500;
    // Never leak internal error detail on 5xx — log it, return a generic message.
    if (status >= 500) {
      request.log.error({ err }, "unhandled server error");
      return reply
        .status(status)
        .send({ error: { code: "internal_error", message: "Internal server error" } });
    }
    return reply.status(status).send({
      error: {
        code: status === 400 ? (err.validation ? "validation_error" : "bad_request") : "error",
        message: err.message,
        ...(err.validation
          ? {
              details: {
                context: err.validationContext,
                issues: err.validation,
              },
            }
          : {}),
      },
    });
  });

  app.setNotFoundHandler((_request, reply) =>
    reply.status(404).send({ error: { code: "not_found", message: "Route not found" } }),
  );

  await app.register(cookie, { secret: config.secretMasterKey });
  await app.register(cors, {
    origin: [config.publicUrl, config.webUrl].filter((value): value is string => Boolean(value)),
    credentials: true,
  });
  // Local and CI runs use a generous ceiling; production keeps 200 requests/minute.
  await app.register(rateLimit, {
    max: deps.rateLimitMax ?? (config.facilityInsecureDev ? 100_000 : 200),
    timeWindow: "1 minute",
  });
  await app.register(swagger, {
    openapi: {
      info: {
        title: "Facility API",
        version: "0.3.0",
        description:
          "Control-plane API for projects, AI agent runs, human approval gates, knowledge, cost governance, and auditability.",
        contact: { name: "Facility", url: "https://github.com/theam/facility" },
        license: { name: "Apache-2.0", url: "https://www.apache.org/licenses/LICENSE-2.0" },
      },
      servers: config.publicUrl ? [{ url: config.publicUrl }] : undefined,
    },
    transform: jsonSchemaTransform,
    transformObject: (document) =>
      "openapiObject" in document
        ? enrichOpenApi(document.openapiObject as OpenApiDocument, routeRecords)
        : document.swaggerObject,
  });

  app.decorateRequest("principal", undefined);
  app.decorateRequest("idempotencyId", undefined);
  app.decorateRequest("idempotencyReplayed", false);
  app.decorateRequest("releasePlatformRunRequestLease", undefined);
  app.decorateRequest("releaseRunnerRunRequestLease", undefined);
  app.decorateRequest("releaseRunTransitionLease", undefined);
  app.decorateRequest("runRequestOperationCount", 0);
  app.decorateRequest("runRequestAborted", false);
  app.decorateRequest("runRequestAbortReleaseDeferred", false);
  app.decorateRequest("runRequestAbortCleanupPromise", undefined);
  app.decorateRequest("runRequestHandlerStarted", false);
  app.decorateRequest("runRequestHandlerSettled", false);
  app.decorateRequest(
    "audit",
    async function audit(this: FastifyRequest, action: string, target, payload = {}) {
      const principal = this.principal;
      if (!principal) return;
      const projectId =
        (target?.type === "project" ? target.id : undefined) ?? this.principal?.projectId ?? null;
      await insertAuditEvent(db, {
        orgId: principal.orgId,
        projectId,
        actor: { type: principal.type, id: principal.id },
        action,
        target,
        payload,
        ip: this.ip,
        userAgent: this.headers["user-agent"],
      });
    },
  );

  // The preview hostname reaches the existing API tasks to avoid another
  // service, but it is not an API origin. Enforce that boundary before any
  // Facility session is resolved so untrusted preview JavaScript cannot use
  // the host as an alternate control-plane entrypoint. A trusted reverse proxy
  // may replace Host, in which case its value-compared marker identifies the
  // preview surface without trusting user-controlled forwarding headers.
  app.addHook("onRequest", async (request) => {
    assertPreviewOriginSurface(
      config,
      request.headers.host,
      request.raw.url ?? request.url,
      request.headers["x-facility-preview-surface"],
    );
  });

  app.addHook("onRequest", async (request, reply) => {
    reply.header("x-request-id", request.id);
    request.principal = await resolvePrincipal(request, db, config, oauthConfig, deps.oauthJwks);
    const permission = request.routeOptions.config?.permission as string | string[] | undefined;
    const isPublic = request.routeOptions.config?.public === true;
    if (!permission && isPublic) return;
    if (!permission) return;
    if (!request.principal) {
      throw new ApiError(401, "unauthorized", "Authentication required");
    }
    if (request.routeOptions.config?.orgAdmin === true && request.principal.projectId) {
      throw new ApiError(
        403,
        "project_scope_forbidden",
        "Project-scoped keys cannot access organization admin endpoints",
      );
    }
    const projectId = (request.params as Record<string, string | undefined>)?.projectId;
    if (projectId) {
      // A project-scoped key is pinned to its project: anything else is 404,
      // not 403, so key holders cannot enumerate other projects.
      if (request.principal.projectId && request.principal.projectId !== projectId) {
        throw new ApiError(404, "not_found", "Project not found");
      }
      const project = (
        await db
          .select({ id: projects.id })
          .from(projects)
          .where(and(eq(projects.id, projectId), eq(projects.orgId, request.principal.orgId)))
          .limit(1)
      )[0];
      if (!project) {
        throw new ApiError(404, "not_found", "Project not found");
      }
    }
    const allowedPermissions = Array.isArray(permission) ? permission : [permission];
    // A sandbox platform key must never enter a terminal/retry route while it
    // holds this run's shared request lease. Besides exceeding its purpose,
    // self-cancel would wait on its own shared lock and cross-cancel could form
    // an A->B / B->A deadlock. Runner lifecycle uses the separate frt_ channel.
    if (request.principal.runId && request.routeOptions.config?.runLifecycle === true) {
      throw new ApiError(
        403,
        "run_key_lifecycle_forbidden",
        "Run-scoped platform keys cannot control run lifecycle",
      );
    }
    if (
      !allowedPermissions.some((candidate) => can(request.principal?.permissions ?? [], candidate))
    ) {
      throw new ApiError(403, "forbidden", "Permission denied", {
        needed: Array.isArray(permission) ? allowedPermissions : permission,
      });
    }
  });

  const releasePlatformRunRequestLease = async (request: FastifyRequest) => {
    const release = request.releasePlatformRunRequestLease;
    request.releasePlatformRunRequestLease = undefined;
    if (release) await release();
  };

  const releaseRunnerRunRequestLease = async (request: FastifyRequest) => {
    const release = request.releaseRunnerRunRequestLease;
    request.releaseRunnerRunRequestLease = undefined;
    if (release) await release();
  };

  const releaseRunTransitionLease = async (request: FastifyRequest) => {
    const release = request.releaseRunTransitionLease;
    request.releaseRunTransitionLease = undefined;
    if (release) await release();
  };

  const releaseAllRunRequestLeases = async (request: FastifyRequest) => {
    await Promise.all([
      releasePlatformRunRequestLease(request),
      releaseRunnerRunRequestLease(request),
      releaseRunTransitionLease(request),
    ]);
  };

  const releaseAbortedIdleRunRequest = async (request: FastifyRequest) => {
    if (!request.runRequestAborted || (request.runRequestOperationCount ?? 0) !== 0) return;
    if (request.runRequestAbortCleanupPromise) {
      await request.runRequestAbortCleanupPromise;
      return;
    }
    // Raw socket close and handler settlement can observe the same idle
    // request. Single-flight the durable idempotency transition so neither can
    // release the advisory lease while the other is still sealing the row.
    const cleanup = (async () => {
      if (!request.runRequestAborted || (request.runRequestOperationCount ?? 0) !== 0) return;
      if (request.runRequestHandlerStarted && !request.runRequestHandlerSettled) return;
      if (request.runRequestAbortReleaseDeferred || request.idempotencyId) {
        if (request.runRequestHandlerStarted) {
          await finalizeIndeterminateIdempotentRequest(db, request);
        } else {
          await abandonIdempotentRequest(db, request);
        }
      }
      request.runRequestAbortReleaseDeferred = false;
      await releaseAllRunRequestLeases(request);
    })();
    request.runRequestAbortCleanupPromise = cleanup;
    try {
      await cleanup;
    } finally {
      if (request.runRequestAbortCleanupPromise === cleanup) {
        request.runRequestAbortCleanupPromise = undefined;
      }
    }
  };

  // An aborted socket does not cancel JavaScript work. Count every pre-handler,
  // handler, and response hook that can still mutate state; an abort releases
  // leases only after the last such operation settles. Successful requests keep
  // their lease until onResponse, including one-shot credential delivery.
  app.decorate("beginRunRequestOperation", (request: FastifyRequest) => {
    request.runRequestOperationCount = (request.runRequestOperationCount ?? 0) + 1;
    let ended = false;
    return async () => {
      if (ended) return;
      ended = true;
      request.runRequestOperationCount = Math.max(0, (request.runRequestOperationCount ?? 1) - 1);
      await releaseAbortedIdleRunRequest(request);
    };
  });

  app.addHook("onRoute", (route) => {
    const handler = route.handler;
    route.handler = async function runRequestLeaseHandler(request, reply) {
      const endOperation = app.beginRunRequestOperation(request);
      try {
        if (request.runRequestAborted || request.raw.aborted) {
          request.runRequestAborted = true;
          throw new ApiError(409, "request_aborted", "Request was aborted before execution");
        }
        request.runRequestHandlerStarted = true;
        return await handler.call(this, request, reply);
      } finally {
        request.runRequestHandlerSettled = true;
        await endOperation();
      }
    };
  });

  app.addHook("onTimeout", async (request) => {
    request.runRequestAborted = true;
    await releaseAbortedIdleRunRequest(request);
  });
  app.addHook("onRequestAbort", async (request) => {
    request.runRequestAborted = true;
    await releaseAbortedIdleRunRequest(request);
  });

  // onRequestAbort covers an incomplete inbound body. A client may also send
  // its full mutation and disconnect while a pre-handler or onSend barrier is
  // waiting; Node does not mark IncomingMessage.aborted in that case. Observe
  // the response socket as well so request-lifetime advisory locks cannot leak.
  app.addHook("onRequest", async (request, reply) => {
    reply.raw.once("close", () => {
      if (reply.raw.writableFinished) return;
      request.runRequestAborted = true;
      void releaseAbortedIdleRunRequest(request).catch((error) => {
        request.log.error({ err: error }, "failed to release aborted run request lease");
      });
    });
  });

  app.addHook("preHandler", async (request, reply) => {
    const endOperation = app.beginRunRequestOperation(request);
    try {
      if (request.runRequestAborted || request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
      const principal = request.principal;
      if (
        reply.sent ||
        !principal?.runId ||
        ["GET", "HEAD", "OPTIONS"].includes(request.method.toUpperCase())
      ) {
        return;
      }
      request.releasePlatformRunRequestLease = await acquireRunApiKeyRequestLease(
        runRequestLeaseClient,
        {
          keyId: principal.id,
          runId: principal.runId,
          orgId: principal.orgId,
          projectId: principal.projectId,
        },
      );
      if (request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
    } finally {
      await endOperation();
    }
  });

  // Acquire and revalidate before idempotency replay. Otherwise a revoked
  // run-scoped key could receive a cached success (and mutate the replay row)
  // after a terminal transition had already won the exclusive lease.
  app.addHook("preHandler", async (request, reply) => {
    const endOperation = app.beginRunRequestOperation(request);
    try {
      if (request.runRequestAborted || request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
      const result = await beginIdempotentRequest(db, request, reply);
      if (request.idempotencyId) request.runRequestAbortReleaseDeferred = true;
      if (request.runRequestAborted || request.raw.aborted) {
        request.runRequestAborted = true;
        throw new ApiError(409, "request_aborted", "Request was aborted before execution");
      }
      return result;
    } finally {
      await endOperation();
    }
  });

  app.addHook("onSend", async (request, reply, payload) => {
    const endOperation = app.beginRunRequestOperation(request);
    try {
      // If the transport disappeared before this hook started, the cleanup
      // owns the idempotency outcome. Await it rather than racing a 409 seal
      // with persistence of a response the client can no longer receive.
      await request.runRequestAbortCleanupPromise;
      if ((request.runRequestAborted || request.raw.aborted) && !request.runRequestHandlerStarted) {
        request.runRequestAborted = true;
        await abandonIdempotentRequest(db, request);
      } else {
        await completeIdempotentRequest(db, request, reply, payload, {
          completeServerError: request.runRequestAborted === true,
        });
      }
      return payload;
    } finally {
      request.runRequestAbortReleaseDeferred = Boolean(request.idempotencyId);
      await endOperation();
    }
  });

  app.addHook("onResponse", async (request, reply) => {
    const endOperation = app.beginRunRequestOperation(request);
    try {
      if (request.runRequestAborted || request.raw.aborted) return;
      const permission = request.routeOptions.config?.permission;
      const action = request.routeOptions.config?.auditAction as string | undefined;
      if (
        !permission ||
        request.idempotencyReplayed ||
        request.method === "GET" ||
        reply.statusCode < 200 ||
        reply.statusCode >= 300 ||
        !action
      ) {
        return;
      }
      const params = request.params as Record<string, string | undefined>;
      await request.audit(action, {
        type: params.projectId ? "project" : "route",
        id: params.projectId ?? request.url,
      });
    } finally {
      await endOperation();
      await releaseAllRunRequestLeases(request);
    }
  });

  const healthOptions = {
    config: { public: true },
    schema: {
      response: {
        200: z.object({ ok: z.boolean(), version: z.string(), db: z.enum(["ok", "down"]) }),
        503: z.object({ ok: z.boolean(), version: z.string(), db: z.enum(["ok", "down"]) }),
      },
    },
  };
  const healthHandler = async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      await db.execute("select 1" as never);
      return { ok: true, version: "0.3.0", db: "ok" as const };
    } catch {
      return reply.status(503).send({ ok: false, version: "0.3.0", db: "down" as const });
    }
  };
  app.get("/health", healthOptions, healthHandler);
  app.get("/readyz", healthOptions, healthHandler);

  await registerAuthorizationServer(app, config);
  if (process.env.NODE_ENV === "test" || process.env.VITEST === "true") {
    app.post(
      "/__test/session",
      {
        config: { public: true },
        schema: { body: z.object({ email: z.string().email() }) },
      },
      async (request, reply) => {
        const session = await ensureDevUser(db, (request.body as { email: string }).email);
        reply.setCookie(
          "facility_session",
          await mintSessionCookie(config, session.userId, session.orgId),
          {
            httpOnly: true,
            sameSite: "lax",
            path: "/",
            secure: false,
          },
        );
        return { ok: true, ...session };
      },
    );
  }
  await registerAuthRoutes(app, config, { fetch: deps.authFetch });
  await registerInternalRoutes(app, config);
  await registerWebhookRoutes(app, config);
  await registerV1Routes(app, config);
  await registerGithubRoutes(app, config);

  await app.register(swaggerUi, { routePrefix: "/docs" });

  app.addHook("onReady", async () => {
    for (const route of routeRecords) {
      if (route.method === "OPTIONS" && route.url === "*") continue;
      if (publicPrefixes.some((prefix) => route.url.startsWith(prefix))) continue;
      if (route.public || publicRoutes.has(`${route.method} ${route.url}`)) continue;
      if (!route.permission) {
        throw new Error(
          `Protected route missing permission declaration: ${route.method} ${route.url}`,
        );
      }
    }
  });

  app.addHook("onClose", async () => {
    if (bossStarted) await boss.stop({ close: true });
    // Stop shared request holders before closing the pool used by exclusive
    // transitions that may be waiting on them.
    await runRequestLeaseClient.end({ timeout: 1 });
    await runTransitionLeaseClient.end({ timeout: 1 });
    await client.end();
  });

  return app;
}

async function resolvePrincipal(
  request: FastifyRequest,
  db: ReturnType<typeof createDb>["db"],
  config: AppConfig,
  oauthConfig: ReturnType<typeof oauthConfigFromApp>,
  oauthJwks?: JWTVerifyGetKey,
): Promise<Principal | undefined> {
  const auth = request.headers.authorization;
  if (auth?.startsWith("Bearer fak_")) {
    const secret = auth.slice("Bearer ".length);
    // One indexed lookup by the key's unique prefix, then one argon2 verify —
    // authentication cost must not grow with the number of keys in the org.
    const rows = await db
      .select({
        key: apiKeys,
        role: rolesTable,
      })
      .from(apiKeys)
      .innerJoin(rolesTable, eq(apiKeys.roleId, rolesTable.id))
      // Reject revoked keys and expired run-scoped keys (expiresAt is null for
      // ordinary keys). A run's platform key thus stops authenticating the moment
      // it expires, even if the terminal-path revoke was somehow missed.
      .where(
        and(
          eq(apiKeys.prefix, keyLookup(secret)),
          isNull(apiKeys.revokedAt),
          or(isNull(apiKeys.expiresAt), gt(apiKeys.expiresAt, new Date())),
        ),
      )
      .limit(2);
    for (const row of rows) {
      if (await verifyKey(secret, row.key.hash)) {
        await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, row.key.id));
        return {
          type: "key",
          id: row.key.id,
          orgId: row.key.orgId,
          projectId: row.key.projectId,
          runId: row.key.runId,
          permissions: row.role.permissions,
        };
      }
    }
    throw new ApiError(401, "unauthorized", "Invalid API key");
  }

  // OAuth access tokens are issued by this Facility instance for its MCP resource.
  if (auth?.startsWith("Bearer ") && oauthConfig) {
    const token = auth.slice("Bearer ".length);
    if (looksLikeJwt(token)) {
      let userId: string;
      let orgId: string;
      try {
        ({ userId, orgId } = await verifyAccessToken(token, oauthConfig, oauthJwks));
      } catch {
        throw new ApiError(401, "unauthorized", "Invalid access token");
      }
      const member = (
        await db
          .select({
            role: rolesTable,
            user: users,
            member: orgMembers,
            githubLogin: userIdentities.login,
          })
          .from(orgMembers)
          .innerJoin(rolesTable, eq(orgMembers.roleId, rolesTable.id))
          .innerJoin(users, eq(orgMembers.userId, users.id))
          .innerJoin(githubInstallations, eq(githubInstallations.orgId, orgMembers.orgId))
          .leftJoin(
            userIdentities,
            and(eq(userIdentities.userId, users.id), eq(userIdentities.provider, "github")),
          )
          .where(
            and(
              eq(users.id, userId),
              eq(orgMembers.orgId, orgId),
              eq(users.status, "active"),
              isNull(githubInstallations.suspendedAt),
            ),
          )
          .limit(1)
      )[0];
      if (!member) {
        throw new ApiError(403, "not_provisioned", "Authenticated user has no platform membership");
      }
      return {
        type: "user",
        id: member.user.id,
        userId: member.user.id,
        orgId: member.member.orgId,
        email: member.user.email,
        name: member.user.name ?? undefined,
        githubLogin: member.githubLogin ?? undefined,
        avatarUrl: member.user.avatarUrl ?? undefined,
        permissions: member.role.permissions,
      };
    }
  }

  const sealedSession = request.cookies.facility_session;
  if (!sealedSession) {
    return undefined;
  }
  try {
    const session = z
      .object({ userId: z.string(), orgId: z.string(), exp: z.number() })
      .parse(JSON.parse(await open(sealedSession, config.secretMasterKey)));
    if (session.exp < Date.now()) {
      throw new ApiError(401, "unauthorized", "Session expired");
    }
    const member = (
      await db
        .select({ role: rolesTable, user: users, githubLogin: userIdentities.login })
        .from(orgMembers)
        .innerJoin(rolesTable, eq(orgMembers.roleId, rolesTable.id))
        .innerJoin(users, eq(orgMembers.userId, users.id))
        .leftJoin(
          userIdentities,
          and(eq(userIdentities.userId, users.id), eq(userIdentities.provider, "github")),
        )
        .where(
          and(
            eq(orgMembers.userId, session.userId),
            eq(orgMembers.orgId, session.orgId),
            eq(users.status, "active"),
          ),
        )
        .limit(1)
    )[0];
    // No member row, or the user has been deactivated → session no longer valid.
    if (!member) return undefined;
    return {
      type: "user",
      id: session.userId,
      userId: session.userId,
      orgId: session.orgId,
      email: member.user.email,
      name: member.user.name ?? undefined,
      githubLogin: member.githubLogin ?? undefined,
      avatarUrl: member.user.avatarUrl ?? undefined,
      permissions: member.role.permissions,
    };
  } catch {
    return undefined;
  }
}

export async function mintSessionCookie(config: AppConfig, userId: string, orgId: string) {
  return seal(
    JSON.stringify({ userId, orgId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }),
    config.secretMasterKey,
  );
}

export async function ensureDevUser(db: ReturnType<typeof createDb>["db"], email: string) {
  const org = (await db.select().from(orgs).where(eq(orgs.slug, "the-agile-monkeys")).limit(1))[0];
  if (!org) throw new ApiError(500, "seed_required", "Dev org is not seeded");
  const role = (
    await db
      .select()
      .from(rolesTable)
      .where(
        and(
          eq(rolesTable.name, "owner"),
          or(isNull(rolesTable.orgId), eq(rolesTable.orgId, org.id)),
        ),
      )
      .limit(1)
  )[0];
  if (!role) throw new ApiError(500, "seed_required", "Bundled owner role is not seeded");
  const existing = (await db.select().from(users).where(eq(users.email, email)).limit(1))[0];
  const userId = existing?.id ?? newId("user");
  if (!existing) {
    await db.insert(users).values({ id: userId, email, name: email, status: "active" });
  }
  await db
    .insert(orgMembers)
    .values({ id: newId("user"), orgId: org.id, userId, roleId: role.id })
    .onConflictDoUpdate({
      target: [orgMembers.orgId, orgMembers.userId],
      set: { roleId: role.id, updatedAt: new Date() },
    });
  return { userId, orgId: org.id };
}
