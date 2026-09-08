import { createServer } from "node:http";

// Stateful HTTP boundary for the real Next pages and /api proxy. This fixture
// tests UI wiring, not authorization or durable storage implementation; those
// remain covered by the PostgreSQL/FakeWorkspaceRuntime integration suites.
const project = { id: "proj_ui", name: "Lifecycle fixture", slug: "lifecycle" };
const base = `/v1/projects/${project.id}/workspace-stories`;
const timestamp = "2026-09-01T00:00:00.000Z";
let permissions;
let bundle;
let messages;
let requests;
let failure;
const agent = { name: "builder", enabled: true, engine: "codex", model: "fixture-model" };

function reset(options = {}) {
  permissions = options.permissions ?? [
    "projects:read",
    "workspaces:read",
    "workspaces:execute",
    "projects:write",
  ];
  bundle = {
    story: {
      id: "story_ui",
      projectId: project.id,
      provider: "manual",
      externalId: "ui-fixture",
      title: "Persistent UI story",
      status: "ready",
      deletedAt: null,
      activeAgentName: null,
      branch: "fixture/story",
      pullRequestUrl: null,
    },
    workspace: {
      id: "ws_ui",
      provider: "fake",
      state: "running",
      volumeRef: "fixture-volume",
      lastActivityAt: timestamp,
      environment: { image: "fixture", ports: [] },
    },
    attention: [],
    timeline: [],
    turns: [],
    artifacts: [],
    needs_attention: false,
  };
  messages = [];
  requests = [];
  failure = null;
}
reset();

createServer(async (req, res) => {
  const path = new URL(req.url, "http://127.0.0.1").pathname;
  let raw = "";
  for await (const part of req) raw += part;
  const body = raw ? JSON.parse(raw) : undefined;
  const reply = (data, status = 200) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(data));
  };
  if (path === "/health") return reply({ ok: true });
  if (path === "/__reset" && req.method === "POST") {
    reset(body);
    return reply({ ok: true });
  }
  if (path === "/__fail" && req.method === "POST") {
    failure = body;
    return reply({ ok: true });
  }
  if (path === "/__state") return reply({ bundle, messages, requests });
  if (path === "/v1/me")
    return reply({
      principal: { email: "fixture@example.test" },
      org: { name: "Fixture" },
      permissions,
    });
  if (path === "/v1/projects") return reply([project]);
  if (path === `/v1/projects/${project.id}`) return reply(project);
  if (path === `/v1/projects/${project.id}/story-agents`) return reply({ agents: [agent] });
  if (req.method === "GET") {
    if (path === base) return reply({ stories: [bundle.story] });
    if (path === `${base}/story_ui`) return reply(bundle);
    if (path === `${base}/story_ui/conversation`) return reply({ messages });
    if (path === `${base}/story_ui/environment`)
      return reply({
        workspace: bundle.workspace,
        events: [],
        inspection: { state: bundle.workspace.state },
        services: [],
        metrics: {
          create_time_ms: null,
          wake_time_ms: null,
          active_compute: bundle.workspace.state === "running",
          retained_storage: bundle.workspace.state !== "destroyed",
          cost: { active_compute_cents: null, retained_storage_cents: null },
        },
      });
  }
  requests.push({
    method: req.method,
    path,
    body,
    surface: req.headers["x-facility-surface"],
    key: req.headers["idempotency-key"],
  });
  if (failure?.path === path) {
    const status = failure.status ?? 500;
    failure = null;
    return reply({ error: { message: "Fixture operation failed; retry is safe." } }, status);
  }
  if (req.method === "POST" && (path === base || path === `${base}/story_ui/messages`)) {
    if (path === base) bundle.story.title = body.title;
    messages.push({
      id: `message_${messages.length}`,
      role: "user",
      body: body.message,
      createdAt: timestamp,
      actor: { id: "fixture" },
    });
    bundle.workspace.state = "running";
    return reply(bundle, 202);
  }
  if (req.method === "POST" && path === `${base}/story_ui/suspend`) {
    bundle.workspace.state = "sleeping";
    return reply(bundle);
  }
  if (req.method === "POST" && path === `${base}/story_ui/archive`) {
    bundle.story.status = "archived";
    bundle.workspace.state = "sleeping";
    return reply(bundle);
  }
  if (req.method === "POST" && path === `${base}/story_ui/restore`) {
    bundle.story.status = "ready";
    return reply(bundle);
  }
  if (req.method === "DELETE" && path === `${base}/story_ui/workspace` && body?.confirm === true) {
    bundle.story.status = "archived";
    bundle.story.deletedAt = timestamp;
    bundle.workspace.state = "destroyed";
    return reply(bundle);
  }
  return reply({ error: { message: `Unexpected fixture request: ${req.method} ${path}` } }, 404);
}).listen(4491, "127.0.0.1");
