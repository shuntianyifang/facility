import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ProjectStoriesPage from "../app/(app)/projects/[projectId]/stories/page";

const fixture = vi.hoisted(() => ({ permissions: [] as string[] }));
vi.mock("@/lib/api", () => ({
  api: {
    workspaceStories: async () => ({ ok: true, data: { stories: [] } }),
    storyAgents: async () => ({ ok: true, data: { agents: [{ name: "builder", enabled: true }] } }),
    me: async () => ({ ok: true, data: { permissions: fixture.permissions } }),
  },
}));
vi.mock("@/components/story/start-workspace-story", () => ({
  StartWorkspaceStory: () => "START_STORY",
}));
vi.mock("@/components/shell/live-refresh", () => ({ LiveRefresh: () => null }));

describe("story creation permission", () => {
  beforeEach(() => {
    fixture.permissions = [];
  });
  it.each([
    "workspaces:execute",
    "workspaces:*",
    "*",
  ])("shows creation for %s", async (permission) => {
    fixture.permissions = [permission];
    expect(await render()).toContain("START_STORY");
  });
  it.each([
    "projects:read",
    "projects:write",
    "runs:execute",
  ])("does not use %s to offer execution", async (permission) => {
    fixture.permissions = [permission];
    expect(await render()).not.toContain("START_STORY");
  });
});

async function render() {
  return renderToStaticMarkup(
    await ProjectStoriesPage({
      params: Promise.resolve({ projectId: "project" }),
      searchParams: Promise.resolve({}),
    }),
  );
}
