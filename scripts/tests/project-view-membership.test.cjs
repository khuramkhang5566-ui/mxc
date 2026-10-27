// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  desiredViewLabels,
  labelChanges,
  ensureViewLabels,
  syncIssue,
} = require("../sync-project-view-membership.cjs");

function issue(labels, logins = []) {
  return {
    labels: labels.map((name) => ({ name })),
    assignees: logins.map((login) => ({ login })),
  };
}

test("assigned networking work remains in Branden's view (#1261)", () => {
  assert.ok(
    desiredViewLabels(
      issue(["Backend-ProcessContainer-Networking"], ["bbonaby"])
    ).includes("View-bbonaby")
  );
});

test("assignment includes work outside an owner's areas and exclusions", () => {
  const result = desiredViewLabels(
    issue(["Backend-ProcessContainer-UI", "OS-MacOS"], ["BBONABY"])
  );
  assert.ok(result.includes("View-bbonaby"));
  assert.ok(result.includes("View-theelliotm"));
});

test("area work remains visible even when assigned to someone else", () => {
  const result = desiredViewLabels(
    issue(
      ["Backend-ProcessContainer", "Backend-ProcessContainer-Networking"],
      ["SohamDas2021"]
    )
  );
  assert.ok(result.includes("View-bbonaby"));
  assert.ok(result.includes("View-SohamDas2021"));
  assert.ok(!result.includes("View-mgudgin"));
  assert.ok(!result.includes("View-jsidewhite"));
});

test("shared SDK work retains its existing area owners", () => {
  const result = desiredViewLabels(issue(["Area-Rust-SDK"]));
  assert.deepEqual(result, [
    "View-mgudgin",
    "View-bbonaby",
    "View-jsidewhite",
  ]);
});

test("removes stale managed memberships without touching other labels", () => {
  assert.deepEqual(
    labelChanges(
      issue(["Backend-Seatbelt", "View-bbonaby", "View-theelliotm", "View-other"])
    ),
    { add: [], remove: ["View-bbonaby"] }
  );
});

test("synchronization reads current state and only changes derived labels", () => {
  const calls = [];
  const api = (method, endpoint, payload) => {
    calls.push({ method, endpoint, payload });
    if (method === "GET") {
      return issue(["Issue-Bug", "Backend-Seatbelt", "View-bbonaby"]);
    }
  };
  syncIssue(api, "test/repo", 123, true, () => {});
  assert.deepEqual(calls, [
    { method: "GET", endpoint: "repos/test/repo/issues/123", payload: undefined },
    {
      method: "POST",
      endpoint: "repos/test/repo/issues/123/labels",
      payload: { labels: ["View-theelliotm"] },
    },
    {
      method: "DELETE",
      endpoint: "repos/test/repo/issues/123/labels/View-bbonaby",
      payload: undefined,
    },
  ]);
});

test("dry runs make no writes and invalid issue data fails explicitly", () => {
  const calls = [];
  const api = (method) => {
    calls.push(method);
    return issue(["Backend-Seatbelt"]);
  };
  syncIssue(api, "test/repo", 123, false, () => {});
  assert.deepEqual(calls, ["GET"]);
  assert.throws(() => desiredViewLabels({ labels: [] }), /assignees arrays/);
});

test("refuses to take over an existing label with another purpose", () => {
  const calls = [];
  const api = (method) => {
    calls.push(method);
    return [{ name: "View-bbonaby", description: "Manually maintained label" }];
  };
  assert.throws(
    () => ensureViewLabels(api, "test/repo"),
    /another purpose|different purpose/
  );
  assert.deepEqual(calls, ["GET"]);
});

test("concurrent label creation is verified and other failures propagate", () => {
  const description =
    "Managed project-view membership: area responsibility or issue assignment.";
  const api = (method, endpoint) => {
    if (endpoint.includes("?")) return [];
    if (method === "POST") {
      const error = new Error("Label already exists");
      error.stdout = JSON.stringify({
        errors: [{ resource: "Label", code: "already_exists" }],
      });
      throw error;
    }
    return { name: decodeURIComponent(endpoint.split("/").pop()), description };
  };
  assert.doesNotThrow(() => ensureViewLabels(api, "test/repo"));
  const failure = new Error("Authentication failed");
  assert.throws(
    () =>
      ensureViewLabels((method) => {
        if (method === "GET") return [];
        throw failure;
      }, "test/repo"),
    (error) => error === failure
  );
});
