#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync } = require("node:child_process");
const { parseArgs } = require("node:util");
const owners = require("./project-view-owners.json");

const labelDescription =
  "Managed project-view membership: area responsibility or issue assignment.";

function desiredViewLabels(issue, rules = owners) {
  if (!Array.isArray(issue.labels) || !Array.isArray(issue.assignees)) {
    throw new Error("Issue must contain complete labels and assignees arrays.");
  }
  const labels = new Set(
    issue.labels.map((label) => {
      const name = typeof label === "string" ? label : label.name;
      if (typeof name !== "string") {
        throw new Error("Issue contains a label without a name.");
      }
      return name.toLowerCase();
    })
  );
  const assignees = new Set(
    issue.assignees.map((assignee) => {
      if (typeof assignee.login !== "string") {
        throw new Error("Issue contains an assignee without a login.");
      }
      return assignee.login.toLowerCase();
    })
  );
  return Object.entries(rules)
    .filter(([login, rule]) => {
      const assigned = assignees.has(login.toLowerCase());
      const area =
        rule.labels.some((label) => labels.has(label.toLowerCase())) &&
        !rule.excludeLabels.some((label) => labels.has(label.toLowerCase()));
      return assigned || area;
    })
    .map(([login]) => `View-${login}`);
}

function labelChanges(issue, rules = owners) {
  const desired = desiredViewLabels(issue, rules);
  const wanted = new Set(desired.map((name) => name.toLowerCase()));
  const existing = issue.labels.map((label) =>
    typeof label === "string" ? label : label.name
  );
  const present = new Set(existing.map((name) => name.toLowerCase()));
  const managed = new Set(
    Object.keys(rules).map((login) => `view-${login.toLowerCase()}`)
  );
  return {
    add: desired.filter((name) => !present.has(name.toLowerCase())),
    remove: existing.filter(
      (name) =>
        managed.has(name.toLowerCase()) && !wanted.has(name.toLowerCase())
    ),
  };
}

function ghApi(method, endpoint, payload) {
  const args = ["api", "--hostname", "github.com", "--method", method, endpoint];
  if (payload !== undefined) args.push("--input", "-");
  const output = execFileSync("gh", args, {
    encoding: "utf8",
    input: payload === undefined ? undefined : JSON.stringify(payload),
    stdio: ["pipe", "pipe", "inherit"],
    maxBuffer: 16 * 1024 * 1024,
  });
  return output.trim() ? JSON.parse(output) : null;
}

function listAll(api, endpoint) {
  const result = [];
  for (let page = 1; ; page++) {
    const entries = api("GET", `${endpoint}&per_page=100&page=${page}`);
    if (!Array.isArray(entries)) {
      throw new Error(`Expected a paginated array from ${endpoint}.`);
    }
    result.push(...entries);
    if (entries.length < 100) return result;
  }
}

function ensureViewLabels(api, repo) {
  const existing = new Map(
    listAll(api, `repos/${repo}/labels?sort=name`).map((label) => [
      label.name.toLowerCase(),
      label,
    ])
  );
  const names = Object.keys(owners).map((login) => `View-${login}`);
  for (const name of names) {
    const label = existing.get(name.toLowerCase());
    if (label && label.description !== labelDescription) {
      throw new Error(
        `${name} already exists with a different purpose; refusing to take it over.`
      );
    }
  }
  for (const name of names) {
    if (existing.has(name.toLowerCase())) continue;
    try {
      api("POST", `repos/${repo}/labels`, {
        name,
        description: labelDescription,
        color: "ededed",
      });
    } catch (error) {
      const failure = error.stdout ? JSON.parse(error.stdout) : null;
      if (
        !failure?.errors?.some(
          (entry) => entry.resource === "Label" && entry.code === "already_exists"
        )
      ) {
        throw error;
      }
      const concurrent = api(
        "GET",
        `repos/${repo}/labels/${encodeURIComponent(name)}`
      );
      if (
        concurrent.name.toLowerCase() !== name.toLowerCase() ||
        concurrent.description !== labelDescription
      ) {
        throw new Error(`${name} was concurrently created for another purpose.`);
      }
    }
  }
}

function syncIssue(api, repo, number, apply, log = console.log) {
  // Read current state rather than a possibly superseded webhook payload.
  const issue = api("GET", `repos/${repo}/issues/${number}`);
  if (issue.pull_request) return;
  const changes = labelChanges(issue);
  log(
    `#${number}: ${apply ? "apply" : "dry run"}; add [${changes.add.join(", ")}]; remove [${changes.remove.join(", ")}]`
  );
  if (!apply) return;
  if (changes.add.length) {
    api("POST", `repos/${repo}/issues/${number}/labels`, {
      labels: changes.add,
    });
  }
  for (const name of changes.remove) {
    api(
      "DELETE",
      `repos/${repo}/issues/${number}/labels/${encodeURIComponent(name)}`
    );
  }
}

function main() {
  const { values } = parseArgs({
    options: {
      repo: { type: "string", default: process.env.GITHUB_REPOSITORY },
      issue: { type: "string" },
      apply: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });
  if (values.help) {
    console.log(
      "Usage: node scripts/sync-project-view-membership.cjs --repo OWNER/REPO [--issue NUMBER] [--apply]\n" +
        "Defaults to a read-only preview. Requires an authenticated gh CLI.\n" +
        "Without --issue, reconciles every open issue; never changes assignments or posts comments.\n" +
        "Named project views should filter label:View-LOGIN, with no assignee filter.\n" +
        "Edit project-view-owners.json when area responsibilities change."
    );
    return;
  }
  if (!values.repo || !/^[\w.-]+\/[\w.-]+$/.test(values.repo)) {
    throw new Error("--repo must be an OWNER/REPO name.");
  }
  if (
    values.issue !== undefined &&
    (!/^[1-9]\d*$/.test(values.issue) ||
      !Number.isSafeInteger(Number(values.issue)))
  ) {
    throw new Error("--issue must be a positive issue number.");
  }
  if (values.apply) {
    ensureViewLabels(ghApi, values.repo);
  }
  const numbers = values.issue
    ? [Number(values.issue)]
    : listAll(ghApi, `repos/${values.repo}/issues?state=open`)
        .filter((issue) => !issue.pull_request)
        .map((issue) => issue.number);
  for (const number of numbers) {
    syncIssue(ghApi, values.repo, number, values.apply);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`Project-view synchronization failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { desiredViewLabels, labelChanges, ensureViewLabels, syncIssue };
