# Combined area and assigned-work views

> **Audience:** MXC maintainers

Each named project view includes all issues in that person's areas, plus
anything assigned to them, including assignments outside their areas.
Area work remains visible even when somebody else is assigned. Shared areas
can therefore appear in more than one view; view membership is not an
implementation assignment.

GitHub Projects cannot combine an area-label filter and an assignee filter
with logical OR. `Project.View.Membership.yml` maintains derived
`View-<login>` issue labels so each named view can use a single label filter.
Keep Labels hidden in the tables and retain manual ordering and native Type.
`My items` continues to use `assignee:@me`.

The workflow reacts to issue and assignment changes and reconciles every open
issue hourly. It also supports manual dispatch. It uses the repository
`GITHUB_TOKEN` with `issues: write`, not an organization-project token.
Pull request runs only test the implementation and cannot write issue labels.
The synchronizer never changes assignees, milestones, issue bodies, or comments.
It only adds and removes its configured derived labels.

## Ownership rules

`scripts/project-view-owners.json` defines each person's positive area labels
and subarea exclusions. Assignment always includes that person, regardless of
the area exclusions. Change these rules when area responsibility changes.
Do not manually edit the derived labels; change the underlying area labels,
assignees, or ownership rules instead.

## Activation

1. Merge the reviewed workflow and scripts before changing project filters.
2. Dispatch **Project View Membership** and confirm the reconciliation succeeds.
3. Change each named view's filter to
   `label:View-LOGIN is:issue is:open status:Todo,"In progress"`.
   Replace `LOGIN` with the matching key from the ownership configuration.
   Remove the old area-label and `no:assignee` filters.
4. Confirm assigned work such as #1261 is visible under Branden, along with
   his area work. Preserve each view's name, Type column, and manual ordering.

Do not activate the filters before the automation is deployed. If reverting
the automation, restore the previous view filters before disabling it.

## Local checks and reconciliation

Run from the repository root with Node.js 24 and an authenticated GitHub CLI:

```powershell
node --test scripts\tests\project-view-membership.test.cjs
node scripts\sync-project-view-membership.cjs --repo microsoft/mxc --issue 1261
node scripts\sync-project-view-membership.cjs --repo microsoft/mxc
```

These commands are read-only unless `--apply` is passed to the synchronizer.
For a manual reconciliation, append `--apply`; the workflow passes it
automatically. Errors fail the command and workflow rather than reporting
successful synchronization.
