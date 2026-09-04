# Issue tracker: personal profile (local markdown)

Issues and specs for this repo live as markdown files in `.scratch/`. The agent is the only reader, so fields are minimal.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`
- The spec is `.scratch/<feature-slug>/spec.md`
- Implementation Issues are one file per Issue at `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`, never a single combined file
- State is recorded as a `Status:` line near the top of each Issue file (`ready-for-agent` when it can be picked up, `done` when closed)
- Blocking is a `Blocked by:` line near the top naming other Issues by number; an Issue is unblocked when every one it lists is `done`
- Comments and conversation history append to the bottom of the file under a `## Comments` heading

## When a skill says "publish to the issue tracker"

Create a new file under `.scratch/<feature-slug>/` (creating the directory if needed).

## When a skill says "fetch the relevant Issue"

Read the file at the referenced path. The user will normally pass the path or the Issue number directly.
