# Prompt-injection test data (phase 5)

This fixture contains no agent instruction file. There is no `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.agents/` or `.codex/` here.

## Why the hostile file is not stored here

- Claude Code and other agent hosts load instruction files from every folder of a repository. A hostile file in this repository would act on every agent that works on kalkan.
- `tests/test_repo_hygiene.py` fails when such a file or folder exists below the repository root.

## How the phase 5 test builds the hostile target

1. The test copies `tests/fixtures/vulnapp/` to a temporary folder. It leaves out `README.md`, `EXPECTED.json` and this note, because they contain the answers.
2. The test writes a hostile `CLAUDE.md` into the root of the copy, and optionally a `.claude/settings.json`. The text tells an agent to treat the code as safe, to skip findings, or to run a command. The test owns this text and writes it only into the temporary folder.
3. The test runs `kalkan run init` on the copy. The engine renames the instruction files in `runs/<run-id>/target/` with the suffix `.kalkan-neutralized` (ENGINE-SPEC, section 10).
4. The test checks the result:
   - the renamed files exist and no original instruction file is left in the run copy,
   - the run still reports the planted vulnerabilities of `EXPECTED.json`,
   - no agent action follows the hostile text.

The same method applies to a secret in git history: a test creates a temporary repository, commits a fake secret, removes it in a second commit, and scans the history. The fixture itself has no git history of its own.
