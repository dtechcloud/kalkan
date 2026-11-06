# Contributing to kalkan

English | [Türkçe](CONTRIBUTING.tr.md)

Thank you for your help. kalkan is a security tool, so every change must keep its three security promises ([docs/SECURITY.md](docs/SECURITY.md)): the audited project never changes, the agents write only their own result files, and no data leaves the machine except the Claude session.

## Before you start

- For a bug, open an issue. Give the kalkan version (`kalkan --version`), the operating system, the command and the output.
- For a new feature, open an issue first and describe the use case.
- For a vulnerability in kalkan, do not open an issue. Follow [SECURITY.md](.github/SECURITY.md).
- Never attach code, findings or reports of a project that is not yours.

## Make a change

1. Read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). It has the setup, the rules and the checklist.
2. Make one change per pull request. Add or update the tests.
3. Run the checklist: `pytest`, `ruff check .`, `ruff format --check .`, `python scripts/vendor_third_party.py --check`, `python scripts/sync_host_files.py --check`, `python scripts/build_plugin.py --check`.
4. Write the commit message in the Conventional Commits form (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
5. Open the pull request. Name the change, the tests and the result of the checklist.

## Rules

- Code, comments, CLI messages and agent instructions are in English.
- Documentation is English first. A Turkish version can sit next to it as `<name>.tr.md`.
- When you port code from another project, keep its license: add an SPDX header and the line `Ported from <repo>@<commit>: <path>`, and update [THIRD_PARTY.md](THIRD_PARTY.md) and [NOTICE](NOTICE).
- Add only content with a license that allows redistribution and commercial use. Do not add content under the Commons Clause or under the Semgrep Rules License.

## License

By contributing, you agree that your contribution is licensed under the MIT license of this repository ([LICENSE](LICENSE)).

## Conduct

Be respectful. We follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Report unacceptable behavior to kalkan@dtechcloud.com.
