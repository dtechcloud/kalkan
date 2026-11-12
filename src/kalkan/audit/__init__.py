# SPDX-License-Identifier: MIT
"""One-command audit: ``kalkan audit`` (docs/ENGINE-SPEC.md, section 25).

- :mod:`kalkan.audit.preflight`: the setup checks (a part of ``kalkan doctor``) and the setup
  decisions (consent, fix commands, exit codes).
- :mod:`kalkan.audit.drive`: the engine steps in this process (``run next`` and ``run step``)
  and the progress of the agent rounds.
- :mod:`kalkan.audit.summary`: the deliverables and the end summary.
- :mod:`kalkan.audit.commands`: the CLI command.
"""
