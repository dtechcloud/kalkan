# SPDX-License-Identifier: MIT
"""One adapter module per engine (docs/ENGINE-SPEC.md, section 13).

Each module records the command line that was checked against ``--help`` of the pinned tool
version. :mod:`kalkan.scanners.registry` lists the adapters in run order.
"""
