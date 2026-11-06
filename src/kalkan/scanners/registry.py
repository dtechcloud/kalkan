# SPDX-License-Identifier: MIT
"""The adapters in run order (ENGINE-SPEC 13 and 13.1).

- :data:`SCANNERS`: the deterministic scanners of the ``deterministic`` phase, in the
  section 13 order. ``scan all`` runs them. The code and IaC scanners come first (Checkov, then
  Checkov on the rendered Helm charts), then the CI/CD workflow scanners (zizmor, actionlint,
  poutine), the repository posture (Scorecard), the file linters (ShellCheck, flawfinder, gixy,
  vacuum) and the built-in matcher.
- :data:`SCA_TOOLS`: the SCA tool adapters (``syft``, ``trivy-sbom``, ``osv-scanner``,
  ``grype``, ``govulncheck``). They only run the tools and write JSON into ``sca/``;
  :mod:`kalkan.sca` reads the outputs.
- :data:`SCA_PIN_TOOLS`: ``osv-scanner-pins`` and ``grype-pins``. ``sca match`` runs them on
  ``sca/manifest-pins.cdx.json``, the exact pins of manifests without a lockfile.
"""

from __future__ import annotations

from kalkan.errors import KalkanError
from kalkan.scanners.adapters.actionlint import ActionlintAdapter
from kalkan.scanners.adapters.bandit import BanditAdapter
from kalkan.scanners.adapters.checkov import CheckovAdapter
from kalkan.scanners.adapters.flawfinder import FlawfinderAdapter
from kalkan.scanners.adapters.gitleaks import GitleaksAdapter, GitleaksHistoryAdapter
from kalkan.scanners.adapters.gixy import GixyAdapter
from kalkan.scanners.adapters.gosec import GosecAdapter
from kalkan.scanners.adapters.govulncheck import GovulncheckAdapter
from kalkan.scanners.adapters.grype import GrypeAdapter, GrypePinsAdapter
from kalkan.scanners.adapters.hadolint import HadolintAdapter
from kalkan.scanners.adapters.helm_checkov import HelmCheckovAdapter
from kalkan.scanners.adapters.kingfisher import KingfisherAdapter, KingfisherHistoryAdapter
from kalkan.scanners.adapters.matcher import MatcherAdapter
from kalkan.scanners.adapters.opengrep import OpengrepAdapter
from kalkan.scanners.adapters.opengrep_packs import OpengrepPacksAdapter
from kalkan.scanners.adapters.osv_scanner import OsvScannerAdapter, OsvScannerPinsAdapter
from kalkan.scanners.adapters.poutine import PoutineAdapter
from kalkan.scanners.adapters.scorecard import ScorecardAdapter
from kalkan.scanners.adapters.shellcheck import ShellcheckAdapter
from kalkan.scanners.adapters.syft import SyftAdapter
from kalkan.scanners.adapters.trivy import TrivyAdapter
from kalkan.scanners.adapters.trivy_sbom import TrivySbomAdapter
from kalkan.scanners.adapters.vacuum import VacuumAdapter
from kalkan.scanners.adapters.zizmor import ZizmorAdapter
from kalkan.scanners.base import Adapter

__all__ = ["SCANNERS", "SCA_PIN_TOOLS", "SCA_TOOLS", "get", "names"]

SCANNERS: tuple[Adapter, ...] = (
    TrivyAdapter(),
    CheckovAdapter(),
    HelmCheckovAdapter(),
    HadolintAdapter(),
    GitleaksAdapter(),
    GitleaksHistoryAdapter(),
    KingfisherAdapter(),
    KingfisherHistoryAdapter(),
    OpengrepAdapter(),
    OpengrepPacksAdapter(),
    BanditAdapter(),
    GosecAdapter(),
    ZizmorAdapter(),
    ActionlintAdapter(),
    PoutineAdapter(),
    ScorecardAdapter(),
    ShellcheckAdapter(),
    FlawfinderAdapter(),
    GixyAdapter(),
    VacuumAdapter(),
    MatcherAdapter(),
)

SCA_TOOLS: tuple[Adapter, ...] = (
    SyftAdapter(),
    TrivySbomAdapter(),
    OsvScannerAdapter(),
    GrypeAdapter(),
    GovulncheckAdapter(),
)

SCA_PIN_TOOLS: tuple[Adapter, ...] = (
    OsvScannerPinsAdapter(),
    GrypePinsAdapter(),
)


def names() -> list[str]:
    """Return every engine name: the scanners, the SCA tools, then the SCA pin tools."""
    return [adapter.name for adapter in (*SCANNERS, *SCA_TOOLS, *SCA_PIN_TOOLS)]


def get(name: str) -> Adapter:
    """Return the adapter of an engine. Raises :class:`~kalkan.errors.KalkanError` for an
    unknown name."""
    for adapter in (*SCANNERS, *SCA_TOOLS, *SCA_PIN_TOOLS):
        if adapter.name == name:
            return adapter
    raise KalkanError(f"unknown engine {name!r} (known engines: {', '.join(names())})")
