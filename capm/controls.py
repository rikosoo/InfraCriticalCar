"""Control catalogue, standard mappings and control portfolios.

Each control is described by

*   ``m``  - the *mitigation* factor: the fraction of the conditional success
    probability of an applicable attack step that the control removes;
*   ``u``  - the *detection uplift*: the fraction of the remaining undetected
    probability mass that the control converts into detection-and-containment;
*   ``recovery`` - the fraction by which the control shortens the outage once
    an impact has occurred (consequence-side controls such as tested offline
    backups or a manual degraded-production mode);
*   ``cost`` - a relative annualised cost index (1 = cheapest, 10 = most
    expensive) used only for the cost-effectiveness ranking of Experiment E4.

``iec62443`` lists the relevant IEC 62443-3-3 system requirements (SR) and
``csf`` the NIST CSF 2.0 subcategories, so that every quantitative result can be
translated into the language the plant's compliance programme already speaks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple

from .model import Edge


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    m: float
    u: float
    cost: float
    iec62443: Tuple[str, ...]
    csf: Tuple[str, ...]
    recovery: float = 0.0
    description: str = ""


CONTROLS: Dict[str, Control] = {c.id: c for c in [
    Control("C01", "Phishing-resistant MFA for remote and privileged access",
            0.65, 0.10, 6, ("SR 1.1", "SR 1.2", "SR 1.5", "SR 1.7"),
            ("PR.AA-02", "PR.AA-03"),
            description="FIDO2/certificate-based authentication replacing OTP and push approval."),
    Control("C02", "Conditional access and device-compliance enforcement",
            0.40, 0.15, 4, ("SR 1.13", "SR 2.6"), ("PR.AA-05",),
            description="Managed-device, location and risk conditions on every remote session."),
    Control("C03", "Administrative tiering and privileged access workstations",
            0.55, 0.20, 7, ("SR 1.1", "SR 2.1", "SR 1.11"), ("PR.AA-05", "PR.PS-01"),
            description="Tier-0 isolation, no domain-admin logon to user or plant hosts."),
    Control("C04", "Brokered, just-in-time vendor remote access",
            0.60, 0.30, 5, ("SR 1.13", "SR 2.6", "SR 6.1"), ("PR.AA-05", "GV.SC-07"),
            description="No direct vendor tunnels; time-boxed sessions through an IDMZ broker "
                        "with recording, aligned with IEC 62443-2-4."),
    Control("C05", "Enforced IT/OT segmentation with an industrial DMZ",
            0.60, 0.25, 8, ("SR 5.1", "SR 5.2", "SR 5.3"), ("PR.IR-01",),
            description="Zone-and-conduit enforcement; no transit conduit from Level 4 to Level 3."),
    Control("C06", "Application allowlisting and removable-media control on OT hosts",
            0.55, 0.15, 5, ("SR 2.3", "SR 3.2"), ("PR.PS-05",),
            description="Engineering workstations and HMIs run only signed, inventoried software."),
    Control("C07", "Endpoint detection and 24/7 monitored response",
            0.25, 0.45, 7, ("SR 6.2", "SR 3.2"), ("DE.CM-01", "DE.CM-09", "RS.MA-01"),
            description="Behavioural detection with an on-call containment capability."),
    Control("C08", "Immutable, offline and exercised backups (IT and OT)",
            0.05, 0.05, 5, ("SR 7.3", "SR 7.4"), ("PR.DS-11", "RC.RP-01"),
            recovery=0.45,
            description="Includes controller projects, MES databases and golden images; "
                        "restoration is rehearsed, which is what shortens the outage."),
    Control("C09", "Controller change control and program integrity monitoring",
            0.50, 0.35, 6, ("SR 3.4", "SR 3.8", "SR 7.6"), ("PR.PS-01", "DE.CM-09"),
            description="Physical key-switch in RUN, signed projects, alarm on program download."),
    Control("C10", "Attack-surface management and expedited patching of exposed services",
            0.45, 0.10, 5, ("SR 7.2", "SR 3.10"), ("ID.RA-01", "PR.PS-02"),
            description="Continuous external inventory and emergency patch path for edge software."),
    Control("C11", "SaaS and OAuth token governance",
            0.45, 0.25, 4, ("SR 1.9", "SR 2.1"), ("PR.AA-05", "GV.SC-06"),
            description="Vetting of connected applications, token lifetime limits, egress analytics."),
    Control("C12", "Identity lifecycle hygiene and dormant credential revocation",
            0.70, 0.10, 3, ("SR 1.3", "SR 1.5"), ("PR.AA-01", "GV.SC-07"),
            description="Automatic disablement of third-party, contractor and legacy accounts."),
    Control("C13", "Continuous OT network monitoring and asset inventory",
            0.05, 0.50, 6, ("SR 6.2", "SR 7.8"), ("ID.AM-01", "DE.CM-01"),
            description="Passive protocol-aware detection; no new attack surface in the cell."),
    Control("C14", "Supplier security assurance and contractual telemetry",
            0.35, 0.20, 6, ("SR 1.13", "SR 6.1"), ("GV.SC-01", "GV.SC-04", "GV.SC-08"),
            description="IEC 62443-2-4 / TISAX evidence, incident-notification SLAs, "
                        "second-source qualification for critical parts."),
    Control("C15", "Service-desk identity proofing and insider-risk programme",
            0.55, 0.25, 3, ("SR 1.1", "SR 2.10"), ("PR.AA-01", "GV.RR-02"),
            description="Out-of-band verification for credential and MFA resets; "
                        "behavioural insider-risk review."),
    Control("C16", "Cloud security and data-exposure posture management",
            0.55, 0.30, 4, ("SR 4.1", "SR 4.3"), ("PR.DS-01", "PR.DS-10", "ID.RA-01"),
            description="CSPM/DSPM with automatic remediation of public data stores."),
    Control("C17", "Operational resilience: buffers, manual fallback and degraded mode",
            0.10, 0.00, 7, ("SR 7.1", "SR 7.4"), ("RC.RP-01", "RC.RP-05", "GV.SC-08"),
            recovery=0.55,
            description="Decoupling buffers for critical parts, paper-kanban fallback and "
                        "rehearsed degraded-mode production."),
]}


@dataclass
class Portfolio:
    """A set of deployed controls; callable as an edge -> (m, u) lookup."""

    active: Tuple[str, ...] = ()
    name: str = "portfolio"
    _cache: Dict[Tuple[str, str, str], Tuple[float, float]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        unknown = [c for c in self.active if c not in CONTROLS]
        if unknown:
            raise KeyError(f"unknown controls: {unknown}")
        self.active = tuple(sorted(set(self.active)))

    def __call__(self, edge: Edge) -> Tuple[float, float]:
        key = edge.key
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        applicable = [CONTROLS[c] for c in edge.controls if c in self.active]
        m_res, u_res = 1.0, 1.0
        for ctrl in applicable:
            m_res *= (1.0 - ctrl.m)
            u_res *= (1.0 - ctrl.u)
        out = (1.0 - m_res, 1.0 - u_res)
        self._cache[key] = out
        return out

    # -- consequence side -------------------------------------------------
    def recovery_factor(self) -> float:
        """Multiplier applied to outage duration by the deployed controls."""
        f = 1.0
        for cid in self.active:
            f *= (1.0 - CONTROLS[cid].recovery)
        return f

    def cost(self) -> float:
        return sum(CONTROLS[c].cost for c in self.active)

    def with_control(self, cid: str) -> "Portfolio":
        return Portfolio(tuple(set(self.active) | {cid}), name=f"{self.name}+{cid}")

    def without_control(self, cid: str) -> "Portfolio":
        return Portfolio(tuple(c for c in self.active if c != cid), name=f"{self.name}-{cid}")


BASELINE = Portfolio((), name="S0 baseline")

#: Named scenarios evaluated in the paper.
SCENARIOS: Dict[str, Portfolio] = {
    "S0": BASELINE,
    "S1": Portfolio(("C01", "C02", "C03", "C12", "C15"), name="S1 identity-first"),
    "S2": Portfolio(("C05", "C06", "C09", "C13"), name="S2 IEC 62443 zones and conduits"),
    "S3": Portfolio(("C04", "C11", "C14", "C16"), name="S3 supply chain and cloud"),
    "S4": Portfolio(("C07", "C08", "C10", "C17"), name="S4 detect and recover"),
    "S5": Portfolio(tuple(sorted(CONTROLS)), name="S5 full programme"),
}


def controls_for(edges: Iterable[Edge]) -> List[str]:
    out: List[str] = []
    for e in edges:
        for c in e.controls:
            if c not in out:
                out.append(c)
    return sorted(out)


def coverage_table() -> List[Sequence[str]]:
    """Rows of (control, name, cost, IEC 62443-3-3 SR, NIST CSF 2.0)."""
    rows: List[Sequence[str]] = []
    for cid in sorted(CONTROLS):
        c = CONTROLS[cid]
        rows.append((c.id, c.name, f"{c.cost:.0f}", "; ".join(c.iec62443), "; ".join(c.csf)))
    return rows
