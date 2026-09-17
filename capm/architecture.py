"""Reference architecture of an automotive OEM plant and its attack graph.

The architecture follows the IEC 62443-3-2 zone-and-conduit decomposition of a
vehicle assembly plant, mapped onto the Purdue model and extended with the two
planes that classical Purdue drawings omit: the *identity* plane (on-premises
Active Directory plus a cloud identity provider) and the *cloud/SaaS* plane
(IaaS tenant, CI/CD, connected-vehicle back end, third-party SaaS). A fifth
plane models the *supply chain* (Tier-1 suppliers, EDI/JIT interfaces, machine
builders and integrators with remote access, and OT software update channels).

Edge parameters (p, delta, effort) are expert-elicited point estimates,
anchored on the incident corpus in ``data/incidents.csv``; Experiment E5
quantifies how sensitive the conclusions are to them.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .model import Asset, AttackGraph, Consequence, Edge, Zone
from .techniques import catalogue

# --------------------------------------------------------------------------
# Zones (IEC 62443-3-2)
# --------------------------------------------------------------------------
ZONES: List[Zone] = [
    Zone("Z-EXT", "Untrusted external network", 5, "it", 0),
    Zone("Z-SUP", "Supplier and integrator networks", 5, "supply_chain", 1),
    Zone("Z-SAAS", "Third-party SaaS", 4, "cloud", 1),
    Zone("Z-IT", "Corporate IT", 4, "it", 2),
    Zone("Z-IDP", "Identity plane", 4, "identity", 3),
    Zone("Z-CLD", "OEM cloud tenant", 4, "cloud", 2),
    Zone("Z-IDMZ", "Industrial DMZ", 35, "ot", 3),
    Zone("Z-OPS", "Site operations", 3, "ot", 3),
    Zone("Z-SCADA", "Area supervisory control", 2, "ot", 3),
    Zone("Z-CTRL", "Basic control", 1, "ot", 3),
    Zone("Z-PROC", "Physical process", 0, "ot", 4),
    Zone("Z-CONS", "Business consequences (modelling artefact)", 0, "it", 0),
]

# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------
ASSETS: List[Asset] = [
    # External -----------------------------------------------------------
    Asset("ext_actor", "External threat actor", "Z-EXT", "actor",
          "Financially motivated intrusion set with hands-on-keyboard capability"),
    # Supply chain -------------------------------------------------------
    Asset("sup_tier1", "Tier-1 supplier IT estate", "Z-SUP", "host",
          "Component supplier operating on just-in-time delivery"),
    Asset("sup_edi", "EDI / JIT ordering and logistics interface", "Z-SUP", "service",
          "Order, kanban and delivery messaging between supplier and OEM"),
    Asset("sup_vendor_ra", "Machine builder remote access", "Z-SUP", "service",
          "Integrator/OEM-of-equipment maintenance access to line assets"),
    Asset("sup_sw_update", "OT software and firmware update channel", "Z-SUP", "service",
          "Engineering software, PLC firmware and project files from vendors"),
    Asset("sup_usb", "Removable media and project files", "Z-SUP", "device",
          "USB media and project archives carried by field engineers"),
    # SaaS ---------------------------------------------------------------
    Asset("saas_crm", "Third-party CRM / customer platform", "Z-SAAS", "service",
          "SaaS CRM reached through OAuth-integrated applications"),
    Asset("saas_dms", "Dealer management platform", "Z-SAAS", "service",
          "Shared SaaS platform serving the retail network"),
    # Corporate IT -------------------------------------------------------
    Asset("it_email", "Corporate mail service", "Z-IT", "service", ""),
    Asset("it_user_ws", "Employee workstation", "Z-IT", "host", ""),
    Asset("it_helpdesk", "IT service desk process", "Z-IT", "service",
          "Human process able to reset credentials and MFA factors"),
    Asset("it_insider", "Recruited or coerced insider", "Z-IT", "identity",
          "Employee or contractor with legitimate plant access"),
    Asset("it_vpn", "Remote access VPN gateway", "Z-IT", "service", ""),
    Asset("it_edge_app", "Internet-facing enterprise application", "Z-IT", "service",
          "ERP/portal middleware exposed to the Internet"),
    Asset("it_erp", "ERP and production planning core", "Z-IT", "service",
          "Order-to-delivery, logistics and plant scheduling"),
    Asset("it_fileshare", "Engineering and business file shares", "Z-IT", "data", ""),
    Asset("it_sccm", "Endpoint management / software deployment", "Z-IT", "service", ""),
    Asset("it_backup", "Backup infrastructure", "Z-IT", "service", ""),
    # Identity -----------------------------------------------------------
    Asset("id_user_cred", "Standard user credentials", "Z-IDP", "identity", ""),
    Asset("id_legacy_cred", "Dormant third-party / legacy credentials", "Z-IDP", "identity",
          "Accounts of former contractors and legacy integrations never revoked"),
    Asset("id_ad", "On-premises Active Directory (tier 0)", "Z-IDP", "service", ""),
    Asset("id_entra", "Cloud identity provider", "Z-IDP", "service", ""),
    Asset("id_federation", "Federation / SSO trust", "Z-IDP", "service", ""),
    Asset("id_pam", "Privileged access management and domain administration", "Z-IDP", "service", ""),
    # Cloud --------------------------------------------------------------
    Asset("cld_tenant", "Cloud tenant control plane", "Z-CLD", "service", ""),
    Asset("cld_storage", "Object storage and data lake", "Z-CLD", "data", ""),
    Asset("cld_cicd", "CI/CD pipeline and artefact registry", "Z-CLD", "service", ""),
    Asset("cld_cv_backend", "Connected-vehicle / telematics back end", "Z-CLD", "service", ""),
    # Industrial DMZ -----------------------------------------------------
    Asset("dmz_jump", "OT jump server", "Z-IDMZ", "host", ""),
    Asset("dmz_broker", "Vendor remote-access broker", "Z-IDMZ", "service", ""),
    Asset("dmz_relay", "Patch, antivirus and update relay", "Z-IDMZ", "service", ""),
    Asset("dmz_mirror", "Historian mirror / data broker", "Z-IDMZ", "data", ""),
    # Site operations ----------------------------------------------------
    Asset("ops_mes", "Manufacturing execution system", "Z-OPS", "service", ""),
    Asset("ops_historian", "Process historian", "Z-OPS", "service", ""),
    Asset("ops_ews", "Engineering workstation", "Z-OPS", "host",
          "Holds controller projects and programming software"),
    Asset("ops_ot_ad", "OT domain controller", "Z-OPS", "service", ""),
    # Supervisory --------------------------------------------------------
    Asset("sca_server", "SCADA / line control server", "Z-SCADA", "service", ""),
    Asset("sca_hmi", "Operator HMI panel", "Z-SCADA", "host", ""),
    # Control ------------------------------------------------------------
    Asset("ctl_plc_body", "Body shop / weld line PLC", "Z-CTRL", "device", ""),
    Asset("ctl_robot", "Robot cell controller", "Z-CTRL", "device", ""),
    Asset("ctl_safety", "Safety PLC / safety instrumented function", "Z-CTRL", "device", ""),
    # Process ------------------------------------------------------------
    Asset("prc_line", "Assembly and weld line", "Z-PROC", "device", ""),
    Asset("prc_paint", "Paint shop", "Z-PROC", "device", ""),
    # Consequences -------------------------------------------------------
    Asset("imp_prod_stop", "Production stoppage", "Z-CONS", "impact", ""),
    Asset("imp_quality", "Silent quality degradation / recall", "Z-CONS", "impact", ""),
    Asset("imp_safety", "Loss of safety function", "Z-CONS", "impact", ""),
    Asset("imp_ip", "Theft of engineering and design data", "Z-CONS", "impact", ""),
    Asset("imp_pii", "Customer personal data breach", "Z-CONS", "impact", ""),
]

# --------------------------------------------------------------------------
# Edges: (src, dst, technique, p, delta, effort_h, controls, rationale, evidence)
# --------------------------------------------------------------------------
E = Tuple[str, str, str, float, float, float, Tuple[str, ...], str, Tuple[str, ...]]

EDGES: List[E] = [
    # --- Initial access -------------------------------------------------
    ("ext_actor", "it_email", "T1566.001", 0.85, 0.30, 4, ("C07",),
     "Mail delivery of a lure to a corporate mailbox", ("INC-07",)),
    ("it_email", "it_user_ws", "T1204.002", 0.35, 0.45, 2, ("C06", "C07"),
     "User opens the attachment and the loader executes", ("INC-07",)),
    ("ext_actor", "it_user_ws", "T1189", 0.22, 0.40, 8, ("C06", "C07"),
     "Drive-by download from an employee browsing session", ("INC-07",)),
    ("ext_actor", "it_edge_app", "T1190", 0.45, 0.35, 24, ("C10", "C07"),
     "Exploitation of an Internet-facing enterprise application", ("INC-18",)),
    ("ext_actor", "it_vpn", "T1133", 0.38, 0.30, 12, ("C01", "C02"),
     "Authentication to remote access with harvested credentials", ("INC-13",)),
    ("ext_actor", "id_legacy_cred", "T1078", 0.30, 0.20, 6, ("C12",),
     "Reuse of dormant contractor or legacy integration accounts", ("INC-18", "INC-19")),
    ("ext_actor", "it_helpdesk", "T1656", 0.35, 0.40, 6, ("C01", "C15"),
     "Voice social engineering of the service desk", ("INC-18",)),
    ("ext_actor", "saas_crm", "T1078.004", 0.30, 0.30, 10, ("C11",),
     "Abuse of OAuth tokens held by an integrated SaaS application", ("INC-17",)),
    ("ext_actor", "cld_storage", "T1530", 0.18, 0.55, 16, ("C16",),
     "Discovery of misconfigured object storage", ("INC-09", "INC-10")),
    ("ext_actor", "saas_dms", "T1190", 0.25, 0.40, 20, ("C11", "C10"),
     "Exploitation of a shared retail SaaS platform", ("INC-11",)),
    ("ext_actor", "sup_tier1", "T1566", 0.55, 0.55, 8, ("C14",),
     "Phishing of a supplier with weaker controls", ("INC-04", "INC-14", "INC-16")),
    ("ext_actor", "sup_vendor_ra", "T1133", 0.30, 0.45, 12, ("C04", "C14"),
     "Compromise of an integrator maintenance account", ("INC-04",)),
    ("ext_actor", "sup_sw_update", "T1195.002", 0.08, 0.50, 120, ("C09", "C14"),
     "Trojanised engineering software or firmware package", ()),
    ("ext_actor", "sup_usb", "T1091", 0.12, 0.50, 40, ("C06", "C14"),
     "Infected removable media carried by field service", ()),
    ("ext_actor", "it_insider", "T1078", 0.06, 0.35, 40, ("C15", "C13"),
     "Recruitment or coercion of a person with plant access", ("INC-08",)),
    # --- Identity consolidation -----------------------------------------
    ("it_user_ws", "id_user_cred", "T1003.001", 0.60, 0.45, 4, ("C07", "C03"),
     "Credential material harvested from the compromised endpoint", ("INC-07",)),
    ("it_user_ws", "id_entra", "T1621", 0.32, 0.40, 6, ("C01",),
     "Push-notification fatigue against the cloud identity provider", ()),
    ("it_helpdesk", "id_user_cred", "T1098", 0.70, 0.35, 2, ("C01", "C15"),
     "Credential and MFA factor reset performed by the service desk", ("INC-18",)),
    ("id_user_cred", "id_ad", "T1078", 0.55, 0.35, 8, ("C03", "C07"),
     "Authenticated foothold in the on-premises directory", ()),
    ("id_legacy_cred", "it_vpn", "T1133", 0.60, 0.25, 2, ("C01", "C12"),
     "Legacy account still authorised for remote access", ("INC-18",)),
    ("id_legacy_cred", "id_ad", "T1078", 0.45, 0.30, 6, ("C12", "C03"),
     "Legacy account still present in the directory", ("INC-18",)),
    ("it_vpn", "it_user_ws", "T1021.001", 0.60, 0.30, 4, ("C02", "C07"),
     "Interactive session to an internal workstation", ("INC-13",)),
    ("it_vpn", "it_erp", "T1210", 0.40, 0.35, 12, ("C10", "C07"),
     "Exploitation of an internal application from the VPN segment", ()),
    ("it_edge_app", "it_erp", "T1210", 0.55, 0.35, 8, ("C10",),
     "Pivot from the exposed middleware to the ERP core", ("INC-18",)),
    ("it_edge_app", "id_ad", "T1552.001", 0.40, 0.30, 10, ("C03", "C12"),
     "Service-account secrets recovered from application configuration", ()),
    ("id_ad", "id_pam", "T1003.006", 0.60, 0.45, 6, ("C03", "C07"),
     "Directory replication abuse yielding tier-0 material", ()),
    ("id_ad", "ops_ot_ad", "T1078", 0.50, 0.35, 12, ("C05", "C03"),
     "Abuse of the trust between corporate and OT directories", ("INC-01", "INC-03")),
    ("id_entra", "id_federation", "T1606.002", 0.35, 0.45, 12, ("C01", "C03"),
     "Forging of federated authentication material", ()),
    ("id_federation", "cld_tenant", "T1550.001", 0.60, 0.40, 6, ("C11",),
     "Use of federated tokens against the cloud control plane", ()),
    ("id_entra", "cld_tenant", "T1078.004", 0.65, 0.40, 4, ("C01", "C02"),
     "Administrative access to the cloud tenant", ()),
    ("id_pam", "it_sccm", "T1072", 0.70, 0.40, 6, ("C03", "C07"),
     "Take-over of the endpoint management platform", ("INC-01", "INC-06")),
    ("id_pam", "it_backup", "T1490", 0.65, 0.45, 6, ("C08", "C03"),
     "Destruction or encryption of backup repositories", ("INC-18",)),
    ("id_pam", "dmz_jump", "T1021.001", 0.55, 0.40, 8, ("C05", "C03"),
     "Administrative logon to the industrial jump server", ()),
    ("it_sccm", "dmz_relay", "T1072", 0.40, 0.45, 10, ("C05", "C09"),
     "Deployment tooling reaching the industrial update relay", ("INC-03",)),
    ("it_sccm", "ops_ews", "T1072", 0.35, 0.45, 10, ("C05", "C06"),
     "Shared management agent present on plant engineering hosts", ("INC-03",)),
    # --- Cloud and SaaS --------------------------------------------------
    ("cld_tenant", "cld_storage", "T1530", 0.75, 0.45, 4, ("C16",), "", ("INC-10",)),
    ("cld_tenant", "cld_cicd", "T1078.004", 0.60, 0.45, 8, ("C11", "C03"), "", ()),
    ("cld_cicd", "cld_cv_backend", "T1195.002", 0.45, 0.50, 24, ("C11",),
     "Malicious artefact promoted through the pipeline", ()),
    ("cld_cicd", "ops_mes", "T1072", 0.28, 0.50, 24, ("C05", "C09"),
     "Cloud-driven deployment of plant-side applications", ()),
    ("cld_tenant", "imp_ip", "T1213", 0.60, 0.50, 12, ("C16",), "", ("INC-05",)),
    ("cld_storage", "imp_pii", "T1530", 0.90, 0.60, 2, ("C16",), "", ("INC-09", "INC-10")),
    ("cld_cv_backend", "imp_pii", "T1530", 0.70, 0.50, 8, ("C16", "C11"), "", ("INC-09",)),
    ("saas_crm", "imp_pii", "T1567.002", 0.80, 0.50, 6, ("C11",), "", ("INC-17",)),
    ("saas_dms", "imp_pii", "T1567.002", 0.70, 0.50, 8, ("C11",), "", ("INC-11",)),
    ("saas_dms", "imp_prod_stop", "T1489", 0.35, 0.40, 8, ("C11", "C14"),
     "Retail/logistics platform outage propagating upstream", ("INC-11",)),
    # --- Collection in IT -------------------------------------------------
    ("it_erp", "it_fileshare", "T1039", 0.70, 0.40, 4, ("C07",), "", ()),
    ("it_user_ws", "it_fileshare", "T1039", 0.55, 0.40, 4, ("C07",), "",
     ("INC-07", "INC-12", "INC-13")),
    ("it_fileshare", "imp_ip", "T1567.002", 0.80, 0.50, 8, ("C07", "C16"), "", ("INC-05", "INC-07")),
    # --- Supply chain into the OEM ---------------------------------------
    ("sup_tier1", "sup_edi", "T1078", 0.75, 0.40, 4, ("C14",), "",
     ("INC-04", "INC-14", "INC-16", "INC-20")),
    ("sup_tier1", "imp_ip", "T1567.002", 0.55, 0.55, 12, ("C14",), "", ("INC-05", "INC-15")),
    ("sup_edi", "imp_prod_stop", "T1489", 0.70, 0.40, 6, ("C14", "C17"),
     "Just-in-time starvation halts the line without any OT compromise",
     ("INC-04", "INC-14", "INC-16", "INC-20")),
    ("sup_edi", "ops_mes", "T1199", 0.35, 0.45, 12, ("C05", "C14"),
     "Trusted supplier interface terminating inside site operations", ("INC-04",)),
    ("sup_vendor_ra", "dmz_broker", "T1133", 0.60, 0.40, 6, ("C04",), "", ()),
    ("sup_vendor_ra", "ops_ews", "T0822", 0.30, 0.60, 12, ("C04", "C13"),
     "Unmanaged cellular or modem access bypassing the IDMZ", ()),
    ("sup_sw_update", "ops_ews", "T0873", 0.50, 0.55, 24, ("C09", "C06"), "", ()),
    ("sup_usb", "ops_ews", "T0847", 0.50, 0.55, 8, ("C06", "C09"), "", ()),
    ("it_insider", "ops_ews", "T1078", 0.60, 0.50, 8, ("C13", "C06"), "", ("INC-08",)),
    ("it_insider", "it_sccm", "T1072", 0.25, 0.45, 16, ("C03", "C13"), "", ("INC-08",)),
    ("ext_actor", "cld_tenant", "T1552.001", 0.15, 0.45, 24, ("C11", "C16"),
     "Cloud secrets exposed in a public code repository", ("INC-19",)),
    # --- Crossing the industrial DMZ --------------------------------------
    ("it_user_ws", "ops_ews", "T1210", 0.30, 0.45, 8, ("C05", "C10", "C13"),
     "Flat-network exploitation of an unpatched plant host, as in the 2017 "
     "worm-driven outages", ("INC-01", "INC-02", "INC-03")),
    ("ops_ews", "ops_mes", "T1210", 0.45, 0.45, 8, ("C05", "C13", "C10"),
     "Propagation from engineering hosts into the MES estate", ("INC-01", "INC-03")),
    ("it_user_ws", "dmz_jump", "T1021.001", 0.35, 0.45, 8, ("C05", "C01"), "", ()),
    ("it_erp", "dmz_mirror", "T1210", 0.45, 0.40, 8, ("C05",), "", ()),
    ("dmz_jump", "ops_ews", "T1021.001", 0.70, 0.40, 4, ("C05", "C03"), "", ()),
    ("dmz_broker", "ops_ews", "T0822", 0.65, 0.45, 6, ("C04", "C13"), "", ()),
    ("dmz_relay", "ops_historian", "T1072", 0.50, 0.45, 10, ("C09", "C13"), "", ()),
    ("dmz_mirror", "ops_historian", "T0885", 0.50, 0.45, 8, ("C05", "C13"), "", ()),
    ("ops_ot_ad", "ops_ews", "T1078", 0.75, 0.40, 4, ("C03", "C13"), "", ()),
    ("ops_ot_ad", "sca_server", "T1078", 0.70, 0.40, 6, ("C03", "C13"), "", ()),
    ("ops_historian", "ops_mes", "T1210", 0.45, 0.45, 10, ("C13", "C10"), "", ()),
    ("ops_mes", "sca_server", "T0886", 0.55, 0.45, 8, ("C05", "C13"), "", ()),
    ("ops_mes", "imp_prod_stop", "T1486", 0.75, 0.35, 6, ("C08", "C07"),
     "Encryption of the MES halts sequencing even with healthy controllers",
     ("INC-01", "INC-03", "INC-18")),
    ("it_erp", "imp_prod_stop", "T1486", 0.60, 0.35, 8, ("C08", "C07"),
     "Loss of planning, parts call-off and logistics stops the plant",
     ("INC-18", "INC-04")),
    ("it_sccm", "imp_prod_stop", "T1486", 0.70, 0.40, 8, ("C08", "C07", "C05"),
     "Enterprise-wide ransomware deployment reaching plant-side Windows hosts",
     ("INC-01", "INC-06", "INC-03")),
    ("it_backup", "imp_prod_stop", "T1490", 0.50, 0.40, 6, ("C08",),
     "Recovery inhibition converting an outage into a multi-week stoppage",
     ("INC-18",)),
    ("ops_ews", "imp_ip", "T1213", 0.60, 0.50, 8, ("C13", "C06"),
     "Theft of controller projects, recipes and line design data", ("INC-05",)),
    # --- Descent to control and process ------------------------------------
    ("ops_ews", "ctl_plc_body", "T0843", 0.70, 0.45, 6, ("C09", "C13"), "", ()),
    ("ops_ews", "ctl_robot", "T0843", 0.60, 0.45, 8, ("C09", "C13"), "", ()),
    ("ops_ews", "ctl_safety", "T0889", 0.32, 0.50, 16, ("C09", "C13"), "", ()),
    ("ops_ews", "sca_server", "T0886", 0.60, 0.40, 6, ("C13", "C05"), "", ()),
    ("sca_server", "sca_hmi", "T0886", 0.75, 0.40, 4, ("C13",), "", ()),
    ("sca_server", "ctl_plc_body", "T0855", 0.70, 0.45, 4, ("C09", "C13"), "", ()),
    ("sca_hmi", "ctl_robot", "T0855", 0.60, 0.45, 6, ("C09", "C13"), "", ()),
    ("sca_server", "imp_prod_stop", "T0813", 0.60, 0.40, 4, ("C13", "C08"),
     "Denial of control at the supervisory layer", ("INC-03",)),
    ("ctl_plc_body", "prc_line", "T0831", 0.85, 0.50, 2, ("C09",), "", ()),
    ("ctl_robot", "prc_line", "T0831", 0.80, 0.50, 2, ("C09",), "", ()),
    ("ctl_robot", "prc_paint", "T0836", 0.60, 0.55, 6, ("C09", "C13"), "", ()),
    ("ctl_safety", "imp_safety", "T0880", 0.45, 0.50, 4, ("C09",), "", ()),
    ("ctl_safety", "imp_prod_stop", "T0816", 0.60, 0.40, 4, ("C09",),
     "Safety trip or controller shutdown stopping the line", ()),
    ("prc_line", "imp_prod_stop", "T0828", 0.90, 0.30, 2, (), "", ("INC-01", "INC-04", "INC-18")),
    ("prc_paint", "imp_quality", "T0836", 0.55, 0.55, 6, ("C09", "C13"),
     "Undetected parameter drift producing defective vehicles", ()),
]

# --------------------------------------------------------------------------
# Consequences
# --------------------------------------------------------------------------
CONSEQUENCES: Dict[str, Consequence] = {
    # downtime hours (min, mode, max); cost per hour and fixed cost in MUSD
    "imp_prod_stop": Consequence((24.0, 120.0, 840.0), 1.05, (5.0, 25.0, 120.0)),
    "imp_quality": Consequence((0.0, 8.0, 72.0), 1.05, (10.0, 90.0, 400.0)),
    "imp_safety": Consequence((48.0, 168.0, 720.0), 1.05, (20.0, 150.0, 600.0), safety=True),
    "imp_ip": Consequence((0.0, 0.0, 0.0), 0.0, (5.0, 40.0, 250.0)),
    "imp_pii": Consequence((0.0, 0.0, 0.0), 0.0, (3.0, 25.0, 180.0)),
}

#: Nodes that, when traversed, extend the outage (recovery inhibition).
AMPLIFIERS: Dict[str, float] = {"it_backup": 1.8, "it_sccm": 1.25, "ops_ot_ad": 1.15}

ENTRY_POINTS: Tuple[str, ...] = ("ext_actor",)


def build_graph(overrides: Optional[Dict[Tuple[str, str, str], Dict[str, float]]] = None
                ) -> AttackGraph:
    """Instantiate and validate the reference attack graph.

    ``overrides`` replaces ``p``, ``delta`` or ``effort_h`` on individual steps,
    keyed by ``(src, dst, technique)``. It is how elicited parameters enter the
    model: ``capm.elicitation.load_overrides`` reads the file a panel produced,
    and the whole pipeline can then be re-run on measured rather than assumed
    values. Steps absent from the mapping keep their published estimate.
    """
    g = AttackGraph()
    for z in ZONES:
        g.add_zone(z)
    for a in ASSETS:
        g.add_asset(a)
    for tid, tech in catalogue().items():
        g.add_technique(tech)
    for (src, dst, tech, p, delta, effort, controls, rationale, evidence) in EDGES:
        if overrides:
            replacement = overrides.get((src, dst, tech))
            if replacement:
                p = replacement.get("p", p)
                delta = replacement.get("delta", delta)
                effort = replacement.get("effort_h", effort)
        g.add_edge(Edge(src, dst, tech, p, delta, effort, tuple(controls), rationale, tuple(evidence)))
    g.consequences = dict(CONSEQUENCES)
    g.entry_points = ENTRY_POINTS
    problems = g.validate()
    if problems:
        raise ValueError("invalid reference architecture:\n  " + "\n  ".join(problems))
    return g
