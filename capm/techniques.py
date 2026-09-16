"""MITRE ATT&CK technique catalogue used by the reference architecture.

Only the techniques that are actually instantiated by an edge of the reference
model are listed. Enterprise techniques use the ``Txxxx`` identifiers of ATT&CK
v17 (Enterprise matrix); industrial techniques use the ``T0xxx`` identifiers of
ATT&CK for ICS.
"""

from __future__ import annotations

from typing import Dict

from .model import Technique

_ENTERPRISE = [
    ("T1566", "Phishing", "Initial Access"),
    ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    ("T1189", "Drive-by Compromise", "Initial Access"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("T1133", "External Remote Services", "Initial Access"),
    ("T1199", "Trusted Relationship", "Initial Access"),
    ("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access"),
    ("T1078", "Valid Accounts", "Initial Access"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    ("T1091", "Replication Through Removable Media", "Initial Access"),
    ("T1204.002", "User Execution: Malicious File", "Execution"),
    ("T1072", "Software Deployment Tools", "Execution"),
    ("T1098", "Account Manipulation", "Persistence"),
    ("T1656", "Impersonation", "Defense Evasion"),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    ("T1003.006", "OS Credential Dumping: DCSync", "Credential Access"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    ("T1606.002", "Forge Web Credentials: SAML Tokens", "Credential Access"),
    ("T1621", "Multi-Factor Authentication Request Generation", "Credential Access"),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    ("T1550.001", "Use Alternate Authentication Material: Application Access Token", "Lateral Movement"),
    ("T1039", "Data from Network Shared Drive", "Collection"),
    ("T1213", "Data from Information Repositories", "Collection"),
    ("T1530", "Data from Cloud Storage", "Collection"),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1489", "Service Stop", "Impact"),
    ("T1490", "Inhibit System Recovery", "Impact"),
]

_ICS = [
    ("T0822", "External Remote Services", "Initial Access"),
    ("T0847", "Replication Through Removable Media", "Initial Access"),
    ("T0862", "Supply Chain Compromise", "Initial Access"),
    ("T0873", "Project File Infection", "Persistence"),
    ("T0885", "Commonly Used Port", "Command and Control"),
    ("T0886", "Remote Services", "Lateral Movement"),
    ("T0843", "Program Download", "Lateral Movement"),
    ("T0889", "Modify Program", "Persistence"),
    ("T0855", "Unauthorized Command Message", "Impair Process Control"),
    ("T0836", "Modify Parameter", "Impair Process Control"),
    ("T0831", "Manipulation of Control", "Impair Process Control"),
    ("T0816", "Device Restart/Shutdown", "Inhibit Response Function"),
    ("T0813", "Denial of Control", "Impact"),
    ("T0828", "Loss of Productivity and Revenue", "Impact"),
    ("T0880", "Loss of Safety", "Impact"),
]


def catalogue() -> Dict[str, Technique]:
    out: Dict[str, Technique] = {}
    for tid, name, tactic in _ENTERPRISE:
        out[tid] = Technique(tid, name, tactic, "enterprise")
    for tid, name, tactic in _ICS:
        out[tid] = Technique(tid, name, tactic, "ics")
    return out
