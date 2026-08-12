"""MITRE ATT&CK Enterprise v16.1 — Professional Threat Intelligence Mapping.

Provides comprehensive mapping between web-application vulnerabilities
detected by PentaVault and the MITRE ATT&CK framework (Enterprise matrix).

Coverage
--------
- 14 Enterprise Tactics  (TA0001 – TA0043)
- 55+ Techniques & Sub-techniques
- Confidence-scored vulnerability → technique associations
- Kill-chain phase cross-references (Lockheed Martin Cyber Kill Chain)
- Per-technique detection guidance, mitigations, platforms & data sources
- Attack-path construction from correlated findings
- Matrix coverage analysis for executive reporting

Alignment: STIX 2.1 object model (attack-pattern, x-mitre-tactic)
Reference: https://attack.mitre.org/  |  ATT&CK version 16.1 (Oct 2024)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# ═══════════════════════════════════════════════════════════════════
#  1.  ENUMERATIONS & DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

class Confidence(str, Enum):
    """Mapping confidence — how strongly a vulnerability maps to a technique."""
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class Platform(str, Enum):
    """Target platforms per ATT&CK Enterprise matrix."""
    LINUX   = "Linux"
    WINDOWS = "Windows"
    MACOS   = "macOS"
    SAAS    = "SaaS"
    IAAS    = "IaaS"
    OFFICE  = "Office 365"
    AZURE   = "Azure AD"
    GWS     = "Google Workspace"
    CONTAINERS = "Containers"
    NETWORK = "Network"
    PRE     = "PRE"


class KillChainPhase(str, Enum):
    """Lockheed Martin Cyber Kill Chain phases."""
    RECONNAISSANCE  = "Reconnaissance"
    WEAPONIZATION   = "Weaponization"
    DELIVERY        = "Delivery"
    EXPLOITATION    = "Exploitation"
    INSTALLATION    = "Installation"
    C2              = "Command & Control"
    ACTIONS         = "Actions on Objectives"


# ── Tactic Registry ────────────────────────────────────────────────

@dataclass(frozen=True)
class Tactic:
    id: str
    name: str
    shortname: str          # ATT&CK URL slug
    ordinal: int            # display order in ATT&CK matrix
    description: str

TACTICS: dict[str, Tactic] = {}

def _t(tid: str, name: str, shortname: str, ordinal: int, desc: str) -> Tactic:
    tac = Tactic(tid, name, shortname, ordinal, desc)
    TACTICS[tid] = tac
    return tac

TA0043 = _t("TA0043", "Reconnaissance",        "reconnaissance",         1,  "Gather information to plan future operations.")
TA0042 = _t("TA0042", "Resource Development",   "resource-development",   2,  "Establish resources to support operations.")
TA0001 = _t("TA0001", "Initial Access",         "initial-access",         3,  "Gain an initial foothold within a network.")
TA0002 = _t("TA0002", "Execution",              "execution",              4,  "Run adversary-controlled code.")
TA0003 = _t("TA0003", "Persistence",            "persistence",            5,  "Maintain a foothold across restarts or credential changes.")
TA0004 = _t("TA0004", "Privilege Escalation",   "privilege-escalation",   6,  "Gain higher-level permissions.")
TA0005 = _t("TA0005", "Defense Evasion",        "defense-evasion",        7,  "Avoid detection throughout the compromise.")
TA0006 = _t("TA0006", "Credential Access",      "credential-access",      8,  "Steal account credentials.")
TA0007 = _t("TA0007", "Discovery",              "discovery",              9,  "Understand the victim environment.")
TA0008 = _t("TA0008", "Lateral Movement",       "lateral-movement",      10,  "Move through the environment to reach objectives.")
TA0009 = _t("TA0009", "Collection",             "collection",            11,  "Gather data of interest.")
TA0011 = _t("TA0011", "Command and Control",    "command-and-control",   12,  "Communicate with compromised systems.")
TA0010 = _t("TA0010", "Exfiltration",           "exfiltration",          13,  "Steal data from the network.")
TA0040 = _t("TA0040", "Impact",                 "impact",                14,  "Disrupt availability or compromise integrity.")


# ── Technique Data Model ───────────────────────────────────────────

@dataclass
class Technique:
    id: str
    name: str
    tactic_ids: list[str]
    url: str
    description: str
    platforms: list[str]        = field(default_factory=lambda: [Platform.LINUX, Platform.WINDOWS, Platform.SAAS])
    data_sources: list[str]     = field(default_factory=list)
    detection: str              = ""
    mitigations: list[str]      = field(default_factory=list)
    kill_chain: list[str]       = field(default_factory=list)
    severity_weight: float      = 5.0      # 1-10 internal risk weight
    is_subtechnique: bool       = False
    parent_id: str | None       = None

    # Convenience helpers ────────────────────────────────────────
    @property
    def primary_tactic_id(self) -> str:
        return self.tactic_ids[0]

    @property
    def primary_tactic(self) -> str:
        return TACTICS[self.primary_tactic_id].name if self.primary_tactic_id in TACTICS else "Unknown"

    def to_ref(self) -> dict[str, Any]:
        """Compact dict suitable for JSON serialisation / API responses."""
        return {
            "technique_id": self.id,
            "name": self.name,
            "tactic": self.primary_tactic,
            "tactic_id": self.primary_tactic_id,
            "tactics": [{"id": tid, "name": TACTICS[tid].name} for tid in self.tactic_ids if tid in TACTICS],
            "url": self.url,
            "description": self.description,
            "platforms": [p.value if hasattr(p, 'value') else p for p in self.platforms],
            "data_sources": self.data_sources,
            "detection": self.detection,
            "mitigations": self.mitigations,
            "kill_chain": [k.value if hasattr(k, 'value') else k for k in self.kill_chain],
            "severity_weight": self.severity_weight,
            "is_subtechnique": self.is_subtechnique,
            "parent_id": self.parent_id,
        }


# ═══════════════════════════════════════════════════════════════════
#  2.  TECHNIQUE DATABASE  (55+ techniques, Enterprise ATT&CK v16.1)
# ═══════════════════════════════════════════════════════════════════

_DB: dict[str, Technique] = {}

def _reg(t: Technique) -> Technique:
    _DB[t.id] = t
    return t

# ── TA0043 Reconnaissance ──────────────────────────────────────────

_reg(Technique(
    id="T1595", name="Active Scanning",
    tactic_ids=["TA0043"],
    url="https://attack.mitre.org/techniques/T1595/",
    description="Adversaries execute active reconnaissance scans to gather information that can be used during targeting. Active scans involve probing victim infrastructure via network traffic.",
    platforms=[Platform.PRE],
    data_sources=["Network Traffic: Network Traffic Flow", "Network Traffic: Network Traffic Content"],
    detection="Monitor for suspicious network traffic that could indicate scanning activity. Look for anomalous patterns such as sequential port probes or high-frequency HTTP requests to multiple paths.",
    mitigations=["M1056 — Pre-compromise: Cannot be easily mitigated as it occurs outside defender visibility"],
    kill_chain=[KillChainPhase.RECONNAISSANCE],
    severity_weight=3.0,
))

_reg(Technique(
    id="T1595.002", name="Active Scanning: Vulnerability Scanning",
    tactic_ids=["TA0043"],
    url="https://attack.mitre.org/techniques/T1595/002/",
    description="Adversaries scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check running software versions against known CVEs.",
    platforms=[Platform.PRE],
    data_sources=["Network Traffic: Network Traffic Flow", "Network Traffic: Network Traffic Content"],
    detection="Monitor for typical vulnerability scanning signatures in IDS/IPS. Frequent requests to non-existent paths or known exploit endpoints indicate active scanning.",
    mitigations=["M1056 — Pre-compromise: Limit externally-visible attack surface"],
    kill_chain=[KillChainPhase.RECONNAISSANCE],
    severity_weight=3.0,
    is_subtechnique=True, parent_id="T1595",
))

_reg(Technique(
    id="T1592", name="Gather Victim Host Information",
    tactic_ids=["TA0043"],
    url="https://attack.mitre.org/techniques/T1592/",
    description="Adversaries gather information about the victim's hosts that can be used during targeting, including hardware, software, and configuration details.",
    platforms=[Platform.PRE],
    data_sources=["Internet Scan: Response Content"],
    detection="Monitor for indicators of information gathering such as banner-grabbing attempts and requests targeting server status pages or info-disclosure endpoints.",
    mitigations=["M1056 — Pre-compromise: Remove unnecessary server headers and information-disclosure endpoints"],
    kill_chain=[KillChainPhase.RECONNAISSANCE],
    severity_weight=2.5,
))

_reg(Technique(
    id="T1590", name="Gather Victim Network Information",
    tactic_ids=["TA0043"],
    url="https://attack.mitre.org/techniques/T1590/",
    description="Adversaries gather information about the victim's networks that can be used during targeting, including topology, addressing, security appliances, and DNS records.",
    platforms=[Platform.PRE],
    data_sources=["Internet Scan: Response Content", "Domain Name: Domain Registration"],
    detection="Monitor for WHOIS queries, DNS enumeration attempts, and network mapping activities targeting your infrastructure.",
    mitigations=["M1056 — Pre-compromise: Limit publicly available network information; use WHOIS privacy"],
    kill_chain=[KillChainPhase.RECONNAISSANCE],
    severity_weight=2.5,
))

# ── TA0042 Resource Development ────────────────────────────────────

_reg(Technique(
    id="T1583.006", name="Acquire Infrastructure: Web Services",
    tactic_ids=["TA0042"],
    url="https://attack.mitre.org/techniques/T1583/006/",
    description="Adversaries may register or compromise web services to host malicious content, stage payloads, or facilitate phishing. Open redirects on trusted domains help legitimise such infrastructure.",
    platforms=[Platform.PRE],
    data_sources=["Internet Scan: Response Content"],
    detection="Flag open redirects to external domains. Monitor for newly registered domains mimicking your brand.",
    mitigations=["M1056 — Pre-compromise: Eliminate open redirect vulnerabilities; implement URL allow-listing"],
    kill_chain=[KillChainPhase.WEAPONIZATION],
    severity_weight=4.0,
))

_reg(Technique(
    id="T1584.001", name="Compromise Infrastructure: Domains",
    tactic_ids=["TA0042"],
    url="https://attack.mitre.org/techniques/T1584/001/",
    description="Adversaries may compromise domains owned by third parties to hijack subdomains, host malicious content, or conduct adversary-in-the-middle attacks via dangling DNS records.",
    platforms=[Platform.PRE, Platform.IAAS],

    data_sources=["DNS: Response", "Domain Registration: Domain Name"],
    detection="Monitor DNS records for dangling CNAME pointers to unallocated cloud resources.",
    mitigations=["M1056 — Pre-compromise: Audit external CNAME records regularly and remove dangling pointers."],
    kill_chain=[KillChainPhase.WEAPONIZATION],
    severity_weight=7.5,
))


_reg(Technique(
    id="T1588.006", name="Obtain Capabilities: Vulnerabilities",
    tactic_ids=["TA0042"],
    url="https://attack.mitre.org/techniques/T1588/006/",
    description="Adversaries may acquire information about vulnerabilities to use during targeting — for example, by scanning public CVE databases, or purchasing 0-day exploits.",
    platforms=[Platform.PRE],
    data_sources=["Malware Repository: Malware Content"],
    detection="This activity occurs outside defender visibility. Ensure timely patching to reduce the window of exploitation.",
    mitigations=["M1056 — Pre-compromise: Timely patch management; vulnerability disclosure programs"],
    kill_chain=[KillChainPhase.WEAPONIZATION],
    severity_weight=3.5,
))

# ── TA0001 Initial Access ─────────────────────────────────────────

_reg(Technique(
    id="T1190", name="Exploit Public-Facing Application",
    tactic_ids=["TA0001"],
    url="https://attack.mitre.org/techniques/T1190/",
    description="Adversaries may exploit a weakness in an internet-facing application or program to gain initial access. Web applications are primary targets — SQLi, RCE, deserialization, and file upload all qualify.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.CONTAINERS, Platform.IAAS, Platform.SAAS, Platform.NETWORK],
    data_sources=["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
    detection="Monitor application logs for anomalous input patterns (SQLi payloads, unexpected serialized objects). Deploy WAF rules and runtime application self-protection (RASP). Correlate multiple 4xx/5xx errors from single source IPs.",
    mitigations=[
        "M1048 — Application Isolation and Sandboxing",
        "M1050 — Exploit Protection (WAF, RASP)",
        "M1030 — Network Segmentation",
        "M1051 — Update Software",
        "M1016 — Vulnerability Scanning",
    ],
    kill_chain=[KillChainPhase.DELIVERY, KillChainPhase.EXPLOITATION],
    severity_weight=9.0,
))

_reg(Technique(
    id="T1189", name="Drive-by Compromise",
    tactic_ids=["TA0001"],
    url="https://attack.mitre.org/techniques/T1189/",
    description="Adversaries gain access through a user visiting a website during normal browsing. The website is often trusted but has been compromised; malicious scripts (e.g. injected XSS) exploit the user's browser or session.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS],
    data_sources=["Application Log: Application Log Content", "File: File Creation", "Network Traffic: Network Connection Creation", "Process: Process Creation"],
    detection="Use browser isolation; monitor for unexpected script execution or DOM changes. Inspect outbound connections to suspicious C2 domains after visits to web applications.",
    mitigations=[
        "M1048 — Application Isolation and Sandboxing",
        "M1050 — Exploit Protection (CSP headers, Sub-Resource Integrity)",
        "M1021 — Restrict Web-Based Content",
        "M1051 — Update Software",
    ],
    kill_chain=[KillChainPhase.DELIVERY, KillChainPhase.EXPLOITATION],
    severity_weight=7.5,
))

_reg(Technique(
    id="T1078", name="Valid Accounts",
    tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
    url="https://attack.mitre.org/techniques/T1078/",
    description="Adversaries obtain and use legitimate credentials (default, stolen, or brute-forced) to gain initial access, maintain persistence, escalate privileges, or evade defenses.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.IAAS, Platform.AZURE, Platform.GWS, Platform.OFFICE, Platform.CONTAINERS, Platform.NETWORK],
    data_sources=["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
    detection="Correlate login events with known good baselines. Alert on logins from unexpected geolocations, impossible-travel, or concurrent sessions. Monitor for credential stuffing patterns (many failed logins).",
    mitigations=[
        "M1013 — Application Developer Guidance (no default credentials)",
        "M1027 — Password Policies (complexity, rotation)",
        "M1032 — Multi-factor Authentication",
        "M1036 — Account Use Policies (lockout thresholds)",
        "M1026 — Privileged Account Management",
    ],
    kill_chain=[KillChainPhase.DELIVERY, KillChainPhase.EXPLOITATION],
    severity_weight=8.0,
))

_reg(Technique(
    id="T1078.001", name="Valid Accounts: Default Accounts",
    tactic_ids=["TA0001", "TA0003", "TA0004"],
    url="https://attack.mitre.org/techniques/T1078/001/",
    description="Adversaries use built-in/default credentials to gain access. Many devices and applications ship with well-known default usernames and passwords.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.IAAS, Platform.AZURE, Platform.NETWORK, Platform.CONTAINERS],
    data_sources=["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
    detection="Audit all default credentials before deployment. Alert on successful authentication by default usernames.",
    mitigations=["M1027 — Password Policies: Change all default credentials at deployment"],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=7.5,
    is_subtechnique=True, parent_id="T1078",
))

# ── TA0002 Execution ──────────────────────────────────────────────

_reg(Technique(
    id="T1059", name="Command and Scripting Interpreter",
    tactic_ids=["TA0002"],
    url="https://attack.mitre.org/techniques/T1059/",
    description="Adversaries abuse command and script interpreters to execute commands, scripts, or binaries. Commonly exploited in web apps through OS command injection and server-side template injection.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["Command: Command Execution", "Process: Process Creation", "Script: Script Execution"],
    detection="Monitor application logs for shell metacharacters in request parameters. Deploy runtime execution monitoring to detect unexpected child processes from web server processes.",
    mitigations=[
        "M1049 — Antivirus/Antimalware",
        "M1038 — Execution Prevention",
        "M1040 — Behavior Prevention on Endpoint",
        "M1026 — Privileged Account Management (least privilege for web service accounts)",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION, KillChainPhase.INSTALLATION],
    severity_weight=9.5,
))

_reg(Technique(
    id="T1059.007", name="Command and Scripting Interpreter: JavaScript",
    tactic_ids=["TA0002"],
    url="https://attack.mitre.org/techniques/T1059/007/",
    description="Adversaries abuse JavaScript for execution, including client-side XSS attacks that execute arbitrary scripts in victim browsers, and server-side Node.js injection.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Command: Command Execution", "Process: Process Creation"],
    detection="Implement strict Content-Security-Policy headers. Monitor DOM mutation events for injected scripts. Server-side: restrict eval() and Function() usage.",
    mitigations=[
        "M1040 — Behavior Prevention on Endpoint",
        "M1038 — Execution Prevention (CSP, SRI)",
        "M1050 — Exploit Protection",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=7.0,
    is_subtechnique=True, parent_id="T1059",
))

_reg(Technique(
    id="T1203", name="Exploitation for Client Execution",
    tactic_ids=["TA0002"],
    url="https://attack.mitre.org/techniques/T1203/",
    description="Adversaries exploit software vulnerabilities in client applications (browsers, PDF readers, office suites) to execute arbitrary code, often as a result of visiting a compromised web page or opening a crafted document.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Application Log: Application Log Content", "Process: Process Creation"],
    detection="Monitor process creation from browser and document-reader processes. Use sandboxed browser environments and exploit-protection technologies (CFG, ACG).",
    mitigations=[
        "M1048 — Application Isolation and Sandboxing",
        "M1050 — Exploit Protection",
        "M1051 — Update Software",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=7.5,
    is_subtechnique=False,
))

# ── TA0003 Persistence ────────────────────────────────────────────

_reg(Technique(
    id="T1505", name="Server Software Component",
    tactic_ids=["TA0003"],
    url="https://attack.mitre.org/techniques/T1505/",
    description="Adversaries abuse legitimate extensible components of servers (modules, plugins, scripts) to establish persistent access.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.NETWORK],
    data_sources=["Application Log: Application Log Content", "File: File Creation", "File: File Modification", "Network Traffic: Network Traffic Flow"],
    detection="Monitor web server content directory for unauthorized file creation. Use file-integrity-monitoring (FIM) on web roots.",
    mitigations=[
        "M1042 — Disable or Remove Feature or Program",
        "M1018 — User Account Management",
        "M1024 — Restrict Registry Permissions",
    ],
    kill_chain=[KillChainPhase.INSTALLATION],
    severity_weight=8.0,
))

_reg(Technique(
    id="T1505.003", name="Server Software Component: Web Shell",
    tactic_ids=["TA0003"],
    url="https://attack.mitre.org/techniques/T1505/003/",
    description="Adversaries install web shells on web servers to maintain persistent access. Web shells provide a backdoor via HTTP and can be implanted through SQL injection, file upload vulnerabilities, or compromised credentials.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.NETWORK],
    data_sources=["Application Log: Application Log Content", "File: File Creation", "File: File Modification", "Network Traffic: Network Traffic Flow", "Process: Process Creation"],
    detection="Monitor for new or modified server-side scripts in web-accessible directories. Detect unusual child-process execution from web server processes (e.g. cmd.exe or /bin/sh spawned by w3wp.exe or httpd).",
    mitigations=[
        "M1042 — Disable or Remove Feature or Program (disable script execution in upload dirs)",
        "M1018 — User Account Management (least privilege for web accounts)",
        "M1033 — Limit Software Installation",
    ],
    kill_chain=[KillChainPhase.INSTALLATION],
    severity_weight=9.0,
    is_subtechnique=True, parent_id="T1505",
))

_reg(Technique(
    id="T1546", name="Event Triggered Execution",
    tactic_ids=["TA0003", "TA0004"],
    url="https://attack.mitre.org/techniques/T1546/",
    description="Adversaries establish persistence and/or elevate privileges using mechanisms triggered by specific events — stored XSS payloads execute every time a victim views the affected page.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS],
    data_sources=["Command: Command Execution", "File: File Creation", "Process: Process Creation", "WMI: WMI Creation"],
    detection="Monitor for persistent script injection in stored content (database, templates). Implement output encoding. Review database content for suspicious HTML/JavaScript.",
    mitigations=[
        "M1038 — Execution Prevention",
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.INSTALLATION],
    severity_weight=7.0,
))

# ── TA0004 Privilege Escalation ───────────────────────────────────

_reg(Technique(
    id="T1068", name="Exploitation for Privilege Escalation",
    tactic_ids=["TA0004"],
    url="https://attack.mitre.org/techniques/T1068/",
    description="Adversaries exploit software vulnerabilities (IDOR, broken access control, insecure direct object references) to gain elevated privileges beyond what is normally authorized.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.CONTAINERS],
    data_sources=["Application Log: Application Log Content", "Process: Process Creation"],
    detection="Monitor for access-control bypass patterns — sequential ID enumeration, unauthorized API calls returning 200 instead of 403. Implement security regression testing on authorization logic.",
    mitigations=[
        "M1048 — Application Isolation and Sandboxing",
        "M1050 — Exploit Protection",
        "M1019 — Threat Intelligence Program",
        "M1051 — Update Software",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=8.5,
))

_reg(Technique(
    id="T1548", name="Abuse Elevation Control Mechanism",
    tactic_ids=["TA0004", "TA0005"],
    url="https://attack.mitre.org/techniques/T1548/",
    description="Adversaries circumvent mechanisms designed to control elevated privileges (e.g. role checks, admin panels) to gain higher-level permissions in web applications.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Command: Command Execution", "Process: OS API Execution", "Process: Process Creation"],
    detection="Monitor for forced browsing to admin endpoints. Detect privilege-escalation attempts by auditing role changes and access-control decisions server-side.",
    mitigations=[
        "M1047 — Audit",
        "M1038 — Execution Prevention",
        "M1026 — Privileged Account Management",
        "M1028 — Operating System Configuration",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=8.0,
))

# ── TA0005 Defense Evasion ────────────────────────────────────────

_reg(Technique(
    id="T1036", name="Masquerading",
    tactic_ids=["TA0005"],
    url="https://attack.mitre.org/techniques/T1036/",
    description="Adversaries manipulate features of their artifacts to make them appear legitimate. Missing X-Content-Type-Options headers allow MIME-sniffing attacks; missing CSP allows inline script injection that masquerades as legitimate page content.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.CONTAINERS],
    data_sources=["File: File Metadata", "File: File Modification", "Process: Process Metadata"],
    detection="Monitor for missing security headers in responses. Implement automated security-header auditing in CI/CD pipelines.",
    mitigations=[
        "M1045 — Code Signing",
        "M1040 — Behavior Prevention on Endpoint",
        "M1038 — Execution Prevention",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=4.5,
))

_reg(Technique(
    id="T1027", name="Obfuscated Files or Information",
    tactic_ids=["TA0005"],
    url="https://attack.mitre.org/techniques/T1027/",
    description="Adversaries obfuscate payloads and scripts to evade detection — XSS payloads often use encoding, character substitution, and DOM clobbering to bypass WAF rules and CSP.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Command: Command Execution", "File: File Creation", "File: File Metadata", "Process: Process Creation"],
    detection="Inspect decoded request payloads. Deploy WAF rules that normalize and decode input before matching. Monitor for HTML entity encoding and JavaScript escaping patterns in user input.",
    mitigations=[
        "M1049 — Antivirus/Antimalware",
        "M1040 — Behavior Prevention on Endpoint",
    ],
    kill_chain=[KillChainPhase.DELIVERY],
    severity_weight=5.0,
))

_reg(Technique(
    id="T1070", name="Indicator Removal",
    tactic_ids=["TA0005"],
    url="https://attack.mitre.org/techniques/T1070/",
    description="Adversaries delete or modify artifacts generated by their activity. SQL injection can be used to truncate log tables; inadequate security logging allows adversaries to operate undetected.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.CONTAINERS, Platform.NETWORK],
    data_sources=["Application Log: Application Log Content", "File: File Deletion", "File: File Modification"],
    detection="Implement immutable, centralized logging. Alert on gaps in log sequences or unauthorized access to log tables. Use write-once storage for security events.",
    mitigations=[
        "M1041 — Encrypt Sensitive Information (protect log integrity)",
        "M1029 — Remote Data Storage (centralized logging)",
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=6.0,
))

_reg(Technique(
    id="T1562", name="Impair Defenses",
    tactic_ids=["TA0005"],
    url="https://attack.mitre.org/techniques/T1562/",
    description="Adversaries disable or modify security tools and logging. Missing security headers (CSP, X-Frame-Options, HSTS) impair built-in browser defense mechanisms that would otherwise prevent exploitation.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.CONTAINERS, Platform.IAAS, Platform.NETWORK],
    data_sources=["Command: Command Execution", "Process: Process Termination", "Sensor Health: Host Status"],
    detection="Monitor for changes to security header configurations. Automate security-header validation in deployment pipelines.",
    mitigations=[
        "M1022 — Restrict File and Directory Permissions",
        "M1024 — Restrict Registry Permissions",
        "M1018 — User Account Management",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=5.5,
))

# ── TA0006 Credential Access ─────────────────────────────────────

_reg(Technique(
    id="T1539", name="Steal Web Session Cookie",
    tactic_ids=["TA0006"],
    url="https://attack.mitre.org/techniques/T1539/",
    description="Adversaries steal web session cookies via XSS, network sniffing, or malware to hijack authenticated sessions without needing credentials.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.OFFICE, Platform.GWS],
    data_sources=["Logon Session: Logon Session Creation", "Process: Process Access"],
    detection="Set HttpOnly and Secure flags on session cookies. Monitor for sessions with anomalous source IPs. Implement session binding (fingerprinting user agent + IP range).",
    mitigations=[
        "M1032 — Multi-factor Authentication",
        "M1054 — Software Configuration (HttpOnly, Secure, SameSite cookie flags)",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS],
    severity_weight=8.0,
))

_reg(Technique(
    id="T1557", name="Adversary-in-the-Middle",
    tactic_ids=["TA0006", "TA0009"],
    url="https://attack.mitre.org/techniques/T1557/",
    description="Adversaries position themselves between two systems to intercept and manipulate traffic. Missing HSTS headers and Transport Layer Security misconfigurations enable MITM attacks to steal credentials and session tokens.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow", "Service: Service Creation"],
    detection="Monitor for TLS downgrade attempts. Implement certificate pinning. Detect ARP spoofing and DNS hijacking on internal networks.",
    mitigations=[
        "M1041 — Encrypt Sensitive Information (enforce TLS 1.2+ everywhere)",
        "M1035 — Limit Access to Resource Over Network (HSTS preload)",
        "M1030 — Network Segmentation",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=7.0,
))

_reg(Technique(
    id="T1110", name="Brute Force",
    tactic_ids=["TA0006"],
    url="https://attack.mitre.org/techniques/T1110/",
    description="Adversaries use brute-force techniques to attempt access to accounts by systematically guessing passwords. Login forms without rate limiting or lockout are especially vulnerable.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.IAAS, Platform.AZURE, Platform.GWS, Platform.OFFICE, Platform.CONTAINERS],
    data_sources=["Application Log: Application Log Content", "User Account: User Account Authentication"],
    detection="Monitor for high volumes of failed authentication attempts from single or distributed sources. Implement progressive delays and account lockout after N failures.",
    mitigations=[
        "M1032 — Multi-factor Authentication",
        "M1027 — Password Policies (complexity, length)",
        "M1036 — Account Use Policies (lockout thresholds)",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=6.5,
))

_reg(Technique(
    id="T1110.001", name="Brute Force: Password Guessing",
    tactic_ids=["TA0006"],
    url="https://attack.mitre.org/techniques/T1110/001/",
    description="Adversaries guess passwords for user accounts, often trying common passwords, dictionary words, or passwords from breached credential lists against login forms.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.IAAS, Platform.AZURE, Platform.GWS, Platform.OFFICE, Platform.CONTAINERS],
    data_sources=["Application Log: Application Log Content", "User Account: User Account Authentication"],
    detection="Monitor for slow-rate brute-force patterns. Implement CAPTCHA after 3-5 failed login attempts.",
    mitigations=["M1032 — Multi-factor Authentication", "M1027 — Password Policies"],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=6.0,
    is_subtechnique=True, parent_id="T1110",
))

_reg(Technique(
    id="T1555", name="Credentials from Password Stores",
    tactic_ids=["TA0006"],
    url="https://attack.mitre.org/techniques/T1555/",
    description="Adversaries search for credentials in password stores including browser credential stores, application configuration files, and database connection strings exposed through SSRF or LFI.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.IAAS],
    data_sources=["Cloud Service: Cloud Service Enumeration", "Command: Command Execution", "File: File Access", "Process: OS API Execution", "Process: Process Access"],
    detection="Monitor for access to browser credential databases, application configuration files, and cloud metadata endpoints that may contain credentials.",
    mitigations=[
        "M1027 — Password Policies",
        "M1026 — Privileged Account Management",
        "M1051 — Update Software",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=7.5,
))

_reg(Technique(
    id="T1552.001", name="Unsecured Credentials: Credentials In Files",
    tactic_ids=["TA0006"],
    url="https://attack.mitre.org/techniques/T1552/001/",
    description="Adversaries search for hardcoded credentials, API keys, tokens, or private keys exposed in source code, client-side JavaScript bundles, configuration files, or public repositories.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.IAAS],
    data_sources=["File: File Content", "Script: Script Execution"],
    detection="Audit client-side JavaScript bundles and HTML source for exposed API keys, tokens, and credentials.",
    mitigations=["M1027 — Password Policies", "M1041 — Encrypt Sensitive Information (do not embed secrets in client-side code)"],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=7.5,
    is_subtechnique=True, parent_id="T1552",
))

_reg(Technique(
    id="T1552.005", name="Unsecured Credentials: Cloud Instance Metadata API",
    tactic_ids=["TA0006"],
    url="https://attack.mitre.org/techniques/T1552/005/",
    description="Adversaries query or inspect application responses to access cloud instance metadata services (IMDS) containing credentials or system parameters.",
    platforms=[Platform.SAAS, Platform.IAAS],
    data_sources=["Application Log: Application Log Content", "Instance: Instance Metadata"],
    detection="Monitor for unauthorized access or leakage of IMDS responses containing IAM tokens or instance credentials.",
    mitigations=["M1042 — Disable Instance Metadata Service or enforce IMDSv2"],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=8.5,
    is_subtechnique=True, parent_id="T1552",
))



# ── TA0007 Discovery ─────────────────────────────────────────────

_reg(Technique(
    id="T1046", name="Network Service Discovery",
    tactic_ids=["TA0007"],
    url="https://attack.mitre.org/techniques/T1046/",
    description="Adversaries scan for running services to identify potential attack surfaces. Port scanning and service enumeration reveal exposed services, versions, and configurations.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.CONTAINERS, Platform.IAAS, Platform.NETWORK],
    data_sources=["Cloud Service: Cloud Service Enumeration", "Command: Command Execution", "Network Traffic: Network Traffic Flow"],
    detection="Monitor for sequential port scanning patterns. Deploy internal honeypots to detect lateral service enumeration.",
    mitigations=[
        "M1030 — Network Segmentation (restrict inter-zone scanning)",
        "M1031 — Network Intrusion Prevention",
        "M1042 — Disable or Remove Feature or Program (close unused ports)",
    ],
    kill_chain=[KillChainPhase.RECONNAISSANCE],
    severity_weight=4.0,
))

_reg(Technique(
    id="T1082", name="System Information Discovery",
    tactic_ids=["TA0007"],
    url="https://attack.mitre.org/techniques/T1082/",
    description="Adversaries attempt to discover detailed system information — server version headers, framework disclosure, debug pages, and error messages reveal software, OS versions, and internal configuration.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.IAAS, Platform.NETWORK],
    data_sources=["Command: Command Execution", "Process: OS API Execution", "Process: Process Creation"],
    detection="Monitor for requests targeting version-disclosure endpoints (/server-status, /server-info). Audit server configurations for verbose error messages.",
    mitigations=[
        "M1054 — Software Configuration (disable verbose errors, remove Server headers)",
    ],
    kill_chain=[KillChainPhase.RECONNAISSANCE],
    severity_weight=3.5,
))

_reg(Technique(
    id="T1083", name="File and Directory Discovery",
    tactic_ids=["TA0007"],
    url="https://attack.mitre.org/techniques/T1083/",
    description="Adversaries enumerate files and directories on target systems. Web directory brute-forcing, path traversal, and LFI allow discovery of sensitive files (configurations, backups, source code).",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["Command: Command Execution", "Process: OS API Execution", "Process: Process Creation"],
    detection="Monitor for high-volume 404 responses indicating directory brute-forcing. Alert on path traversal patterns (../) in request URLs.",
    mitigations=[
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.RECONNAISSANCE, KillChainPhase.EXPLOITATION],
    severity_weight=5.0,
))

_reg(Technique(
    id="T1580", name="Cloud Infrastructure Discovery",
    tactic_ids=["TA0007"],
    url="https://attack.mitre.org/techniques/T1580/",
    description="Adversaries discover cloud infrastructure components via SSRF to cloud metadata endpoints (169.254.169.254), allowing enumeration of cloud resources, IAM roles, and network configurations.",
    platforms=[Platform.IAAS],
    data_sources=["Cloud Service: Cloud Service Enumeration", "Instance: Instance Metadata"],
    detection="Monitor for SSRF attempts targeting cloud metadata endpoints. Block server-side requests to 169.254.169.254 unless specifically required.",
    mitigations=[
        "M1018 — User Account Management",
        "M1037 — Filter Network Traffic (block metadata endpoint access)",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION, KillChainPhase.RECONNAISSANCE],
    severity_weight=7.0,
))

# ── TA0008 Lateral Movement ──────────────────────────────────────

_reg(Technique(
    id="T1210", name="Exploitation of Remote Services",
    tactic_ids=["TA0008"],
    url="https://attack.mitre.org/techniques/T1210/",
    description="Adversaries exploit remote services to gain access to internal systems. SSRF vulnerabilities allow pivoting from a public-facing application to internal services that are not directly exposed to the internet.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.CONTAINERS],
    data_sources=["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
    detection="Monitor for unexpected internal network connections from web-server processes. Alert on SSRF patterns (requests to RFC1918 addresses, cloud metadata IPs, or localhost).",
    mitigations=[
        "M1042 — Disable or Remove Feature or Program",
        "M1030 — Network Segmentation (strict inter-zone firewall rules)",
        "M1050 — Exploit Protection",
        "M1051 — Update Software",
        "M1019 — Threat Intelligence Program",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=8.5,
))

_reg(Technique(
    id="T1021", name="Remote Services",
    tactic_ids=["TA0008"],
    url="https://attack.mitre.org/techniques/T1021/",
    description="Adversaries use valid accounts to log into services that accept remote connections (SSH, RDP, web admin panels). Weak or stolen credentials enable lateral movement across the environment.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.IAAS],
    data_sources=["Logon Session: Logon Session Creation", "Network Traffic: Network Connection Creation", "Network Traffic: Network Traffic Flow"],
    detection="Monitor for lateral authentication to internal services originating from compromised web servers.",
    mitigations=[
        "M1032 — Multi-factor Authentication",
        "M1035 — Limit Access to Resource Over Network",
        "M1030 — Network Segmentation",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION],
    severity_weight=7.0,
))

# ── TA0009 Collection ────────────────────────────────────────────

_reg(Technique(
    id="T1185", name="Browser Session Hijacking",
    tactic_ids=["TA0009"],
    url="https://attack.mitre.org/techniques/T1185/",
    description="Adversaries exploit web browsers (through XSS, browser extensions, or injected scripts) to hijack active sessions, intercept credentials, and exfiltrate data from authenticated web applications.",
    platforms=[Platform.WINDOWS, Platform.LINUX, Platform.MACOS],
    data_sources=["Logon Session: Logon Session Creation", "Process: Process Access"],
    detection="Monitor browser-side for injected scripts. Implement Sub-Resource Integrity (SRI). Detect session anomalies (IP change, user-agent change mid-session).",
    mitigations=[
        "M1017 — User Training",
        "M1018 — User Account Management",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS],
    severity_weight=7.5,
))

_reg(Technique(
    id="T1530", name="Data from Cloud Storage",
    tactic_ids=["TA0009"],
    url="https://attack.mitre.org/techniques/T1530/",
    description="Adversaries access data from cloud storage (S3 buckets, Azure Blobs, GCS) using credentials or tokens obtained through SSRF to cloud metadata endpoints or misconfigured IAM policies.",
    platforms=[Platform.IAAS, Platform.SAAS],
    data_sources=["Cloud Storage: Cloud Storage Access", "Cloud Storage: Cloud Storage Enumeration"],
    detection="Enable cloud storage access logging. Alert on unusual access patterns (bulk downloads, access from new IPs, access to sensitive prefixes).",
    mitigations=[
        "M1041 — Encrypt Sensitive Information",
        "M1022 — Restrict File and Directory Permissions (bucket policies)",
        "M1037 — Filter Network Traffic (block SSRF to metadata)",
        "M1032 — Multi-factor Authentication",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=7.5,
))

_reg(Technique(
    id="T1213", name="Data from Information Repositories",
    tactic_ids=["TA0009"],
    url="https://attack.mitre.org/techniques/T1213/",
    description="Adversaries leverage access to information repositories (databases, intranets, wikis, collaboration platforms) to collect valuable data. SQL injection provides direct database access.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS, Platform.IAAS, Platform.GWS, Platform.OFFICE],
    data_sources=["Application Log: Application Log Content", "Logon Session: Logon Session Creation"],
    detection="Monitor for bulk data extraction from databases. Alert on SQL queries returning large result sets outside normal application patterns.",
    mitigations=[
        "M1017 — User Training",
        "M1018 — User Account Management",
        "M1047 — Audit (database access logging)",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=7.0,
))

_reg(Technique(
    id="T1005", name="Data from Local System",
    tactic_ids=["TA0009"],
    url="https://attack.mitre.org/techniques/T1005/",
    description="Adversaries search local system sources such as file systems, configuration files, and application data for sensitive information. Path traversal and LFI expose local files to remote attackers.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["Command: Command Execution", "File: File Access"],
    detection="Monitor file-access patterns from web server processes. Alert on access to sensitive paths (/etc/passwd, web.config, .env files).",
    mitigations=[
        "M1057 — Data Loss Prevention",
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=6.5,
))

# ── TA0011 Command and Control ───────────────────────────────────

_reg(Technique(
    id="T1071", name="Application Layer Protocol",
    tactic_ids=["TA0011"],
    url="https://attack.mitre.org/techniques/T1071/",
    description="Adversaries communicate using OSI application-layer protocols (HTTP, HTTPS, DNS) to blend in with normal traffic. Injected scripts may beacon to C2 servers over standard web protocols.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection="Inspect outbound HTTP traffic for beaconing patterns (periodic requests, encoded payloads). Use DNS analytics to detect DNS-over-HTTPS C2 tunnels.",
    mitigations=[
        "M1031 — Network Intrusion Prevention",
        "M1030 — Network Segmentation",
    ],
    kill_chain=[KillChainPhase.C2],
    severity_weight=6.0,
))

_reg(Technique(
    id="T1071.001", name="Application Layer Protocol: Web Protocols",
    tactic_ids=["TA0011"],
    url="https://attack.mitre.org/techniques/T1071/001/",
    description="Adversaries use HTTP/HTTPS for command and control. XSS payloads can exfiltrate data by creating image tags or fetch requests to attacker-controlled servers.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection="Monitor for data exfiltration via image tags, fetch/XHR to external domains. Implement CSP connect-src directives to restrict outbound connections.",
    mitigations=[
        "M1031 — Network Intrusion Prevention",
        "M1030 — Network Segmentation",
    ],
    kill_chain=[KillChainPhase.C2],
    severity_weight=6.5,
    is_subtechnique=True, parent_id="T1071",
))

_reg(Technique(
    id="T1105", name="Ingress Tool Transfer",
    tactic_ids=["TA0011"],
    url="https://attack.mitre.org/techniques/T1105/",
    description="Adversaries transfer tools or payloads into the victim environment from an external system. File upload vulnerabilities and command injection enable delivering post-exploitation tools to compromised web servers.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["File: File Creation", "Network Traffic: Network Connection Creation", "Network Traffic: Network Traffic Content"],
    detection="Monitor file creation events in web-accessible directories. Alert on executable file uploads. Implement file-type validation and upload sandboxing.",
    mitigations=[
        "M1031 — Network Intrusion Prevention",
        "M1037 — Filter Network Traffic",
    ],
    kill_chain=[KillChainPhase.INSTALLATION, KillChainPhase.C2],
    severity_weight=7.0,
))

# ── TA0010 Exfiltration ─────────────────────────────────────────

_reg(Technique(
    id="T1041", name="Exfiltration Over C2 Channel",
    tactic_ids=["TA0010"],
    url="https://attack.mitre.org/techniques/T1041/",
    description="Adversaries exfiltrate data over the C2 channel — XSS payloads send stolen cookies and form data to attacker servers using the same HTTP connection.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Command: Command Execution", "File: File Access", "Network Traffic: Network Connection Creation", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection="Monitor for unexpected outbound data transfers. Implement Data Loss Prevention (DLP) policies. Inspect CSP violation reports for data-exfiltration attempts.",
    mitigations=[
        "M1031 — Network Intrusion Prevention",
        "M1057 — Data Loss Prevention",
        "M1030 — Network Segmentation",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=7.0,
))

_reg(Technique(
    id="T1048", name="Exfiltration Over Alternative Protocol",
    tactic_ids=["TA0010"],
    url="https://attack.mitre.org/techniques/T1048/",
    description="Adversaries exfiltrate data using protocols other than the C2 channel — DNS exfiltration, ICMP tunnelling, or out-of-band HTTP requests from exploited SQL injection (DNS-based SQLi).",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.NETWORK],
    data_sources=["Command: Command Execution", "File: File Access", "Network Traffic: Network Connection Creation", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"],
    detection="Monitor for unusual DNS query volumes. Detect DNS queries with encoded data in subdomains. Alert on outbound ICMP traffic from web servers.",
    mitigations=[
        "M1057 — Data Loss Prevention",
        "M1030 — Network Segmentation",
        "M1031 — Network Intrusion Prevention",
        "M1037 — Filter Network Traffic",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=6.5,
))

# ── TA0040 Impact ────────────────────────────────────────────────

_reg(Technique(
    id="T1565", name="Data Manipulation",
    tactic_ids=["TA0040"],
    url="https://attack.mitre.org/techniques/T1565/",
    description="Adversaries manipulate data to undermine integrity. SQL injection enables direct database modifications; stored XSS alters page content served to users.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.SAAS],
    data_sources=["File: File Creation", "File: File Deletion", "File: File Modification", "Process: OS API Execution"],
    detection="Implement database audit logging. Monitor for unauthorized UPDATE/DELETE SQL statements. Deploy file integrity monitoring on critical assets.",
    mitigations=[
        "M1041 — Encrypt Sensitive Information",
        "M1029 — Remote Data Storage",
        "M1030 — Network Segmentation",
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=8.0,
))

_reg(Technique(
    id="T1565.001", name="Data Manipulation: Stored Data Manipulation",
    tactic_ids=["TA0040"],
    url="https://attack.mitre.org/techniques/T1565/001/",
    description="Adversaries manipulate stored data (database records, files) to affect business processes. SQL injection is the primary vector for modifying, inserting, or deleting application data at scale.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["File: File Creation", "File: File Deletion", "File: File Modification"],
    detection="Enable database transaction logging with change-data-capture. Monitor for bulk UPDATE/DELETE/DROP statements. Implement row-level security and least-privilege database accounts.",
    mitigations=[
        "M1041 — Encrypt Sensitive Information",
        "M1029 — Remote Data Storage (off-site backups)",
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=8.5,
    is_subtechnique=True, parent_id="T1565",
))

_reg(Technique(
    id="T1565.002", name="Data Manipulation: Transmitted Data Manipulation",
    tactic_ids=["TA0040"],
    url="https://attack.mitre.org/techniques/T1565/002/",
    description="Adversaries manipulate data in transit between systems. Man-in-the-middle attacks on unencrypted channels allow modification of requests and responses, injecting malicious content.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS],
    data_sources=["Network Traffic: Network Traffic Content", "Process: OS API Execution"],
    detection="Enforce end-to-end TLS. Monitor for certificate-related anomalies. Implement HSTS preloading.",
    mitigations=[
        "M1041 — Encrypt Sensitive Information (TLS everywhere)",
    ],
    kill_chain=[KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS],
    severity_weight=7.0,
    is_subtechnique=True, parent_id="T1565",
))

_reg(Technique(
    id="T1499", name="Endpoint Denial of Service",
    tactic_ids=["TA0040"],
    url="https://attack.mitre.org/techniques/T1499/",
    description="Adversaries exhaust system resources to deny service. Heavy SQL queries from injection, resource-intensive SSRF requests, or ReDoS patterns can cause application-level denial of service.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.IAAS, Platform.AZURE, Platform.GWS, Platform.OFFICE, Platform.SAAS],
    data_sources=["Application Log: Application Log Content", "Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow", "Sensor Health: Host Status"],
    detection="Monitor for slow-query patterns and resource exhaustion indicators. Implement request rate limiting and query timeouts.",
    mitigations=[
        "M1037 — Filter Network Traffic",
        "M1030 — Network Segmentation",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=6.0,
))

_reg(Technique(
    id="T1491", name="Defacement",
    tactic_ids=["TA0040"],
    url="https://attack.mitre.org/techniques/T1491/",
    description="Adversaries modify visual content to deliver messaging, intimidate, or claim credit. Stored XSS and SQL injection can alter web-page content visible to all users.",
    platforms=[Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.IAAS],
    data_sources=["Application Log: Application Log Content", "File: File Creation", "File: File Modification", "Network Traffic: Network Traffic Content"],
    detection="Implement file integrity monitoring on web content. Monitor for unexpected DOM changes in client-side monitoring. Deploy Content-Security-Policy to prevent inline script execution.",
    mitigations=[
        "M1053 — Data Backup",
        "M1022 — Restrict File and Directory Permissions",
    ],
    kill_chain=[KillChainPhase.ACTIONS],
    severity_weight=5.5,
))


# ═══════════════════════════════════════════════════════════════════
#  3.  BACKWARD-COMPATIBLE EXPORTS
# ═══════════════════════════════════════════════════════════════════

# Legacy flat dict consumed by app.py `GET /api/mitre` and report_exporter.
# Now richer — includes platforms, data_sources, detection, mitigations, kill_chain.
MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    tid: {
        "name": tech.name,
        "tactic": tech.primary_tactic,
        "tactic_id": tech.primary_tactic_id,
        "tactics": [{"id": t, "name": TACTICS[t].name} for t in tech.tactic_ids if t in TACTICS],
        "url": tech.url,
        "description": tech.description,
        "platforms": [p.value if hasattr(p, 'value') else p for p in tech.platforms],
        "data_sources": tech.data_sources,
        "detection": tech.detection,
        "mitigations": tech.mitigations,
        "kill_chain": [k.value if hasattr(k, 'value') else k for k in tech.kill_chain],
        "severity_weight": tech.severity_weight,
        "is_subtechnique": tech.is_subtechnique,
        "parent_id": tech.parent_id,
    }
    for tid, tech in _DB.items()
}


# ═══════════════════════════════════════════════════════════════════
#  4.  VULNERABILITY → TECHNIQUE MAPPING  (weighted, multi-pattern)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class _MappingRule:
    """One keyword → technique association with a confidence level."""
    keyword: str
    technique_ids: list[str]
    confidence: Confidence = Confidence.HIGH


_VULN_RULES: list[_MappingRule] = [
    # ── SQL Injection ───────────────────────────────────────────
    _MappingRule("sql injection",             ["T1190", "T1505.003", "T1565.001", "T1213", "T1059"]),
    _MappingRule("sqli",                      ["T1190", "T1505.003", "T1565.001", "T1213"]),
    _MappingRule("sql",                       ["T1190", "T1565.001"],                        Confidence.MEDIUM),
    _MappingRule("blind sql",                 ["T1190", "T1565.001", "T1048"]),
    _MappingRule("union select",              ["T1190", "T1213", "T1565.001"]),

    # ── Cross-Site Scripting ────────────────────────────────────
    _MappingRule("xss",                       ["T1189", "T1059.007", "T1539", "T1185", "T1071.001"]),
    _MappingRule("cross-site scripting",      ["T1189", "T1059.007", "T1539", "T1185", "T1071.001"]),
    _MappingRule("reflected xss",             ["T1189", "T1059.007", "T1539"]),
    _MappingRule("stored xss",               ["T1189", "T1059.007", "T1539", "T1185", "T1546", "T1491"]),
    _MappingRule("dom xss",                   ["T1059.007", "T1185"]),
    _MappingRule("dom-based",                 ["T1059.007", "T1185"],                        Confidence.MEDIUM),
    _MappingRule("script injection",          ["T1059.007", "T1189"]),

    # ── SSRF ────────────────────────────────────────────────────
    _MappingRule("ssrf",                      ["T1190", "T1210", "T1530", "T1580", "T1555"]),
    _MappingRule("server-side request",       ["T1190", "T1210", "T1530", "T1580"]),

    # ── IDOR / Broken Access Control ────────────────────────────
    _MappingRule("idor",                      ["T1190", "T1068", "T1548"]),
    _MappingRule("insecure direct object",    ["T1190", "T1068", "T1548"]),
    _MappingRule("broken access",             ["T1068", "T1548", "T1078"]),
    _MappingRule("authorization bypass",      ["T1068", "T1548"]),
    _MappingRule("privilege escalation",      ["T1068", "T1548"]),
    _MappingRule("forced browsing",           ["T1068", "T1083"]),

    # ── Open Redirect ──────────────────────────────────────────
    _MappingRule("open redirect",             ["T1583.006", "T1189"]),
    _MappingRule("redirect",                  ["T1583.006"],                                 Confidence.LOW),
    _MappingRule("subdomain takeover",        ["T1584.001"]),


    # ── Command Injection ──────────────────────────────────────
    _MappingRule("command injection",         ["T1059", "T1190", "T1505.003"]),
    _MappingRule("os command",                ["T1059", "T1190"]),
    _MappingRule("rce",                       ["T1059", "T1190", "T1505.003", "T1105"]),
    _MappingRule("remote code execution",     ["T1059", "T1190", "T1505.003", "T1105"]),

    # ── File Inclusion / Path Traversal ───────────────────────
    _MappingRule("path traversal",            ["T1083", "T1005", "T1190"]),
    _MappingRule("file inclusion",            ["T1083", "T1005", "T1190"]),
    _MappingRule("lfi",                       ["T1083", "T1005"]),
    _MappingRule("directory traversal",       ["T1083", "T1005"]),

    # ── Authentication / Session ───────────────────────────────
    _MappingRule("default credential",        ["T1078.001", "T1078"]),
    _MappingRule("weak password",             ["T1110", "T1110.001"]),
    _MappingRule("brute force",               ["T1110", "T1110.001"]),
    _MappingRule("session fixation",          ["T1539", "T1185"]),
    _MappingRule("session hijack",            ["T1539", "T1185"]),
    _MappingRule("credential",                ["T1555", "T1078"],                            Confidence.MEDIUM),
    _MappingRule("secrets detection",          ["T1552.001", "T1555"]),
    _MappingRule("hardcoded secret",           ["T1552.001", "T1555"]),
    _MappingRule("exposed secret",             ["T1552.001", "T1555"]),
    _MappingRule("cloud misconfiguration",     ["T1530", "T1552.005"]),
    _MappingRule("cloud storage",              ["T1530"]),
    _MappingRule("s3 bucket",                  ["T1530"]),
    _MappingRule("metadata leakage",           ["T1552.005"]),



    # ── Security Headers ───────────────────────────────────────
    _MappingRule("content-security-policy",   ["T1059.007", "T1189", "T1562"]),
    _MappingRule("strict-transport-security", ["T1557", "T1565.002"]),
    _MappingRule("strict transport",          ["T1557", "T1565.002"]),
    _MappingRule("x-frame-options",           ["T1189", "T1185", "T1562"]),
    _MappingRule("clickjacking",              ["T1189", "T1185"]),
    _MappingRule("x-content-type",            ["T1036", "T1203", "T1562"]),
    _MappingRule("mime sniff",                ["T1036", "T1203"]),
    _MappingRule("x-xss-protection",          ["T1059.007", "T1562"]),
    _MappingRule("referrer-policy",           ["T1082", "T1562"]),
    _MappingRule("permissions-policy",        ["T1082", "T1562"]),
    _MappingRule("feature-policy",            ["T1082", "T1562"]),
    _MappingRule("missing header",            ["T1562"],                                     Confidence.LOW),
    _MappingRule("security header",           ["T1562"],                                     Confidence.LOW),

    # ── Information Disclosure ─────────────────────────────────
    _MappingRule("server version",            ["T1082", "T1046", "T1592"]),
    _MappingRule("version disclosure",        ["T1082", "T1592"]),
    _MappingRule("information disclosure",    ["T1082", "T1592", "T1005"]),
    _MappingRule("error message",             ["T1082"],                                     Confidence.MEDIUM),
    _MappingRule("stack trace",               ["T1082"],                                     Confidence.MEDIUM),
    _MappingRule("debug",                     ["T1082"],                                     Confidence.LOW),

    # ── Cryptographic Failures ─────────────────────────────────
    _MappingRule("tls",                       ["T1557", "T1565.002"],                        Confidence.MEDIUM),
    _MappingRule("ssl",                       ["T1557", "T1565.002"],                        Confidence.MEDIUM),
    _MappingRule("certificate",               ["T1557"],                                     Confidence.LOW),
    _MappingRule("weak cipher",               ["T1557"]),
    _MappingRule("cleartext",                 ["T1557", "T1041"]),
    _MappingRule("http://",                   ["T1557"],                                     Confidence.LOW),

    # ── Denial of Service ──────────────────────────────────────
    _MappingRule("denial of service",         ["T1499"]),
    _MappingRule("redos",                     ["T1499"]),
    _MappingRule("resource exhaust",          ["T1499"]),

    # ── File Upload ────────────────────────────────────────────
    _MappingRule("file upload",               ["T1505.003", "T1105", "T1190"]),
    _MappingRule("unrestricted upload",       ["T1505.003", "T1105"]),

    # ── CORS ───────────────────────────────────────────────────
    _MappingRule("cors",                      ["T1189", "T1557"],                            Confidence.MEDIUM),

    # ── Deserialization ────────────────────────────────────────
    _MappingRule("deserialization",           ["T1059", "T1190"]),

    # ── XML External Entity ────────────────────────────────────
    _MappingRule("xxe",                       ["T1190", "T1005"]),
    _MappingRule("xml external",              ["T1190", "T1005"]),
]


# ═══════════════════════════════════════════════════════════════════
#  5.  MATCHING ENGINE
# ═══════════════════════════════════════════════════════════════════

def _match_rules(text: str) -> list[tuple[str, Confidence]]:
    """Return deduplicated (technique_id, confidence) pairs for *text*.

    Matches are accumulated across ALL matching rules (not first-match),
    keeping the highest confidence for each technique.
    """
    text_lower = text.lower()
    technique_conf: dict[str, Confidence] = {}
    conf_rank = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}

    for rule in _VULN_RULES:
        if rule.keyword in text_lower:
            for tid in rule.technique_ids:
                if tid in _DB:
                    existing = technique_conf.get(tid)
                    if existing is None or conf_rank[rule.confidence] > conf_rank[existing]:
                        technique_conf[tid] = rule.confidence

    return list(technique_conf.items())


def get_mitre_for_finding(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Return enriched MITRE ATT&CK technique dicts for a given finding."""
    search_text = " ".join(filter(None, [
        finding.get("title", ""),
        finding.get("type", ""),
        finding.get("module", ""),
        finding.get("detail", ""),
    ]))

    matches = _match_rules(search_text)
    if not matches:
        # Fallback: generic web exploit
        matches = [("T1190", Confidence.LOW)]

    result = []
    for tid, conf in matches:
        tech = _DB.get(tid)
        if tech:
            ref = tech.to_ref()
            ref["confidence"] = conf.value
            result.append(ref)

    # Sort by severity_weight descending for consistent display order
    result.sort(key=lambda r: r.get("severity_weight", 0), reverse=True)
    return result


# ═══════════════════════════════════════════════════════════════════
#  6.  ENRICHMENT FUNCTIONS  (backward-compatible public API)
# ═══════════════════════════════════════════════════════════════════

def enrich_finding_mitre(finding: dict[str, Any]) -> dict[str, Any]:
    """Add MITRE ATT&CK mapping fields to a finding dict.

    Attaches:
      - mitre_attack:   list of matched techniques (with confidence)
      - mitre_tactics:  deduplicated list of tactic names covered
      - mitre_kill_chain: deduplicated kill-chain phases in order
    """
    techniques = get_mitre_for_finding(finding)

    finding["mitre_attack"] = [
        {
            "technique": t["technique_id"],
            "name": t["name"],
            "tactic": t["tactic"],
            "tactic_id": t["tactic_id"],
            "tactics": t.get("tactics", []),
            "url": t["url"],
            "confidence": t.get("confidence", "high"),
            "severity_weight": t.get("severity_weight", 5.0),
            "detection": t.get("detection", ""),
            "mitigations": t.get("mitigations", []),
            "platforms": t.get("platforms", []),
            "kill_chain": t.get("kill_chain", []),
        }
        for t in techniques
    ]

    # Convenience aggregations
    seen_tactics: dict[str, None] = {}
    seen_phases: dict[str, None] = {}
    for t in techniques:
        for tac in t.get("tactics", []):
            seen_tactics[tac["name"]] = None
        for phase in t.get("kill_chain", []):
            seen_phases[phase] = None

    finding["mitre_tactics"] = list(seen_tactics.keys())
    finding["mitre_kill_chain"] = list(seen_phases.keys())
    return finding


def enrich_findings_mitre(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Batch-enrich all findings with MITRE ATT&CK data."""
    for f in findings:
        enrich_finding_mitre(f)
    return findings


# ═══════════════════════════════════════════════════════════════════
#  7.  ANALYSIS & BREAKDOWN FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def build_mitre_breakdown(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a MITRE ATT&CK breakdown grouped by tactic → techniques → findings.

    Returns a list sorted by tactic ordinal (ATT&CK matrix column order).
    """
    tactic_map: dict[str, dict[str, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(lambda: {
            "name": "", "tactic": "", "tactic_id": "", "url": "",
            "confidence": "low", "severity_weight": 0,
            "detection": "", "mitigations": [],
            "finding_ids": [], "finding_titles": [],
            "finding_evidence": [],
        }))

    conf_rank = {"high": 3, "medium": 2, "low": 1}

    for f in findings:
        fid = f.get("id", "")
        ftitle = f.get("title", f.get("type", ""))
        for mt in f.get("mitre_attack", []):
            tid = mt["technique"]
            # Handle multi-tactic techniques
            for tac_info in mt.get("tactics", [{"id": mt.get("tactic_id", ""), "name": mt.get("tactic", "")}]):
                tactic_name = tac_info["name"]
                entry = tactic_map[tactic_name][tid]
                entry["name"] = mt["name"]
                entry["tactic"] = tactic_name
                entry["tactic_id"] = tac_info["id"]
                entry["url"] = mt["url"]
                entry["detection"] = mt.get("detection", "")
                entry["mitigations"] = mt.get("mitigations", [])
                entry["severity_weight"] = max(entry["severity_weight"], mt.get("severity_weight", 0))
                # Keep highest confidence
                new_conf = mt.get("confidence", "low")
                if conf_rank.get(new_conf, 0) > conf_rank.get(entry["confidence"], 0):
                    entry["confidence"] = new_conf
                if fid not in entry["finding_ids"]:
                    entry["finding_ids"].append(fid)
                if ftitle and ftitle not in entry["finding_titles"]:
                    entry["finding_titles"].append(ftitle)
                if len(entry["finding_evidence"]) < 5:
                    entry["finding_evidence"].append({
                        "url": f.get("url", f.get("path", "")),
                        "detail": (f.get("detail", "") or "")[:120],
                        "severity": f.get("severity", "Low"),
                    })

    # Sort by ATT&CK tactic ordinal
    tactic_order = {tac.name: tac.ordinal for tac in TACTICS.values()}

    result = []
    for tactic in sorted(tactic_map, key=lambda t: tactic_order.get(t, 99)):
        tactic_id = ""
        techniques = []
        for tid, info in sorted(tactic_map[tactic].items(), key=lambda x: -x[1]["severity_weight"]):
            tactic_id = info["tactic_id"]
            techniques.append({
                "technique_id": tid,
                "name": info["name"],
                "url": info["url"],
                "confidence": info["confidence"],
                "severity_weight": info["severity_weight"],
                "detection": info["detection"],
                "mitigations": info["mitigations"],
                "finding_count": len(info["finding_ids"]),
                "finding_ids": info["finding_ids"],
                "finding_titles": info["finding_titles"],
                "finding_evidence": info["finding_evidence"],
            })
        result.append({
            "tactic": tactic,
            "tactic_id": tactic_id,
            "technique_count": len(techniques),
            "techniques": techniques,
        })
    return result


def build_attack_paths(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Construct potential attack paths from correlated findings.

    Groups findings by kill-chain phase and builds ordered attack
    chains that an adversary could follow based on detected vulns.
    """
    kc_order = [p.value for p in KillChainPhase]
    phase_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for f in findings:
        phases = f.get("mitre_kill_chain", [])
        for phase in phases:
            phase_findings[phase].append({
                "id": f.get("id", ""),
                "title": f.get("title", f.get("type", "")),
                "severity": f.get("severity", "Low"),
                "techniques": [mt["technique"] for mt in f.get("mitre_attack", [])],
            })

    paths = []
    for phase in kc_order:
        if phase in phase_findings:
            paths.append({
                "phase": phase,
                "phase_index": kc_order.index(phase),
                "finding_count": len(phase_findings[phase]),
                "findings": phase_findings[phase],
            })

    return paths


def compute_matrix_coverage(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute ATT&CK matrix coverage statistics.

    Returns tactic-level coverage data suitable for heatmap rendering.
    """
    total_techniques_per_tactic: dict[str, set[str]] = defaultdict(set)
    for tid, tech in _DB.items():
        for tac_id in tech.tactic_ids:
            if tac_id in TACTICS:
                total_techniques_per_tactic[TACTICS[tac_id].name].add(tid)

    hit_techniques_per_tactic: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        for mt in f.get("mitre_attack", []):
            for tac_info in mt.get("tactics", [{"name": mt.get("tactic", "")}]):
                hit_techniques_per_tactic[tac_info["name"]].add(mt["technique"])

    tactic_order = {tac.name: tac.ordinal for tac in TACTICS.values()}
    coverage = []
    for tac_name in sorted(TACTICS.values(), key=lambda t: t.ordinal):
        total = len(total_techniques_per_tactic.get(tac_name.name, set()))
        hit = len(hit_techniques_per_tactic.get(tac_name.name, set()))
        pct = round((hit / total * 100) if total > 0 else 0, 1)
        coverage.append({
            "tactic": tac_name.name,
            "tactic_id": tac_name.id,
            "ordinal": tac_name.ordinal,
            "total_techniques": total,
            "detected_techniques": hit,
            "coverage_pct": pct,
            "detected_ids": sorted(hit_techniques_per_tactic.get(tac_name.name, set())),
        })

    total_all = sum(c["total_techniques"] for c in coverage)
    detected_all = sum(c["detected_techniques"] for c in coverage)

    return {
        "matrix_version": "ATT&CK Enterprise v16.1",
        "total_tactics": len(TACTICS),
        "tactics_with_hits": sum(1 for c in coverage if c["detected_techniques"] > 0),
        "total_techniques_in_db": len(_DB),
        "total_technique_hits": detected_all,
        "overall_coverage_pct": round((detected_all / total_all * 100) if total_all > 0 else 0, 1),
        "tactics": coverage,
    }


# ── Full reference for UI display ──────────────────────────────────

def get_all_techniques() -> dict[str, dict[str, Any]]:
    """Return the full MITRE technique database for reference display."""
    return MITRE_TECHNIQUES


def get_all_tactics() -> list[dict[str, Any]]:
    """Return ordered list of all ATT&CK Enterprise tactics."""
    return [
        {
            "id": tac.id,
            "name": tac.name,
            "shortname": tac.shortname,
            "ordinal": tac.ordinal,
            "description": tac.description,
            "url": f"https://attack.mitre.org/tactics/{tac.id}/",
        }
        for tac in sorted(TACTICS.values(), key=lambda t: t.ordinal)
    ]


def build_threat_narrative(
    target: str,
    findings: list[dict[str, Any]],
    breakdown: list[dict[str, Any]],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    """Generate a target-personalised threat intelligence narrative.

    Produces a rich-text summary referencing the actual hostname,
    detected vulnerability types, matched ATT&CK techniques,
    kill-chain coverage, and affected endpoints.
    """
    from urllib.parse import urlparse

    hostname = urlparse(target).hostname or target

    total = len(findings)
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    vuln_types: set[str] = set()
    affected_urls: set[str] = set()

    for f in findings:
        sev = f.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["Info"] += 1
        vuln_types.add(f.get("type", f.get("module", "unknown")))
        url = f.get("url", f.get("path", ""))
        if url:
            affected_urls.add(url)

    # Determine overall risk level
    if sev_counts["Critical"] > 0:
        risk_level, risk_color = "CRITICAL", "critical"
    elif sev_counts["High"] > 0:
        risk_level, risk_color = "HIGH", "high"
    elif sev_counts["Medium"] > 0:
        risk_level, risk_color = "ELEVATED", "medium"
    else:
        risk_level, risk_color = "LOW", "low"

    tactics_hit = coverage.get("tactics_with_hits", 0)
    total_tactics = coverage.get("total_tactics", 14)
    tech_hits = coverage.get("total_technique_hits", 0)

    # ── Build narrative sentences from actual scan data ──────────
    sentences: list[str] = []

    sentences.append(
        f"Analysis of <strong>{hostname}</strong> identified "
        f"<strong>{total} security finding{'s' if total != 1 else ''}</strong> "
        f"mapping to <strong>{tech_hits} MITRE ATT&amp;CK technique{'s' if tech_hits != 1 else ''}</strong> "
        f"across <strong>{tactics_hit}/{total_tactics}</strong> Enterprise tactics."
    )

    # Per-vulnerability-type contextual descriptions
    _type_narratives: dict[str, str] = {
        "xss": (
            f"Cross-Site Scripting (XSS) vulnerabilities were detected on {hostname}, "
            "enabling adversaries to execute arbitrary JavaScript in victim browsers "
            "(T1059.007), steal session cookies (T1539), and perform drive-by "
            "compromises (T1189)."
        ),
        "sqli": (
            f"SQL Injection flaws were found on {hostname}, allowing adversaries to "
            "exploit the public-facing application (T1190) for data exfiltration "
            "(T1048) and data manipulation (T1565.001)."
        ),
        "header": (
            f"Missing security headers on {hostname} impair built-in browser defenses "
            "(T1562), enabling MIME-sniffing attacks (T1036), clickjacking (T1185), "
            "and man-in-the-middle interception (T1557)."
        ),
        "ssrf": (
            f"Server-Side Request Forgery (SSRF) on {hostname} could allow adversaries "
            "to access internal services (T1210), cloud metadata (T1580), and "
            "credential stores (T1555)."
        ),
        "idor": (
            f"Insecure Direct Object References on {hostname} enable privilege "
            "escalation (T1068) and unauthorised data access through broken access "
            "controls (T1548)."
        ),
        "redirect": (
            f"Open redirect vulnerabilities on {hostname} can be weaponised for "
            "phishing campaigns by lending domain trust to malicious infrastructure "
            "(T1583.006)."
        ),
    }

    for vtype in vuln_types:
        vl = vtype.lower()
        for key, desc in _type_narratives.items():
            if key in vl:
                sentences.append(desc)
                break

    # Kill-chain span narrative
    kc_phases: set[str] = set()
    for f in findings:
        kc_phases.update(f.get("mitre_kill_chain", []))
    if len(kc_phases) >= 3:
        sentences.append(
            f"The detected vulnerabilities on {hostname} span "
            f"<strong>{len(kc_phases)} kill-chain phases</strong>, indicating that "
            "an adversary could chain these findings into a multi-stage attack \u2014 "
            "from initial reconnaissance through exploitation to actions on objectives."
        )

    # Affected endpoint count
    if len(affected_urls) > 3:
        sentences.append(
            f"<strong>{len(affected_urls)} distinct endpoints</strong> on {hostname} "
            "were identified as vulnerable, expanding the overall attack surface."
        )

    # High-value tactic callout
    high_value = ["Credential Access", "Lateral Movement", "Impact"]
    detected_hv = [
        tg["tactic"] for tg in breakdown if tg["tactic"] in high_value
    ]
    if detected_hv:
        sentences.append(
            f"Notably, findings map to high-impact tactics including "
            f"<strong>{', '.join(detected_hv)}</strong>, which represent advanced "
            "adversary objectives in the kill chain."
        )

    return {
        "target": target,
        "hostname": hostname,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "narrative": " ".join(sentences),
        "finding_count": total,
        "severity_breakdown": sev_counts,
        "vuln_types": sorted(vuln_types),
        "affected_endpoint_count": len(affected_urls),
        "tactics_covered": tactics_hit,
        "techniques_matched": tech_hits,
    }
