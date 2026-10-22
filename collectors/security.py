"""
Coletor de controles de Security Hardening:
FileVault, Application Firewall, Gatekeeper, SIP e atualizações pendentes.

Nenhum dos comandos abaixo exige root para LEITURA de status.
As funções parse_* são puras (sem I/O) para facilitar testes unitários.
"""

import logging
import re
from typing import Any, Callable, Dict, Iterable, List, Optional

from collectors.utils import make_section, read_plist, run_command, safe_collect

logger = logging.getLogger("macfleet.collectors.security")

FDESETUP = "/usr/bin/fdesetup"
SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
SPCTL = "/usr/sbin/spctl"
CSRUTIL = "/usr/bin/csrutil"
SOFTWAREUPDATE = "/usr/sbin/softwareupdate"

ALF_PLIST = "/Library/Preferences/com.apple.alf.plist"
SWU_PLIST = "/Library/Preferences/com.apple.SoftwareUpdate.plist"

FIREWALL_STATES = {0: "off", 1: "on", 2: "block_all"}


# --------------------------------------------------------------------------- #
# Parsers (puros)
# --------------------------------------------------------------------------- #
def parse_filevault_status(output: str) -> Dict[str, Any]:
    """
    Exemplos de saída do `fdesetup status`:
      FileVault is On.
      FileVault is Off.
      FileVault is Off, but will be enabled after the next restart.
      Encryption in progress: Percent completed = 42.3
      Decryption in progress: Percent completed = 10.0
    """
    low = output.lower()
    state = "unknown"
    if "encryption in progress" in low:
        state = "encrypting"
    elif "decryption in progress" in low:
        state = "decrypting"
    elif "filevault is on" in low:
        state = "on"
    elif "filevault is off" in low:
        state = "off"

    progress = None
    match = re.search(r"percent completed\s*=\s*([\d.]+)", low)
    if match:
        progress = float(match.group(1))

    return {
        "state": state,
        "enabled": None if state == "unknown" else state == "on",
        "deferred_enablement_pending": ("deferred enablement" in low) or ("after the next restart" in low),
        "progress_percent": progress,
    }


def parse_firewall_globalstate(output: str) -> Optional[int]:
    """`socketfilterfw --getglobalstate` -> 'Firewall is enabled. (State = 1)'."""
    match = re.search(r"state\s*=\s*(\d)", output, re.IGNORECASE)
    if match:
        return int(match.group(1))
    low = output.lower()
    if "disabled" in low:
        return 0
    if "enabled" in low:
        return 1
    return None


def parse_on_off(output: str) -> Optional[bool]:
    """Interpreta saídas do tipo 'Stealth mode enabled' / 'Firewall stealth mode is on'."""
    low = output.lower()
    if re.search(r"\b(off|disabled)\b", low):
        return False
    if re.search(r"\b(on|enabled)\b", low):
        return True
    return None


def parse_gatekeeper(output: str) -> Optional[bool]:
    """`spctl --status` -> 'assessments enabled' | 'assessments disabled'."""
    low = output.lower()
    if "assessments disabled" in low:
        return False
    if "assessments enabled" in low:
        return True
    return None


def parse_sip_status(output: str) -> Dict[str, Any]:
    """
    `csrutil status`:
      System Integrity Protection status: enabled.
      System Integrity Protection status: disabled.
      System Integrity Protection status: unknown (Custom Configuration).
    """
    low = output.lower()
    state = "unknown"
    match = re.search(r"system integrity protection status:\s*([a-z]+)", low)
    if match:
        state = match.group(1)
    if "custom configuration" in low:
        state = "custom"
    return {"state": state, "enabled": None if state == "unknown" else state == "enabled"}


_TITLE_RE = re.compile(r"Title:\s*(.*?),\s*Version:", re.IGNORECASE)
_VERSION_RE = re.compile(r"Version:\s*([^,]+)", re.IGNORECASE)
_RECOMMENDED_RE = re.compile(r"Recommended:\s*(YES|NO)", re.IGNORECASE)
_ACTION_RE = re.compile(r"Action:\s*([A-Za-z]+)", re.IGNORECASE)


def parse_softwareupdate_list(output: str) -> List[Dict[str, Any]]:
    """
    Formato moderno (macOS 10.15+):
      * Label: macOS Sonoma 14.6.1-23G93
          Title: macOS Sonoma 14.6.1, Version: 14.6.1, Size: 1300000KiB, Recommended: YES, Action: restart,
    Formato legado (<= 10.14):
       * Safari12.1-12.1
          Safari (12.1), 63000K [recommended]
    """
    updates = []  # type: List[Dict[str, Any]]
    current = None  # type: Optional[Dict[str, Any]]
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("* Label:") or (line.startswith("* ") and ":" not in line[:8]):
            label = line.split("Label:", 1)[1].strip() if "Label:" in line else line[2:].strip()
            current = {"label": label, "title": label, "version": None,
                       "recommended": None, "restart_required": False}
            updates.append(current)
            continue
        if current is None:
            continue
        if line.lower().startswith("title:"):
            title = _TITLE_RE.search(line)
            version = _VERSION_RE.search(line)
            recommended = _RECOMMENDED_RE.search(line)
            action = _ACTION_RE.search(line)
            if title:
                current["title"] = title.group(1).strip()
            if version:
                current["version"] = version.group(1).strip()
            if recommended:
                current["recommended"] = recommended.group(1).upper() == "YES"
            if action:
                current["restart_required"] = action.group(1).lower() in ("restart", "shut")
        elif "[recommended]" in line.lower() or "[restart]" in line.lower():
            current["title"] = line.split(",")[0].strip()
            current["recommended"] = "[recommended]" in line.lower()
            current["restart_required"] = "[restart]" in line.lower()
    return updates


def is_security_update(update: Dict[str, Any], keywords: Iterable[str]) -> bool:
    text = "{} {}".format(update.get("label") or "", update.get("title") or "").lower()
    return any(k.lower() in text for k in keywords)


def _summarize_updates(updates: List[Dict[str, Any]], keywords: Iterable[str]) -> Dict[str, Any]:
    keywords = list(keywords)
    for upd in updates:
        upd["is_security"] = is_security_update(upd, keywords)
    return {
        "pending_total": len(updates),
        "pending_security": sum(1 for u in updates if u["is_security"]),
        "restart_required": any(u.get("restart_required") for u in updates),
        "updates": updates,
    }


# --------------------------------------------------------------------------- #
# Coletores
# --------------------------------------------------------------------------- #
def collect_filevault() -> Dict[str, Any]:
    res = run_command([FDESETUP, "status"])
    if not res.executed:
        return make_section("error", error=res.error, evidence=[res.evidence()], state="unknown", enabled=None)
    parsed = parse_filevault_status(res.output)
    if parsed["state"] == "unknown":
        return make_section("error", error="saída do fdesetup não reconhecida", evidence=[res.evidence()], **parsed)
    return make_section("ok", evidence=[res.evidence()], **parsed)


def collect_firewall() -> Dict[str, Any]:
    evidence = []
    state_code = None
    source = None

    res = run_command([SOCKETFILTERFW, "--getglobalstate"])
    evidence.append(res.evidence())
    if res.executed and res.output:
        state_code = parse_firewall_globalstate(res.output)
        source = "socketfilterfw"

    if state_code is None:  # Fallback: preferências do ALF (até macOS 14)
        alf = read_plist(ALF_PLIST)
        if alf and "globalstate" in alf:
            state_code = int(alf["globalstate"])
            source = ALF_PLIST

    stealth = None
    stealth_res = run_command([SOCKETFILTERFW, "--getstealthmode"])
    evidence.append(stealth_res.evidence())
    if stealth_res.executed and stealth_res.output:
        stealth = parse_on_off(stealth_res.output)

    if state_code is None:
        return make_section("error", error="não foi possível determinar o estado do firewall",
                            evidence=evidence, enabled=None, state="unknown", stealth_mode=stealth)
    return make_section(
        "ok",
        evidence=evidence,
        enabled=state_code in (1, 2),
        state=FIREWALL_STATES.get(state_code, "unknown"),
        state_code=state_code,
        stealth_mode=stealth,
        source=source,
    )


def collect_gatekeeper() -> Dict[str, Any]:
    res = run_command([SPCTL, "--status"])
    if not res.executed:
        return make_section("error", error=res.error, evidence=[res.evidence()], enabled=None)
    enabled = parse_gatekeeper(res.output)
    if enabled is None:
        return make_section("error", error="saída do spctl não reconhecida", evidence=[res.evidence()], enabled=None)
    return make_section("ok", evidence=[res.evidence()], enabled=enabled)


def collect_sip() -> Dict[str, Any]:
    res = run_command([CSRUTIL, "status"])
    if not res.executed:
        return make_section("error", error=res.error, evidence=[res.evidence()], state="unknown", enabled=None)
    parsed = parse_sip_status(res.output)
    if parsed["state"] == "unknown":
        return make_section("error", error="saída do csrutil não reconhecida", evidence=[res.evidence()], **parsed)
    return make_section("ok", evidence=[res.evidence()], **parsed)


def _collect_updates_cached(keywords: Iterable[str], note: Optional[str] = None) -> Dict[str, Any]:
    """Lê o cache local do Software Update (rápido, sem consulta à rede)."""
    prefs = read_plist(SWU_PLIST)
    if prefs is None:
        return make_section("error", error="cache do Software Update indisponível ({})".format(SWU_PLIST),
                            source="cache", pending_total=None, pending_security=None)
    updates = []
    for item in prefs.get("RecommendedUpdates", []) or []:
        name = item.get("Display Name") or item.get("Identifier") or "desconhecido"
        updates.append({
            "label": item.get("Identifier") or name,
            "title": name,
            "version": item.get("Display Version"),
            "recommended": True,
            "restart_required": None,
        })
    last_check = prefs.get("LastSuccessfulDate")
    summary = _summarize_updates(updates, keywords)
    fields = dict(summary)
    fields["source"] = "cache"
    fields["last_successful_check"] = last_check.isoformat() if hasattr(last_check, "isoformat") else last_check
    if note:
        fields["note"] = note
    return make_section("ok", **fields)


def collect_software_updates(mode: str, keywords: Iterable[str], timeout: int) -> Dict[str, Any]:
    """
    mode:
      live   -> `softwareupdate --list` (consulta o catálogo da Apple; pode levar minutos)
      cached -> lê /Library/Preferences/com.apple.SoftwareUpdate.plist
      skip   -> não coleta
    """
    if mode == "skip":
        return make_section("skipped", reason="coleta de atualizações desativada (--updates-mode skip)",
                            pending_total=None, pending_security=None)
    if mode == "cached":
        return _collect_updates_cached(keywords)

    res = run_command([SOFTWAREUPDATE, "--list", "--include-config-data"], timeout=timeout)
    if not res.executed:
        logger.warning("softwareupdate falhou (%s); usando cache local.", res.error)
        cached = _collect_updates_cached(keywords, note="fallback: softwareupdate falhou ({})".format(res.error))
        cached.setdefault("evidence", []).append(res.evidence())
        return cached

    output = res.output
    if "no new software available" in output.lower():
        updates = []  # type: List[Dict[str, Any]]
    else:
        updates = parse_softwareupdate_list(output)
        if not updates and res.returncode != 0:
            return make_section("error", error="softwareupdate retornou código {}".format(res.returncode),
                                evidence=[res.evidence()], pending_total=None, pending_security=None)

    fields = _summarize_updates(updates, keywords)
    fields["source"] = "softwareupdate"
    return make_section("ok", evidence=[res.evidence()], **fields)


def collect_security(updates_mode: str = "live",
                     security_keywords: Iterable[str] = (),
                     update_timeout: int = 300,
                     progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    def _p(msg: str) -> None:
        if progress:
            progress(msg)

    _p("FileVault (fdesetup)")
    filevault = safe_collect("filevault", collect_filevault)
    _p("Application Firewall (socketfilterfw)")
    firewall = safe_collect("firewall", collect_firewall)
    _p("Gatekeeper (spctl)")
    gatekeeper = safe_collect("gatekeeper", collect_gatekeeper)
    _p("System Integrity Protection (csrutil)")
    sip = safe_collect("sip", collect_sip)
    if updates_mode == "live":
        _p("Software Update (softwareupdate --list) — pode levar alguns minutos")
    else:
        _p("Software Update (modo: {})".format(updates_mode))
    updates = safe_collect("software_updates", collect_software_updates,
                           updates_mode, security_keywords, update_timeout)

    return {
        "filevault": filevault,
        "firewall": firewall,
        "gatekeeper": gatekeeper,
        "sip": sip,
        "software_updates": updates,
    }
