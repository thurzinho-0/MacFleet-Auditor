"""
Coletor de inventário e saúde operacional (ITAM / Health):
identificação do dispositivo, versão do macOS, armazenamento, usuário e uptime.
"""

import getpass
import grp
import json
import logging
import os
import platform
import pwd
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from collectors.utils import make_section, run_command, safe_collect

logger = logging.getLogger("macfleet.collectors.system")

SW_VERS = "/usr/bin/sw_vers"
SYSTEM_PROFILER = "/usr/sbin/system_profiler"
SCUTIL = "/usr/sbin/scutil"
DF = "/bin/df"
SYSCTL = "/usr/sbin/sysctl"
DSEDITGROUP = "/usr/sbin/dseditgroup"
STAT = "/usr/bin/stat"

BYTES_PER_GB = 1000 ** 3  # GB decimal, mesmo padrão exibido pelo Finder


# --------------------------------------------------------------------------- #
# Parsers (puros)
# --------------------------------------------------------------------------- #
_SW_VERS_KEYS = {
    "ProductName": "product_name",
    "ProductVersion": "product_version",
    "ProductVersionExtra": "product_version_extra",  # Rapid Security Response, ex.: (a)
    "BuildVersion": "build_version",
}


def parse_sw_vers(output: str) -> Dict[str, str]:
    data = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        mapped = _SW_VERS_KEYS.get(key.strip())
        if mapped:
            data[mapped] = value.strip()
    return data


def parse_hardware_json(text: str) -> Dict[str, Any]:
    data = json.loads(text)
    items = data.get("SPHardwareDataType") or [{}]
    hw = items[0] if items else {}
    return {
        "model_name": hw.get("machine_name"),
        "model_identifier": hw.get("machine_model"),
        "model_number": hw.get("model_number"),
        "serial_number": hw.get("serial_number"),
        "hardware_uuid": hw.get("platform_UUID"),
        "chip": hw.get("chip_type") or hw.get("cpu_type"),
        "cpu_cores": hw.get("number_processors"),
        "memory": hw.get("physical_memory"),
        "firmware_version": hw.get("boot_rom_version"),
        "activation_lock_status": hw.get("activation_lock_status"),
    }


def parse_df(output: str) -> Dict[str, Optional[str]]:
    """`df -Pk /` -> linha 2: Filesystem 1024-blocks Used Available Capacity Mounted-on"""
    lines = [l for l in output.splitlines() if l.strip()]
    if len(lines) < 2:
        return {"device": None, "mount_point": None}
    cols = lines[1].split()
    return {"device": cols[0], "mount_point": cols[-1] if len(cols) >= 6 else None}


def parse_boottime(output: str) -> Optional[int]:
    """`sysctl -n kern.boottime` -> '{ sec = 1729500000, usec = 123 } Mon Oct ...'"""
    match = re.search(r"sec\s*=\s*(\d+)", output)
    return int(match.group(1)) if match else None


# --------------------------------------------------------------------------- #
# Coletores
# --------------------------------------------------------------------------- #
def collect_os() -> Dict[str, Any]:
    res = run_command([SW_VERS])
    data = parse_sw_vers(res.output) if res.executed else {}
    source = "sw_vers"
    if not data.get("product_version"):
        mac_ver = platform.mac_ver()[0]
        if mac_ver:
            data = {"product_name": "macOS", "product_version": mac_ver}
            source = "platform.mac_ver"

    if not data.get("product_version"):
        return make_section("error", error=res.error or "versão do macOS não identificada",
                            evidence=[res.evidence()], product_version=None)

    full = data["product_version"]
    if data.get("product_version_extra"):
        full = "{} {}".format(full, data["product_version_extra"])
    return make_section(
        "ok",
        evidence=[res.evidence()],
        product_name=data.get("product_name"),
        product_version=data["product_version"],
        product_version_extra=data.get("product_version_extra"),
        build_version=data.get("build_version"),
        full_version=full,
        kernel_version=platform.release(),
        architecture=platform.machine(),
        source=source,
    )


def _scutil_get(key: str) -> Optional[str]:
    res = run_command([SCUTIL, "--get", key])
    value = res.stdout.strip() if res.ok else ""
    return value or None


def collect_device() -> Dict[str, Any]:
    evidence = []
    hardware = {}  # type: Dict[str, Any]
    error = None

    res = run_command([SYSTEM_PROFILER, "SPHardwareDataType", "-json"], timeout=90)
    ev = res.evidence()
    ev["output"] = "[JSON omitido da evidência — campos extraídos abaixo]" if res.ok else ev["output"]
    evidence.append(ev)
    if res.ok:
        try:
            hardware = parse_hardware_json(res.stdout)
        except (ValueError, AttributeError) as exc:
            error = "JSON do system_profiler inválido: {}".format(exc)
    else:
        error = res.error or "system_profiler retornou código {}".format(res.returncode)

    device = {
        "computer_name": _scutil_get("ComputerName"),
        "local_hostname": _scutil_get("LocalHostName"),
        "hostname": platform.node(),
    }
    device.update(hardware)

    status = "ok" if hardware.get("serial_number") else "error"
    if status == "error" and not error:
        error = "número de série não identificado"
    return make_section(status, error=error, evidence=evidence, **device)


def collect_storage(path: str = "/") -> Dict[str, Any]:
    """
    Em APFS, `/` é o volume de sistema selado (read-only), mas statvfs retorna o
    espaço disponível do CONTAINER inteiro — que é o que importa operacionalmente.
    Por isso used = total - free (e não usage.used, que reflete só o volume de sistema).
    """
    usage = shutil.disk_usage(path)
    total, free = usage.total, usage.free
    used = total - free
    df_res = run_command([DF, "-Pk", path])
    df_info = parse_df(df_res.stdout) if df_res.ok else {"device": None, "mount_point": None}

    return make_section(
        "ok",
        evidence=[df_res.evidence()],
        path=path,
        device=df_info["device"],
        total_bytes=total,
        used_bytes=used,
        free_bytes=free,
        total_gb=round(total / BYTES_PER_GB, 2),
        used_gb=round(used / BYTES_PER_GB, 2),
        free_gb=round(free / BYTES_PER_GB, 2),
        used_percent=round(used / total * 100, 2) if total else None,
        free_percent=round(free / total * 100, 2) if total else None,
    )


def resolve_target_user() -> Tuple[str, str]:
    """
    Determina QUAL usuário auditar:
      1. sudo  -> SUDO_USER (o humano que invocou o sudo)
      2. root sem sudo (MDM/LaunchDaemon) -> usuário logado no console
      3. caso contrário -> usuário do processo
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user, "SUDO_USER"

    current = getpass.getuser()
    if os.geteuid() == 0:
        res = run_command([STAT, "-f", "%Su", "/dev/console"])
        console = res.stdout.strip() if res.ok else ""
        if console and console not in ("root", "_mbsetupuser", "loginwindow"):
            return console, "console_user"
    return current, "process_user"


def _admin_group_members() -> List[str]:
    try:
        return sorted(grp.getgrnam("admin").gr_mem)
    except KeyError:
        return []


def check_admin(user: str) -> Tuple[Optional[bool], str, Optional[Dict[str, Any]]]:
    """Usa dseditgroup (resolve grupos aninhados); fallback para o módulo grp."""
    res = run_command([DSEDITGROUP, "-o", "checkmember", "-m", user, "admin"])
    if res.executed:
        out = res.stdout.strip().lower()
        if out.startswith("yes"):
            return True, "dseditgroup", res.evidence()
        if out.startswith("no"):
            return False, "dseditgroup", res.evidence()
    try:
        group = grp.getgrnam("admin")
        member = user in group.gr_mem or pwd.getpwnam(user).pw_gid == group.gr_gid
        return member, "grp", res.evidence()
    except KeyError:
        return None, "indisponível", res.evidence()


def collect_user() -> Dict[str, Any]:
    user, resolution = resolve_target_user()
    is_admin, method, evidence = check_admin(user)
    try:
        uid = pwd.getpwnam(user).pw_uid  # type: Optional[int]
    except KeyError:
        uid = None
    status = "ok" if is_admin is not None else "error"
    return make_section(
        status,
        error=None if status == "ok" else "não foi possível verificar o grupo admin",
        evidence=[evidence] if evidence else None,
        username=user,
        uid=uid,
        resolved_from=resolution,
        is_admin=is_admin,
        check_method=method,
        admin_group_members=_admin_group_members(),
        audit_running_as_root=os.geteuid() == 0,
    )


def collect_uptime() -> Dict[str, Any]:
    res = run_command([SYSCTL, "-n", "kern.boottime"])
    boot_ts = parse_boottime(res.stdout) if res.ok else None
    if boot_ts is None:
        return make_section("error", error=res.error or "kern.boottime não interpretado",
                            evidence=[res.evidence()], uptime_days=None)
    boot = datetime.fromtimestamp(boot_ts, tz=timezone.utc)
    uptime_seconds = int((datetime.now(timezone.utc) - boot).total_seconds())
    return make_section(
        "ok",
        boot_time=boot.astimezone().isoformat(),
        uptime_seconds=uptime_seconds,
        uptime_days=round(uptime_seconds / 86400, 2),
    )


def collect_system(progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    def _p(msg: str) -> None:
        if progress:
            progress(msg)

    _p("Identificação do dispositivo (system_profiler, scutil)")
    device = safe_collect("device", collect_device)
    _p("Versão do macOS (sw_vers)")
    os_info = safe_collect("os", collect_os)
    _p("Armazenamento do volume principal (/)")
    storage = safe_collect("storage", collect_storage, "/")
    _p("Usuário e privilégios (dseditgroup)")
    user = safe_collect("user", collect_user)
    uptime = safe_collect("uptime", collect_uptime)

    return {"device": device, "os": os_info, "storage": storage, "user": user, "uptime": uptime}
