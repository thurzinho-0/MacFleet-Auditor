"""Exportador do relatório estruturado em JSON (audit_report_YYYYMMDD_HHMMSS.json)."""

import json
import logging
import os
import tempfile
from datetime import date, datetime
from typing import Any, Dict

logger = logging.getLogger("macfleet.reporters.json")


def _default(obj: Any) -> Any:
    """Serializa tipos que o plistlib/datetime podem introduzir nos dados brutos."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (set, tuple)):
        return list(obj)
    return str(obj)


def build_report(metadata: Dict[str, Any], collected: Dict[str, Any], evaluation: Dict[str, Any],
                 schema_version: str = "1.0") -> Dict[str, Any]:
    return {
        "schema_version": schema_version,
        "metadata": metadata,
        "policy": evaluation["policy"],
        "summary": evaluation["summary"],
        "compliance_results": evaluation["results"],
        "collected_data": collected,
    }


def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=_default)


def write_report(report: Dict[str, Any], output_dir: str, timestamp: datetime,
                 prefix: str = "audit_report") -> str:
    """
    Grava o relatório de forma atômica (tmp + rename), com permissão 0640.
    Se executado via sudo, devolve a posse do arquivo ao usuário que chamou o sudo.
    """
    output_dir = os.path.abspath(os.path.expanduser(output_dir))
    created_dir = not os.path.isdir(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    filename = "{}_{}.json".format(prefix, timestamp.strftime("%Y%m%d_%H%M%S"))
    final_path = os.path.join(output_dir, filename)
    counter = 1
    while os.path.exists(final_path):  # duas execuções no mesmo segundo
        final_path = os.path.join(output_dir, filename.replace(".json", "_{}.json".format(counter)))
        counter += 1

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=output_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(to_json(report))
            handle.write("\n")
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, final_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    # Só altera o dono do diretório se ele foi criado por esta execução.
    _restore_ownership(*([output_dir, final_path] if created_dir else [final_path]))
    return final_path


def _restore_ownership(*paths: str) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for path in paths:
        try:
            os.chown(path, int(uid), int(gid))
        except (OSError, ValueError) as exc:
            logger.debug("Não foi possível ajustar dono de %s: %s", path, exc)
