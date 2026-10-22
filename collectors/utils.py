"""
Utilitários compartilhados pelos coletores.

Toda execução de comando nativo do macOS passa por `run_command`, que:
  * usa caminhos absolutos dos binários (evita PATH hijacking quando rodando com sudo);
  * força locale "C" (saída em inglês -> parsing estável em Macs configurados em pt_BR);
  * aplica timeout e nunca lança exceção para o chamador (erros viram dados).
"""

import logging
import os
import plistlib
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("macfleet.collectors")

DEFAULT_TIMEOUT = 30
MAX_EVIDENCE_CHARS = 4000

_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec"


def _safe_env() -> Dict[str, str]:
    env = {"LC_ALL": "C", "LANG": "C", "PATH": _SAFE_PATH}
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    return env


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


@dataclass
class CommandResult:
    command: List[str]
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None
    duration_ms: int = 0

    @property
    def executed(self) -> bool:
        """O processo rodou até o fim (independente do exit code)."""
        return self.error is None

    @property
    def ok(self) -> bool:
        return self.executed and self.returncode == 0

    @property
    def output(self) -> str:
        """stdout + stderr (várias ferramentas da Apple escrevem status no stderr)."""
        parts = [p for p in (self.stdout.strip(), self.stderr.strip()) if p]
        return "\n".join(parts)

    def evidence(self) -> Dict[str, Any]:
        out = self.output
        if len(out) > MAX_EVIDENCE_CHARS:
            out = out[:MAX_EVIDENCE_CHARS] + "\n... [truncado]"
        return {
            "command": " ".join(self.command),
            "returncode": self.returncode,
            "output": out,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


def run_command(command: List[str], timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    """Executa um comando nativo de forma segura e retorna sempre um CommandResult."""
    binary = command[0]
    if os.path.isabs(binary):
        if not os.path.exists(binary):
            return CommandResult(command, error="binário não encontrado: {}".format(binary))
    elif shutil.which(binary, path=_SAFE_PATH) is None:
        return CommandResult(command, error="comando não encontrado no PATH seguro: {}".format(binary))

    logger.debug("Executando: %s", " ".join(command))
    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_safe_env(),
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command,
            stdout=_to_text(exc.stdout),
            stderr=_to_text(exc.stderr),
            error="timeout após {}s".format(timeout),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
    except (OSError, ValueError) as exc:
        return CommandResult(command, error="falha ao executar: {}".format(exc))

    result = CommandResult(
        command,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    logger.debug("rc=%s (%sms)", result.returncode, result.duration_ms)
    return result


def read_plist(path: str) -> Optional[Dict[str, Any]]:
    """Lê um plist (XML ou binário). Retorna None se ausente/ilegível."""
    try:
        with open(path, "rb") as handle:
            data = plistlib.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        logger.debug("Não foi possível ler %s: %s", path, exc)
        return None


def make_section(collection_status: str = "ok", error: Optional[str] = None,
                 evidence: Optional[List[Dict[str, Any]]] = None, **fields: Any) -> Dict[str, Any]:
    """
    Padroniza o formato de cada bloco de dados coletados.

    collection_status: "ok" | "error" | "skipped"
    """
    section = {"collection_status": collection_status}  # type: Dict[str, Any]
    section.update(fields)
    if error:
        section["error"] = error
    if evidence:
        section["evidence"] = evidence
    return section


def safe_collect(name: str, func: Callable[..., Dict[str, Any]], *args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Isola falhas inesperadas de um coletor para que a auditoria continue."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - robustez intencional
        logger.exception("Falha inesperada no coletor %s", name)
        return make_section("error", error="exceção no coletor: {}: {}".format(type(exc).__name__, exc))
