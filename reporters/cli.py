"""Saída visual no Terminal: inventário, tabela de conformidade e resumo executivo."""

import sys
import textwrap
from typing import Any, Dict, Optional, TextIO

WIDTH = 86


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return "\033[{}m{}\033[0m".format(code, text) if self.enabled else text

    def bold(self, t: str) -> str: return self._wrap("1", t)
    def dim(self, t: str) -> str: return self._wrap("2", t)
    def red(self, t: str) -> str: return self._wrap("31", t)
    def green(self, t: str) -> str: return self._wrap("32", t)
    def yellow(self, t: str) -> str: return self._wrap("33", t)
    def cyan(self, t: str) -> str: return self._wrap("36", t)


BADGES = {
    "PASS": ("✔ PASS", "green"),
    "WARNING": ("▲ WARN", "yellow"),
    "FAIL": ("✖ FAIL", "red"),
    "SKIPPED": ("○ SKIP", "dim"),
}

OVERALL = {
    "COMPLIANT": ("CONFORME", "green"),
    "AT_RISK": ("EM RISCO (avisos)", "yellow"),
    "NON_COMPLIANT": ("NÃO CONFORME", "red"),
}


def _val(v: Any, suffix: str = "") -> str:
    if v is None:
        return "n/d"
    if isinstance(v, bool):
        return "Sim" if v else "Não"
    return "{}{}".format(v, suffix)


class CliReporter:
    def __init__(self, use_color: bool = True, enabled: bool = True, stream: Optional[TextIO] = None) -> None:
        self.s = _Style(use_color)
        self.enabled = enabled
        self.out = stream or sys.stdout

    # ------------------------------------------------------------ helpers
    def _print(self, text: str = "") -> None:
        if self.enabled:
            print(text, file=self.out, flush=True)

    def _rule(self, char: str = "─") -> None:
        self._print(self.s.dim(char * WIDTH))

    def _section(self, title: str) -> None:
        self._print()
        self._print(self.s.bold(self.s.cyan(title.upper())))
        self._rule()

    def _kv(self, key: str, value: str) -> None:
        self._print("  {:<24} {}".format(key, value))

    def _badge(self, status: str) -> str:
        text, color = BADGES.get(status, (status, "dim"))
        return getattr(self.s, color)("{:<7}".format(text))

    # ------------------------------------------------------------ API
    def banner(self, tool: str, version: str, policy_name: str, policy_version: str) -> None:
        self._rule("═")
        self._print(self.s.bold("  {}  v{}".format(tool, version)) +
                    self.s.dim("   ·   política: {} v{}".format(policy_name, policy_version)))
        self._rule("═")

    def note(self, text: str) -> None:
        for line in textwrap.wrap(text, WIDTH - 4):
            self._print(self.s.yellow("  ! ") + line)

    def step(self, text: str) -> None:
        self._print(self.s.dim("  → coletando: ") + text)

    def inventory(self, data: Dict[str, Any]) -> None:
        sysd = data.get("system", {})
        dev, osd = sysd.get("device", {}), sysd.get("os", {})
        sto, usr, upt = sysd.get("storage", {}), sysd.get("user", {}), sysd.get("uptime", {})

        self._section("Inventário do dispositivo")
        self._kv("Nome do computador", _val(dev.get("computer_name") or dev.get("hostname")))
        self._kv("Modelo", "{} ({})".format(_val(dev.get("model_name")), _val(dev.get("model_identifier"))))
        self._kv("Chip / Memória", "{} / {}".format(_val(dev.get("chip")), _val(dev.get("memory"))))
        self._kv("Número de série", _val(dev.get("serial_number")))
        self._kv("macOS", "{} {} (build {})".format(
            _val(osd.get("product_name")), _val(osd.get("full_version")), _val(osd.get("build_version"))))
        if sto.get("total_gb") is not None:
            self._kv("Disco (/)", "{} GB livres de {} GB  ·  {}% em uso".format(
                sto["free_gb"], sto["total_gb"], sto["used_percent"]))
        self._kv("Usuário auditado", "{}  ·  admin: {}".format(_val(usr.get("username")), _val(usr.get("is_admin"))))
        self._kv("Uptime", _val(upt.get("uptime_days"), " dias"))

    def results(self, evaluation: Dict[str, Any]) -> None:
        self._section("Resultados de conformidade")
        self._print(self.s.bold("  {:<7}  {:<8} {:<9} {:<38} {}".format(
            "STATUS", "ID", "SEVER.", "CONTROLE", "DETALHE")))
        current_cat = None
        for r in evaluation["results"]:
            if r["category"] != current_cat:
                current_cat = r["category"]
                self._print(self.s.dim("  · {}".format(current_cat)))
            title = r["title"] if len(r["title"]) <= 38 else r["title"][:35] + "..."
            msg = r["message"] if len(r["message"]) <= 60 else r["message"][:57] + "..."
            self._print("  {}  {:<8} {:<9} {:<38} {}".format(
                self._badge(r["status"]), r["id"], r["severity"], title, self.s.dim(msg)))

    def summary(self, evaluation: Dict[str, Any], report_path: Optional[str], duration: float,
                html_path: Optional[str] = None) -> None:
        summ = evaluation["summary"]
        label, color = OVERALL.get(summ["overall_status"], (summ["overall_status"], "dim"))

        actionable = [r for r in evaluation["results"] if r["status"] in ("FAIL", "WARNING")]
        if actionable:
            self._section("Ações recomendadas")
            actionable.sort(key=lambda r: (r["status"] != "FAIL",
                                           {"critical": 0, "high": 1, "medium": 2}.get(r["severity"], 3)))
            for r in actionable:
                self._print("  {} {} — {}".format(self._badge(r["status"]), self.s.bold(r["id"]), r["title"]))
                for line in textwrap.wrap(r.get("remediation") or r["message"], WIDTH - 12):
                    self._print("            " + line)

        self._section("Resumo executivo")
        self._kv("Status geral", self.s.bold(getattr(self.s, color)(label)))
        self._kv("Regras avaliadas", "{} total  ·  {} PASS  ·  {} WARNING  ·  {} FAIL  ·  {} SKIP".format(
            summ["total_rules"], self.s.green(str(summ["passed"])), self.s.yellow(str(summ["warnings"])),
            self.s.red(str(summ["failed"])), summ["skipped"]))
        self._kv("Score de conformidade", "{}%  (ponderado por severidade: {}%)".format(
            summ["compliance_score"], summ["weighted_score"]))
        if summ["critical_failures"]:
            self._kv("Falhas CRÍTICAS", self.s.red(", ".join(summ["critical_failures"])))
        self._kv("Duração", "{:.1f}s".format(duration))
        if report_path:
            self._kv("Relatório JSON", report_path)
        if html_path:
            self._kv("Dashboard HTML", html_path)
        self._rule("═")
