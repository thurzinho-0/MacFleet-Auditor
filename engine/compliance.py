"""
Motor de conformidade: avalia os dados coletados contra as regras declarativas
definidas em config.py (ou em uma política JSON externa).
"""

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("macfleet.engine")

PASS = "PASS"
WARNING = "WARNING"
FAIL = "FAIL"
SKIPPED = "SKIPPED"

STATUS_ORDER = {FAIL: 0, WARNING: 1, PASS: 2, SKIPPED: 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

OperatorResult = Tuple[str, str]


# --------------------------------------------------------------------------- #
# Operadores
# --------------------------------------------------------------------------- #
def _fmt(value: Any, unit: str = "") -> str:
    if isinstance(value, bool):
        return "sim" if value else "não"
    return "{}{}".format(value, unit)


def compare_versions(a: str, b: str) -> int:
    """-1 se a<b, 0 se igual, 1 se a>b. Compara apenas componentes numéricos."""
    def norm(v: str) -> List[int]:
        parts = [int(x) for x in re.findall(r"\d+", str(v))][:4]
        return parts + [0] * (4 - len(parts))
    va, vb = norm(a), norm(b)
    return (va > vb) - (va < vb)


def op_is_true(value: Any, params: Dict[str, Any]) -> OperatorResult:
    if value is True:
        return PASS, "Controle ativo."
    return params.get("on_fail", FAIL), "Controle inativo (valor: {}).".format(_fmt(value))


def op_is_false(value: Any, params: Dict[str, Any]) -> OperatorResult:
    if value is False:
        return PASS, "Condição não presente."
    return params.get("on_fail", FAIL), "Condição presente (valor: {}).".format(_fmt(value))


def op_in(value: Any, params: Dict[str, Any]) -> OperatorResult:
    if value in params.get("pass", []):
        return PASS, "Estado '{}' conforme.".format(value)
    if value in params.get("warning", []):
        return WARNING, "Estado '{}' requer atenção.".format(value)
    return params.get("on_fail", FAIL), "Estado '{}' não conforme.".format(value)


def op_max(value: Any, params: Dict[str, Any]) -> OperatorResult:
    limit = params["max"]
    unit = params.get("unit", "")
    if value <= limit:
        return PASS, "{} (máximo permitido: {}).".format(_fmt(value, unit), limit)
    return params.get("on_fail", FAIL), "{} — acima do máximo permitido ({}).".format(_fmt(value, unit), limit)


def op_min_threshold(value: Any, params: Dict[str, Any]) -> OperatorResult:
    pass_t, warn_t = params["pass"], params["warning"]
    unit = params.get("unit", "")
    if value > pass_t:
        return PASS, "{} (mínimo: > {}).".format(_fmt(value, unit), _fmt(pass_t, unit))
    if value > warn_t:
        return WARNING, "{} — abaixo do ideal (> {}).".format(_fmt(value, unit), _fmt(pass_t, unit))
    return FAIL, "{} em nível crítico (<= {}).".format(_fmt(value, unit), _fmt(warn_t, unit))


def op_version_gte(value: Any, params: Dict[str, Any]) -> OperatorResult:
    minimum = params["min_version"]
    if compare_versions(str(value), minimum) >= 0:
        return PASS, "Versão {} >= {}.".format(value, minimum)
    return params.get("on_fail", FAIL), "Versão {} abaixo do mínimo {}.".format(value, minimum)


OPERATORS = {
    "is_true": op_is_true,
    "is_false": op_is_false,
    "in": op_in,
    "max": op_max,
    "min_threshold": op_min_threshold,
    "version_gte": op_version_gte,
}  # type: Dict[str, Callable[[Any, Dict[str, Any]], OperatorResult]]


# --------------------------------------------------------------------------- #
# Avaliação
# --------------------------------------------------------------------------- #
def _resolve(data: Dict[str, Any], dotted: str) -> Optional[Any]:
    node = data  # type: Any
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def evaluate_rule(rule: Dict[str, Any], data: Dict[str, Any], on_error: str = WARNING) -> Dict[str, Any]:
    params = rule.get("params", {}) or {}
    result = {
        "id": rule["id"],
        "title": rule["title"],
        "category": rule.get("category", "General"),
        "severity": rule.get("severity", "medium"),
        "status": None,
        "expected": rule.get("expected"),
        "actual": None,
        "message": "",
        "remediation": None,
        "references": rule.get("references", []),
        "data_path": "{}.{}".format(rule["source"], rule["field"]),
    }  # type: Dict[str, Any]

    section = _resolve(data, rule["source"])
    operator = OPERATORS.get(rule["operator"])

    if operator is None:
        result.update(status=on_error, message="Operador desconhecido: {}".format(rule["operator"]))
    elif not isinstance(section, dict):
        result.update(status=on_error, message="Bloco de dados '{}' não encontrado.".format(rule["source"]))
    elif section.get("collection_status") == "skipped":
        result.update(status=SKIPPED, message=section.get("reason", "Coleta não executada."))
    else:
        value = section.get(rule["field"])
        result["actual"] = value
        if section.get("collection_status") == "error" or value is None:
            detail = section.get("error") or "valor ausente"
            result.update(status=on_error, message="Não foi possível verificar: {}.".format(detail))
        else:
            try:
                status, message = operator(value, params)
            except (KeyError, TypeError) as exc:
                status, message = on_error, "Erro ao avaliar regra: {}".format(exc)
            # Mensagem customizada por regra: rule["messages"][STATUS] com placeholder {value}
            template = (rule.get("messages") or {}).get(status)
            if template:
                message = template.format(value=_fmt(value))
            result.update(status=status, message=message)

    if result["status"] in (FAIL, WARNING):
        result["remediation"] = rule.get("remediation")
    return result


def summarize(results: List[Dict[str, Any]], severity_weights: Dict[str, int]) -> Dict[str, Any]:
    counts = {PASS: 0, WARNING: 0, FAIL: 0, SKIPPED: 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    evaluated = [r for r in results if r["status"] != SKIPPED]
    score = round(counts[PASS] / len(evaluated) * 100, 1) if evaluated else 0.0

    total_weight = sum(severity_weights.get(r["severity"], 1) for r in evaluated)
    earned = sum(
        severity_weights.get(r["severity"], 1) * {PASS: 1.0, WARNING: 0.5}.get(r["status"], 0.0)
        for r in evaluated
    )
    weighted = round(earned / total_weight * 100, 1) if total_weight else 0.0

    if counts[FAIL]:
        overall = "NON_COMPLIANT"
    elif counts[WARNING]:
        overall = "AT_RISK"
    else:
        overall = "COMPLIANT"

    critical_failures = [r["id"] for r in results if r["status"] == FAIL and r["severity"] == "critical"]
    return {
        "overall_status": overall,
        "total_rules": len(results),
        "passed": counts[PASS],
        "warnings": counts[WARNING],
        "failed": counts[FAIL],
        "skipped": counts[SKIPPED],
        "compliance_score": score,
        "weighted_score": weighted,
        "critical_failures": critical_failures,
    }


def evaluate(data: Dict[str, Any], policy: Dict[str, Any],
             severity_weights: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    weights = severity_weights or {"critical": 10, "high": 5, "medium": 3, "low": 1}
    on_error = policy.get("on_collection_error", WARNING)
    results = [evaluate_rule(rule, data, on_error) for rule in policy["rules"]]
    return {
        "policy": {
            "name": policy.get("name"),
            "version": policy.get("version"),
            "description": policy.get("description"),
        },
        "summary": summarize(results, weights),
        "results": results,
    }
