"""
Configuração central do MacFleet Auditor: limiares e política de conformidade.

A política é DECLARATIVA: cada regra aponta para um bloco de dados coletados
(`source`), um campo (`field`) e um operador. Para criar uma política própria
sem editar código, exporte a padrão com `--dump-policy`, ajuste o JSON e
rode com `--policy minha_politica.json`.

Operadores disponíveis (engine/compliance.py):
  is_true        valor == True                    -> PASS, senão on_fail
  is_false       valor == False                   -> PASS, senão on_fail
  in             valor em params.pass             -> PASS; em params.warning -> WARNING; senão on_fail
  max            valor <= params.max              -> PASS, senão on_fail
  min_threshold  valor >  params.pass             -> PASS; > params.warning -> WARNING; senão FAIL
  version_gte    versão >= params.min_version     -> PASS, senão on_fail

Campos opcionais por regra: params.on_fail (FAIL|WARNING), params.unit,
messages {"PASS"|"WARNING"|"FAIL": "texto com {value}"}, remediation, references.
"""

import json
from typing import Any, Dict, Optional

TOOL_NAME = "MacFleet Auditor"
TOOL_VERSION = "1.0.0"
REPORT_PREFIX = "audit_report"
REPORT_SCHEMA_VERSION = "1.0"

# ------------------------------------------------------------------ limiares
DISK_FREE_PASS_PERCENT = 15.0      # > 15% livre  -> PASS
DISK_FREE_WARNING_PERCENT = 10.0   # > 10% livre  -> WARNING ; <= 10% -> FAIL
MIN_MACOS_VERSION = "15.0"         # ajuste à sua política de suporte (ex.: N-2)
SOFTWAREUPDATE_TIMEOUT = 300       # segundos

# Heurística para classificar uma atualização como "de segurança".
# Atualizações de SO (macOS), Background Security Improvements / RSR, XProtect,
# MRT e Safari carregam correções de CVEs na prática.
SECURITY_UPDATE_KEYWORDS = (
    "security",
    "macos",
    "xprotect",
    "mrt",
    "gatekeeper",
    "safari",
    "rapid security response",
    "background security",
)

# Pesos para o score ponderado (PASS = 100% do peso, WARNING = 50%, FAIL = 0%)
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 3, "low": 1}

# ------------------------------------------------------------------ política
POLICY = {
    "name": "MacFleet Baseline",
    "version": "1.0.0",
    "description": "Baseline mínima de hardening e saúde operacional para endpoints macOS corporativos.",
    "on_collection_error": "WARNING",
    "rules": [
        {
            "id": "SEC-001",
            "title": "Criptografia de disco (FileVault)",
            "category": "Security Hardening",
            "severity": "critical",
            "source": "security.filevault",
            "field": "state",
            "operator": "in",
            "params": {"pass": ["on"], "warning": ["encrypting"]},
            "expected": "FileVault ativo (On)",
            "remediation": "Habilitar via MDM (payload FileVault + escrow da Recovery Key) "
                           "ou localmente: sudo fdesetup enable",
            "references": ["CIS Apple macOS Benchmark: Ensure FileVault Is Enabled",
                           "NIST mSCP: system_settings_filevault_enforce"],
        },
        {
            "id": "SEC-002",
            "title": "Application Firewall ativo",
            "category": "Security Hardening",
            "severity": "high",
            "source": "security.firewall",
            "field": "enabled",
            "operator": "is_true",
            "expected": "Firewall habilitado (State = 1 ou 2)",
            "remediation": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on "
                           "(ou payload com.apple.security.firewall via MDM)",
            "references": ["CIS Apple macOS Benchmark: Ensure Firewall Is Enabled",
                           "NIST mSCP: system_settings_firewall_enable"],
        },
        {
            "id": "SEC-003",
            "title": "Firewall em Stealth Mode",
            "category": "Security Hardening",
            "severity": "low",
            "source": "security.firewall",
            "field": "stealth_mode",
            "operator": "is_true",
            "params": {"on_fail": "WARNING"},
            "expected": "Stealth mode habilitado",
            "messages": {"PASS": "Stealth mode ativo.", "WARNING": "Stealth mode desativado (responde a ICMP/probes)."},
            "remediation": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            "references": ["CIS Apple macOS Benchmark: Ensure Firewall Stealth Mode Is Enabled",
                           "NIST mSCP: system_settings_firewall_stealth_mode_enable"],
        },
        {
            "id": "SEC-004",
            "title": "Gatekeeper ativo",
            "category": "Security Hardening",
            "severity": "high",
            "source": "security.gatekeeper",
            "field": "enabled",
            "operator": "is_true",
            "expected": "assessments enabled",
            "remediation": "sudo spctl --master-enable (ou payload com.apple.systempolicy.control via MDM)",
            "references": ["CIS Apple macOS Benchmark: Ensure Gatekeeper Is Enabled",
                           "NIST mSCP: os_gatekeeper_enable"],
        },
        {
            "id": "SEC-005",
            "title": "System Integrity Protection (SIP)",
            "category": "Security Hardening",
            "severity": "critical",
            "source": "security.sip",
            "field": "state",
            "operator": "in",
            "params": {"pass": ["enabled"], "warning": ["custom"]},
            "expected": "SIP enabled",
            "remediation": "Iniciar no recoveryOS e executar: csrutil enable ; reiniciar",
            "references": ["CIS Apple macOS Benchmark: Ensure System Integrity Protection Is Enabled",
                           "NIST mSCP: os_sip_enable"],
        },
        {
            "id": "SEC-006",
            "title": "Atualizações de segurança pendentes",
            "category": "Patch Management",
            "severity": "high",
            "source": "security.software_updates",
            "field": "pending_security",
            "operator": "max",
            "params": {"max": 0, "unit": " pendente(s)"},
            "expected": "0 atualizações de segurança pendentes",
            "remediation": "sudo softwareupdate --install --all --restart "
                           "(ou enforcement via Declarative Device Management no MDM)",
            "references": ["CIS Apple macOS Benchmark: Ensure All Apple-provided Software Is Current"],
        },
        {
            "id": "SEC-007",
            "title": "Atualizações pendentes (todas)",
            "category": "Patch Management",
            "severity": "medium",
            "source": "security.software_updates",
            "field": "pending_total",
            "operator": "max",
            "params": {"max": 0, "on_fail": "WARNING", "unit": " pendente(s)"},
            "expected": "Nenhuma atualização pendente",
            "remediation": "Revisar `softwareupdate --list` e agendar janela de manutenção.",
            "references": [],
        },
        {
            "id": "OPS-001",
            "title": "Espaço livre no volume principal",
            "category": "Operational Health",
            "severity": "medium",
            "source": "system.storage",
            "field": "free_percent",
            "operator": "min_threshold",
            "params": {"pass": DISK_FREE_PASS_PERCENT, "warning": DISK_FREE_WARNING_PERCENT, "unit": "%"},
            "expected": "> {:.0f}% livre".format(DISK_FREE_PASS_PERCENT),
            "remediation": "Liberar espaço (caches, Downloads, snapshots locais: tmutil listlocalsnapshots /). "
                           "Pouco espaço impede instalação de updates do macOS.",
            "references": [],
        },
        {
            "id": "OPS-002",
            "title": "Versão mínima suportada do macOS",
            "category": "Operational Health",
            "severity": "medium",
            "source": "system.os",
            "field": "product_version",
            "operator": "version_gte",
            "params": {"min_version": MIN_MACOS_VERSION, "on_fail": "WARNING"},
            "expected": ">= {}".format(MIN_MACOS_VERSION),
            "remediation": "Planejar upgrade de versão major do macOS (verificar compatibilidade do hardware).",
            "references": [],
        },
        {
            "id": "IAM-001",
            "title": "Usuário sem privilégio de Administrador",
            "category": "Identity & Access",
            "severity": "medium",
            "source": "system.user",
            "field": "is_admin",
            "operator": "is_false",
            "params": {"on_fail": "WARNING"},
            "expected": "Usuário padrão (fora do grupo admin)",
            "messages": {"PASS": "Usuário padrão (sem admin).", "WARNING": "Usuário é membro do grupo admin."},
            "remediation": "Aplicar menor privilégio: remover do grupo admin "
                           "(sudo dseditgroup -o edit -d <usuario> -t user admin) e usar elevação just-in-time.",
            "references": ["CIS Controls v8 — 5.4 Restrict Administrator Privileges"],
        },
    ],
}

REQUIRED_RULE_KEYS = ("id", "title", "severity", "source", "field", "operator")


def load_policy(path: Optional[str] = None) -> Dict[str, Any]:
    """Retorna a política padrão ou carrega uma política customizada em JSON."""
    if not path:
        return POLICY
    with open(path, "r", encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise ValueError("política inválida: esperado objeto com lista 'rules'")
    for idx, rule in enumerate(policy["rules"]):
        missing = [k for k in REQUIRED_RULE_KEYS if k not in rule]
        if missing:
            raise ValueError("regra #{} sem campos obrigatórios: {}".format(idx, ", ".join(missing)))
    policy.setdefault("name", "Custom Policy")
    policy.setdefault("version", "0.0.0")
    policy.setdefault("on_collection_error", "WARNING")
    return policy
