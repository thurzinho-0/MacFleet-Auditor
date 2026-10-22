"""
Exportador do dashboard HTML (audit_report_YYYYMMDD_HHMMSS.html).

O HTML é autocontido: CSS, JavaScript e os dados do relatório ficam embutidos
no próprio arquivo. Não há CDN nem chamadas de rede, então ele abre offline em
qualquer navegador. O dashboard também aceita carregar outro JSON pelo botão
"Carregar relatório" ou arrastando o arquivo para a página.
"""

import os
from typing import Any, Dict

from reporters.json_reporter import _restore_ownership, to_json

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_template.html")
PLACEHOLDER = "/*__REPORT_DATA__*/null"


def render_dashboard(report: Dict[str, Any]) -> str:
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as handle:
        template = handle.read()
    if PLACEHOLDER not in template:
        raise ValueError("template do dashboard sem placeholder de dados")
    # Todo "<" vira \u003c (válido em strings JSON): nenhum valor coletado consegue
    # fechar a tag <script> nem abrir comentário HTML (anti-injeção).
    payload = to_json(report).replace("<", "\\u003c")
    return template.replace(PLACEHOLDER, payload, 1)


def write_dashboard(report: Dict[str, Any], json_path: str) -> str:
    """Grava o dashboard ao lado do JSON, com o mesmo nome base."""
    html_path = os.path.splitext(json_path)[0] + ".html"
    tmp_path = html_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(render_dashboard(report))
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, html_path)
    _restore_ownership(html_path)
    return html_path
