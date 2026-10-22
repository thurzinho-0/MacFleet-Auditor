#!/usr/bin/env python3
"""
MacFleet Auditor — auditoria local de segurança e saúde operacional para macOS.

Uso rápido:
    python3 auditor.py                       # auditoria completa (consulta updates ao vivo)
    python3 auditor.py --updates-mode cached # rápido: usa cache local do Software Update
    sudo python3 auditor.py                  # contexto root (equivalente a execução via MDM)

Exit codes (úteis para MDM / Jamf / Kandji / Intune):
    0 = COMPLIANT   1 = AT_RISK (warnings)   2 = NON_COMPLIANT (falhas)   3 = erro de execução
"""

import sys

if sys.version_info < (3, 9):
    sys.stderr.write("MacFleet Auditor requer Python 3.9+ (detectado {}).\n".format(sys.version.split()[0]))
    sys.exit(3)

import argparse
import getpass
import json
import logging
import os
import platform
import socket
import time
import uuid
from datetime import datetime
from typing import List, Optional

import config
from collectors import security, system
from engine import compliance
from reporters import html_reporter, json_reporter
from reporters.cli import CliReporter

EXIT_COMPLIANT = 0
EXIT_AT_RISK = 1
EXIT_NON_COMPLIANT = 2
EXIT_ERROR = 3

EXIT_BY_STATUS = {"COMPLIANT": EXIT_COMPLIANT, "AT_RISK": EXIT_AT_RISK, "NON_COMPLIANT": EXIT_NON_COMPLIANT}


def parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="auditor.py",
        description="{} — auditoria local de segurança e saúde operacional para macOS.".format(config.TOOL_NAME),
    )
    parser.add_argument("-o", "--output-dir", default="./reports",
                        help="diretório de saída do relatório JSON (padrão: ./reports)")
    parser.add_argument("--updates-mode", choices=("live", "cached", "skip"), default="live",
                        help="live: softwareupdate --list (lento, preciso) | cached: cache local | skip: não verifica")
    parser.add_argument("--update-timeout", type=int, default=config.SOFTWAREUPDATE_TIMEOUT,
                        help="timeout em segundos do softwareupdate (padrão: %(default)s)")
    parser.add_argument("--policy", help="arquivo JSON com política customizada")
    parser.add_argument("--dump-policy", action="store_true",
                        help="imprime a política padrão em JSON e sai (base para customização)")
    parser.add_argument("--no-html", action="store_true",
                        help="não gera o dashboard HTML (gerado por padrão ao lado do JSON)")
    parser.add_argument("--open", action="store_true",
                        help="abre o dashboard HTML no navegador ao final")
    parser.add_argument("--json-stdout", action="store_true",
                        help="imprime o relatório JSON no stdout (suprime a saída visual)")
    parser.add_argument("-q", "--quiet", action="store_true", help="sem saída visual (apenas exit code + arquivo)")
    parser.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    parser.add_argument("-v", "--verbose", action="store_true", help="logs de depuração no stderr")
    parser.add_argument("--version", action="version", version="{} {}".format(config.TOOL_NAME, config.TOOL_VERSION))
    # Uso interno (desenvolvimento/testes fora do macOS)
    parser.add_argument("--allow-non-darwin", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def build_metadata(args: argparse.Namespace, run_id: str, started: datetime, finished: datetime,
                   duration: float) -> dict:
    return {
        "tool": config.TOOL_NAME,
        "tool_version": config.TOOL_VERSION,
        "run_id": run_id,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 2),
        "hostname": socket.gethostname(),
        "executed_by": getpass.getuser(),
        "sudo_user": os.environ.get("SUDO_USER"),
        "running_as_root": os.geteuid() == 0,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "options": {"updates_mode": args.updates_mode, "policy_file": args.policy},
    }


def _open_in_browser(path: str) -> None:
    """Abre o dashboard no navegador padrão do usuário (com sudo, abre como SUDO_USER)."""
    import subprocess
    cmd = ["/usr/bin/open", path]
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        cmd = ["/usr/bin/sudo", "-u", sudo_user] + cmd
    try:
        subprocess.run(cmd, check=False, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write("Não foi possível abrir o navegador: {}\n".format(exc))


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.dump_policy:
        print(json.dumps(config.POLICY, indent=2, ensure_ascii=False))
        return EXIT_COMPLIANT

    if platform.system() != "Darwin" and not args.allow_non_darwin:
        sys.stderr.write("Erro: o MacFleet Auditor deve ser executado no macOS (detectado: {}).\n"
                         .format(platform.system()))
        return EXIT_ERROR

    try:
        policy = config.load_policy(args.policy)
    except (OSError, ValueError) as exc:
        sys.stderr.write("Erro ao carregar a política: {}\n".format(exc))
        return EXIT_ERROR

    use_color = (not args.no_color) and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    cli = CliReporter(use_color=use_color, enabled=not (args.quiet or args.json_stdout))

    run_id = str(uuid.uuid4())
    started = datetime.now().astimezone()
    t0 = time.monotonic()

    cli.banner(config.TOOL_NAME, config.TOOL_VERSION, policy["name"], policy["version"])
    if os.geteuid() != 0:
        cli.note("Executando sem root. Todos os checks do MVP funcionam como usuário comum; "
                 "use sudo para simular o contexto de execução via MDM.")

    collected = {
        "system": system.collect_system(progress=cli.step),
        "security": security.collect_security(
            updates_mode=args.updates_mode,
            security_keywords=config.SECURITY_UPDATE_KEYWORDS,
            update_timeout=args.update_timeout,
            progress=cli.step,
        ),
    }

    evaluation = compliance.evaluate(collected, policy, config.SEVERITY_WEIGHTS)
    duration = time.monotonic() - t0
    finished = datetime.now().astimezone()

    metadata = build_metadata(args, run_id, started, finished, duration)
    report = json_reporter.build_report(metadata, collected, evaluation, config.REPORT_SCHEMA_VERSION)

    report_path = None
    try:
        report_path = json_reporter.write_report(report, args.output_dir, started, config.REPORT_PREFIX)
    except OSError as exc:
        sys.stderr.write("Erro ao gravar o relatório JSON: {}\n".format(exc))

    html_path = None
    if report_path and not args.no_html:
        try:
            html_path = html_reporter.write_dashboard(report, report_path)
        except (OSError, ValueError) as exc:
            sys.stderr.write("Erro ao gerar o dashboard HTML: {}\n".format(exc))

    if args.json_stdout:
        print(json_reporter.to_json(report))

    cli.inventory(collected)
    cli.results(evaluation)
    cli.summary(evaluation, report_path, duration, html_path)

    if args.open and html_path:
        _open_in_browser(html_path)

    if report_path is None:
        return EXIT_ERROR
    return EXIT_BY_STATUS.get(evaluation["summary"]["overall_status"], EXIT_ERROR)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nAuditoria interrompida pelo usuário.\n")
        sys.exit(130)
