# MacFleet Auditor

Auditoria **local e somente leitura** de segurança e saúde operacional para macOS.
Não usa nenhuma dependência externa (apenas a standard library do Python 3.9+) e chama só binários nativos da Apple.

```
macfleet_auditor/
├── auditor.py              # Entry point / CLI / exit codes
├── config.py               # Limiares + política declarativa (regras)
├── collectors/
│   ├── utils.py            # run_command seguro, leitura de plist, padronização
│   ├── security.py         # FileVault, Firewall, Gatekeeper, SIP, Updates
│   └── system.py           # Hardware, serial, macOS, disco, usuário/admin, uptime
├── engine/compliance.py    # Avalia dados x regras -> PASS / WARNING / FAIL / SKIPPED
├── reporters/
│   ├── cli.py              # Resumo executivo no Terminal
│   ├── json_reporter.py    # audit_report_YYYYMMDD_HHMMSS.json
│   ├── html_reporter.py    # audit_report_YYYYMMDD_HHMMSS.html (dashboard)
│   └── dashboard_template.html  # Template HTML/CSS/JS do dashboard (sem dependências)
├── tests/test_parsers.py   # Testes unitários (rodam em qualquer SO)
└── examples/               # Exemplo de relatório JSON
```

## 1. Pré-requisitos

```bash
python3 --version          # precisa ser 3.9+
```

O `/usr/bin/python3` do macOS vem com as Command Line Tools. Se aparecer o diálogo de instalação:

```bash
xcode-select --install
```

## 2. Execução

```bash
cd macfleet_auditor

python3 auditor.py                          # auditoria completa (consulta updates ao vivo, ~30s–3min)
python3 auditor.py --updates-mode cached    # rápido: usa o cache local do Software Update
python3 auditor.py --updates-mode skip      # não verifica updates (regras viram SKIPPED)
python3 auditor.py -o ~/Desktop/auditorias  # muda o diretório do relatório (padrão: ./reports)
python3 auditor.py --json-stdout > out.json # JSON no stdout (pipelines, MDM)
python3 auditor.py -q; echo $?              # silencioso, só exit code + arquivo
python3 auditor.py --open                   # abre o dashboard HTML no navegador ao final
python3 auditor.py --no-html                # gera apenas o JSON
```

### Dashboard HTML

Cada execução gera, ao lado do JSON, um `audit_report_YYYYMMDD_HHMMSS.html` com os dados embutidos.
O arquivo é autocontido, sem CDN e sem rede: abre offline com duplo clique ou com `open reports/*.html`.

O dashboard mostra:

- Status geral, score de conformidade e atualizações pendentes.
- Resultados por categoria e por severidade, mais as três ações prioritárias.
- Armazenamento com os limiares de 15% e 10%.
- Ficha do dispositivo.
- Tabela de controles com filtros e busca. Ao clicar numa linha, aparecem o esperado, o valor coletado, a remediação, as referências e a evidência do comando.
- Lista de updates e metadados da execução.

Também tem tema claro/escuro e impressão em PDF. Para ver outro relatório, use o botão **Carregar relatório** ou arraste um `.json` para a página.

### Exit codes

| Código | Significado |
|---|---|
| 0 | `COMPLIANT`, todas as regras passaram |
| 1 | `AT_RISK`, há warnings e nenhuma falha |
| 2 | `NON_COMPLIANT`, ao menos uma regra em FAIL |
| 3 | Erro de execução (SO não suportado, política inválida, falha ao gravar o relatório) |

## 3. Permissões e `sudo`

**Nenhum check do MVP exige root**, porque todos fazem apenas leitura de status:

| Check | Comando | Root? |
|---|---|---|
| FileVault | `fdesetup status` | Não |
| Firewall | `socketfilterfw --getglobalstate` / `--getstealthmode` | Não |
| Gatekeeper | `spctl --status` | Não |
| SIP | `csrutil status` | Não |
| Updates | `softwareupdate --list --include-config-data` | Não |
| Hardware/serial | `system_profiler SPHardwareDataType -json` | Não |
| Admin | `dseditgroup -o checkmember` | Não |

Quando usar `sudo python3 auditor.py`:

- Para **reproduzir o contexto de MDM** (Jamf, Kandji, Intune e Mosyle rodam scripts como root).
- Como root, a ferramenta audita o **usuário correto**: primeiro o `SUDO_USER`; se for execução direta como root (MDM), o usuário logado no console (`stat -f %Su /dev/console`).
- O JSON gerado com sudo é devolvido ao seu usuário (`chown` para `SUDO_UID`), com permissão `0640`, porque contém número de série.

Hardening da própria ferramenta:

- Binários chamados por **caminho absoluto**, com `PATH` mínimo, para evitar PATH hijacking sob sudo.
- Locale forçado em `C`, para que o parsing seja estável em Macs em pt_BR.
- Timeout em todo comando.
- Nenhuma alteração no sistema; as remediações são apenas sugeridas no relatório.

**Full Disk Access não é necessário** para os checks atuais.

## 4. Política de conformidade

As regras ficam em `config.py` (`POLICY`) e são declarativas:

```python
{
  "id": "OPS-001", "severity": "medium",
  "source": "system.storage", "field": "free_percent",
  "operator": "min_threshold",
  "params": {"pass": 15.0, "warning": 10.0, "unit": "%"},   # >15 PASS · >10 WARNING · senão FAIL
  "remediation": "...", "references": ["..."]
}
```

Operadores disponíveis: `is_true`, `is_false`, `in`, `max`, `min_threshold` e `version_gte`. O campo opcional `params.on_fail` (`FAIL` ou `WARNING`) define a severidade da não conformidade.

Para personalizar sem editar o código:

```bash
python3 auditor.py --dump-policy > minha_politica.json   # edite limiares, severidades, regras
python3 auditor.py --policy minha_politica.json
```

Se uma coleta falhar (comando ausente, timeout ou saída não reconhecida), a regra vira `WARNING` com o motivo e a auditoria segue. Esse comportamento é configurável em `on_collection_error`.

## 5. Testes

```bash
python3 -m unittest discover -s tests -v
```

## 6. Próximos passos sugeridos

- Distribuir via MDM como script + LaunchDaemon, enviando o JSON para um bucket/SIEM.
- Usar o exit code como Extension Attribute ou Smart Group.
- Novos coletores: screensaver lock, auto-login, Remote Login/SSH, Bluetooth sharing, perfis MDM instalados (`profiles status -type enrollment`), XProtect version, Time Machine.
- Um reporter HTML para auditorias pontuais.
