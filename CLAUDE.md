# CLAUDE.md — Cloud Detection & Response (CDR) Scanner

## Project Overview

Cloud Detection & Response Scanner — a cloud audit log analysis engine that detects threats, misconfigurations, and suspicious activity across AWS CloudTrail, Azure Activity/Sign-in, and GCP Audit logs, mapped to the MITRE ATT&CK Cloud Matrix.

- **Language**: Python 3.10+ (no external dependencies — pure stdlib)
- **Scanner file**: `cdr_scanner.py` (single self-contained file)
- **Version**: 1.0.0
- **License**: MIT

## Architecture

1. **Module-level constants** — `MITRE_MAP` (38 technique IDs), `COMPLIANCE_MAP` (7 frameworks).
2. **`Finding` dataclass** — `rule_id, name, tactic, severity, cloud, source_file, event_time, event_name, actor, source_ip, region, description, recommendation, mitre, compliance, raw_event`.
3. **Detection rule lists** — `AWS_RULES` (35), `AZURE_RULES` (14), `GCP_RULES` (10). Each rule has `id, tactic, name, severity, event_names, condition (lambda), description, recommendation, mitre, compliance`.
4. **Condition helpers** — lambda-based contextual analysis functions (e.g. `_ct_mfa_used`, `_ct_cross_account`, `_ct_sg_open`, `_az_global_admin`, `_gcp_owner_editor`).
5. **Log parsers** — `_parse_cloudtrail`, `_parse_azure_log`, `_parse_gcp_log` handle various JSON envelopes.
6. **Auto-detection** — `_detect_cloud` identifies cloud provider from JSON structure.
7. **Field extractors** — `_extract_aws_fields`, `_extract_azure_fields`, `_extract_gcp_fields`.
8. **`CDRScanner` class** — `scan_path` → `_scan_directory` → `_scan_file` → `_analyse_events`.
9. **CLI**: `argparse` with `target`, `--json`, `--html`, `--severity`, `--verbose`, `--version`.
10. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## Detection Rules (59 rules across 9 MITRE ATT&CK tactics)

| Cloud | Tactic | Rule IDs | Count |
|-------|--------|----------|-------|
| AWS | Initial Access | CDR-AWS-IA-001 to 004 | 4 |
| AWS | Persistence | CDR-AWS-PE-001 to 005 | 5 |
| AWS | Privilege Escalation | CDR-AWS-PR-001 to 004 | 4 |
| AWS | Defense Evasion | CDR-AWS-DE-001 to 007 | 7 |
| AWS | Credential Access | CDR-AWS-CA-001 to 003 | 3 |
| AWS | Discovery | CDR-AWS-DI-001 to 002 | 2 |
| AWS | Exfiltration | CDR-AWS-EX-001 to 003 | 3 |
| AWS | Network | CDR-AWS-NET-001 to 003 | 3 |
| AWS | Impact | CDR-AWS-IM-001 to 005 | 5 |
| Azure | Initial Access | CDR-AZ-IA-001 to 003 | 3 |
| Azure | Persistence | CDR-AZ-PE-001 to 003 | 3 |
| Azure | Privilege Escalation | CDR-AZ-PR-001 to 002 | 2 |
| Azure | Defense Evasion | CDR-AZ-DE-001 to 003 | 3 |
| Azure | Network | CDR-AZ-NET-001 | 1 |
| Azure | Impact | CDR-AZ-IM-001 to 002 | 2 |
| GCP | Persistence | CDR-GCP-PE-001 to 002 | 2 |
| GCP | Privilege Escalation | CDR-GCP-PR-001 to 002 | 2 |
| GCP | Defense Evasion | CDR-GCP-DE-001 to 002 | 2 |
| GCP | Exfiltration | CDR-GCP-EX-001 | 1 |
| GCP | Network | CDR-GCP-NET-001 | 1 |
| GCP | Impact | CDR-GCP-IM-001 to 002 | 2 |

## MITRE ATT&CK Techniques (38 mapped)

T1078, T1078.004, T1110, T1110.001, T1136, T1136.003, T1098, T1098.001, T1098.003, T1548, T1484, T1484.002, T1562, T1562.001, T1562.008, T1530, T1537, T1580, T1526, T1190, T1021, T1021.004, T1021.001, T1496, T1485, T1486, T1552, T1552.005, T1528, T1556, T1525, T1578, T1578.002, T1578.003, T1578.004, T1199, T1535, T1619, T1613

## Compliance Frameworks

- **CIS AWS Foundations Benchmark**
- **CIS Azure Foundations Benchmark**
- **CIS GCP Foundations Benchmark**
- **NIST 800-53**
- **SOC 2 Type II**
- **PCI-DSS v4.0**
- **ISO 27001:2022**

## File Types Scanned

`.json`, `.log` — cloud audit log files in JSON format.

## Development Guidelines

### Adding New Rules

1. Add the rule dict to `AWS_RULES`, `AZURE_RULES`, or `GCP_RULES`.
2. Follow the ID pattern: `CDR-{CLOUD}-{TACTIC}-{NNN}` (e.g. `CDR-AWS-DE-008`).
3. Tactic abbreviations: IA (Initial Access), PE (Persistence), PR (Privilege Escalation), DE (Defense Evasion), CA (Credential Access), DI (Discovery), EX (Exfiltration), NET (Network), IM (Impact).
4. Every rule must include: `id`, `tactic`, `name`, `severity`, `event_names` (list), `condition` (lambda), `description`, `recommendation`, `mitre` (list of technique IDs), `compliance` (list of framework keys).
5. If the condition requires contextual analysis, add a helper function prefixed with `_ct_` (AWS), `_az_` (Azure), or `_gcp_` (GCP).

### Testing

```bash
python cdr_scanner.py tests/samples/ --verbose
python cdr_scanner.py tests/samples/ --json report.json --html report.html
```

### Test Sample Files

- `tests/samples/cloudtrail_malicious.json` — AWS CloudTrail attack simulation (35 events)
- `tests/samples/azure_activity_malicious.json` — Azure Activity/Sign-in threats (16 events)
- `tests/samples/gcp_audit_malicious.json` — GCP Audit Log threats (10 events)

## Conventions

- Single-file scanner — all rules, engine, and reports in `cdr_scanner.py`.
- No external dependencies — only Python stdlib.
- HTML reports use dark theme with red gradient (`#dc2626` → `#991b1b` → `#7f1d1d`).
- Keep rule descriptions actionable — always include a concrete `recommendation`.
- Use British English in descriptions (sanitise, unauthorised, etc.) for consistency.
