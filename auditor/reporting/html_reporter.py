"""HTML audit report generator producing a self-contained, executive-ready dashboard."""

import html
import json
import os
from typing import Any, Dict, List, Optional

from auditor.models import AuditReport, CheckStatus, Finding, RiskLevel


class HtmlReporter:
    """Generates standalone, responsive HTML security audit reports with embedded styling."""

    @staticmethod
    def _status_badge(status: CheckStatus) -> str:
        color_map = {
            CheckStatus.PASS: ("#dcfce7", "#15803d", "PASS"),
            CheckStatus.FAIL: ("#fee2e2", "#b91c1c", "FAIL"),
            CheckStatus.REVIEW: ("#fef3c7", "#b45309", "REVIEW"),
            CheckStatus.ERROR: ("#ede9fe", "#6d28d9", "ERROR"),
            CheckStatus.NOT_APPLICABLE: ("#f1f5f9", "#475569", "N/A"),
        }
        bg, text, label = color_map.get(status, ("#f1f5f9", "#475569", status.value))
        return f'<span class="badge" style="background-color: {bg}; color: {text}; font-weight: 700;">{label}</span>'

    @staticmethod
    def _risk_badge(risk: RiskLevel) -> str:
        color_map = {
            RiskLevel.CRITICAL: ("#7f1d1d", "#fee2e2", "CRITICAL"),
            RiskLevel.HIGH: ("#c2410c", "#ffedd5", "HIGH"),
            RiskLevel.MEDIUM: ("#b45309", "#fef3c7", "MEDIUM"),
            RiskLevel.LOW: ("#15803d", "#dcfce7", "LOW"),
            RiskLevel.INFORMATIONAL: ("#0369a1", "#e0f2fe", "INFO"),
        }
        text, bg, label = color_map.get(risk, ("#334155", "#f1f5f9", risk.value))
        return f'<span class="badge" style="background-color: {bg}; color: {text}; font-weight: 600;">{label}</span>'

    @classmethod
    def _format_evidence(cls, evidence: Any) -> str:
        if isinstance(evidence, (dict, list)):
            formatted = json.dumps(evidence, indent=2)
            return f"<pre><code>{html.escape(formatted)}</code></pre>"
        return f"<pre><code>{html.escape(str(evidence))}</code></pre>"

    @classmethod
    def generate(cls, report: AuditReport, output_path: Optional[str] = None) -> str:
        """
        Generate complete HTML document from AuditReport.
        
        Optionally writes to disk if output_path is provided.
        """
        s = report.summary
        info = report.system_info

        # Filter prioritized actions (FAIL and REVIEW findings sorted by risk)
        risk_priority = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 4,
            RiskLevel.INFORMATIONAL: 5,
        }
        actionable_findings = [
            f for f in report.findings
            if f.status in (CheckStatus.FAIL, CheckStatus.REVIEW, CheckStatus.ERROR)
        ]
        actionable_findings.sort(key=lambda x: risk_priority.get(x.risk_level, 99))

        remediation_rows = ""
        if actionable_findings:
            for f in actionable_findings:
                remediation_rows += f"""
                <tr>
                    <td><strong>{html.escape(f.check_id)}</strong></td>
                    <td>{html.escape(f.control_name)}</td>
                    <td>{cls._status_badge(f.status)}</td>
                    <td>{cls._risk_badge(f.risk_level)}</td>
                    <td>{html.escape(f.recommended_remediation)}</td>
                </tr>
                """
        else:
            remediation_rows = """
            <tr>
                <td colspan="5" style="text-align:center; padding: 20px; color: #15803d; font-weight: 600;">
                    ✓ All evaluated controls satisfied their baseline requirements. No immediate remediation actions required.
                </td>
            </tr>
            """

        finding_cards = ""
        for f in report.findings:
            evidence_html = cls._format_evidence(f.observed_evidence)
            finding_cards += f"""
            <div class="finding-card status-{f.status.value.lower()}">
                <div class="finding-header">
                    <div class="finding-title">
                        <span class="finding-id">{html.escape(f.check_id)}</span>
                        <h3>{html.escape(f.control_name)}</h3>
                    </div>
                    <div class="finding-badges">
                        {cls._risk_badge(f.risk_level)}
                        {cls._status_badge(f.status)}
                    </div>
                </div>
                
                <div class="finding-body">
                    <div class="field-group">
                        <div class="field-label">Expected Baseline Requirement</div>
                        <div class="field-value">{html.escape(f.expected_requirement)}</div>
                    </div>

                    <div class="field-group">
                        <div class="field-label">Evaluation & Risk Analysis</div>
                        <div class="field-value">{html.escape(f.explanation)}</div>
                    </div>

                    <div class="field-group">
                        <div class="field-label">Observed Configuration Evidence</div>
                        <div class="field-value evidence-box">{evidence_html}</div>
                    </div>

                    <div class="field-group remediation-box">
                        <div class="field-label">Recommended Remediation</div>
                        <div class="field-value">{html.escape(f.recommended_remediation)}</div>
                    </div>

                    <div class="field-group limitations-box">
                        <div class="field-label">Control Verification Limitations</div>
                        <div class="field-value">{html.escape(f.verification_limitations)}</div>
                    </div>
                </div>
            </div>
            """

        limitations_html = "".join(f"<li>{html.escape(item)}</li>" for item in report.limitations)

        score_color = "#15803d" if s.compliance_score_percent >= 80 else ("#b45309" if s.compliance_score_percent >= 50 else "#b91c1c")

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IT Security Controls Audit Report - {html.escape(info.hostname)}</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --primary: #1e3a8a;
            --primary-light: #3b82f6;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: var(--font-sans);
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 30px 20px;
        }}

        .container {{
            max-width: 1180px;
            margin: 0 auto;
        }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 32px 36px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-bottom: 24px;
        }}

        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.15);
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}

        .header h1 {{
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .header-subtitle {{
            color: #94a3b8;
            font-size: 14px;
            margin-top: 4px;
        }}

        .header-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            font-size: 13px;
            color: #cbd5e1;
        }}

        .meta-item strong {{
            color: #ffffff;
            display: inline-block;
            margin-right: 6px;
        }}

        /* Metrics Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}

        .metric-card {{
            background: var(--surface);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        .metric-value {{
            font-size: 32px;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 6px;
        }}

        .metric-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
        }}

        /* Section Styling */
        .section {{
            background: var(--surface);
            border-radius: 12px;
            border: 1px solid var(--border);
            padding: 28px;
            margin-bottom: 28px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        .section-title {{
            font-size: 20px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 8px;
        }}

        .section-desc {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 20px;
        }}

        /* Table */
        .table-responsive {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            text-align: left;
        }}

        th {{
            background-color: #f8fafc;
            color: var(--text-secondary);
            font-weight: 600;
            padding: 12px 14px;
            border-bottom: 2px solid var(--border);
            white-space: nowrap;
        }}

        td {{
            padding: 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        /* Finding Cards */
        .finding-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-left-width: 6px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.04);
            overflow: hidden;
        }}

        .finding-card.status-pass {{
            border-left-color: #10b981;
        }}

        .finding-card.status-fail {{
            border-left-color: #ef4444;
        }}

        .finding-card.status-review {{
            border-left-color: #f59e0b;
        }}

        .finding-card.status-error {{
            border-left-color: #8b5cf6;
        }}

        .finding-card.status-not_applicable {{
            border-left-color: #64748b;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8fafc;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
            gap: 12px;
        }}

        .finding-title {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .finding-id {{
            font-family: var(--font-mono);
            font-weight: 700;
            background: #e2e8f0;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            color: #334155;
        }}

        .finding-header h3 {{
            font-size: 16px;
            font-weight: 600;
        }}

        .finding-badges {{
            display: flex;
            gap: 8px;
            align-items: center;
        }}

        .finding-body {{
            padding: 20px;
        }}

        .field-group {{
            margin-bottom: 16px;
        }}

        .field-group:last-child {{
            margin-bottom: 0;
        }}

        .field-label {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}

        .field-value {{
            font-size: 14px;
            color: var(--text-primary);
        }}

        .remediation-box {{
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 6px;
            padding: 12px 16px;
        }}

        .remediation-box .field-label {{
            color: #166534;
        }}

        .limitations-box {{
            background: #fefce8;
            border: 1px solid #fef08a;
            border-radius: 6px;
            padding: 12px 16px;
            margin-top: 12px;
        }}

        .limitations-box .field-label {{
            color: #854d0e;
        }}

        .evidence-box pre {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 14px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 12px;
            line-height: 1.4;
            margin-top: 6px;
        }}

        /* Limitations list */
        .disclaimer-list {{
            list-style-type: square;
            padding-left: 20px;
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .disclaimer-list li {{
            margin-bottom: 8px;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            padding: 20px 0;
        }}

        @media print {{
            body {{
                padding: 0;
                background: #ffffff;
            }}
            .header {{
                background: #1e293b !important;
                color: #ffffff !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            .section, .finding-card {{
                box-shadow: none;
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-top">
                <div>
                    <h1>Automated IT Security Controls Auditor</h1>
                    <div class="header-subtitle">Host Configuration Assessment & Compliance Evaluation</div>
                </div>
                <div>
                    <span class="badge" style="background-color: rgba(255,255,255,0.15); color: #ffffff; font-size: 12px;">v{html.escape(report.tool_version)}</span>
                </div>
            </div>

            <div class="header-meta">
                <div class="meta-item"><strong>Target Host:</strong> {html.escape(info.hostname)}</div>
                <div class="meta-item"><strong>Operating System:</strong> {html.escape(info.os_name)} {html.escape(info.os_release)} ({html.escape(info.os_architecture)})</div>
                <div class="meta-item"><strong>Audit Timestamp:</strong> {html.escape(report.timestamp)}</div>
                <div class="meta-item"><strong>Execution Context:</strong> {"Elevated (Administrator)" if info.is_elevated else "Standard User (Non-Elevated)"}</div>
            </div>
        </header>

        <!-- Metrics Overview -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value" style="color: var(--primary);">{s.total_checks}</div>
                <div class="metric-label">Total Controls</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #15803d;">{s.pass_count}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #b91c1c;">{s.fail_count}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #b45309;">{s.review_count}</div>
                <div class="metric-label">Needs Review</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #6d28d9;">{s.error_count}</div>
                <div class="metric-label">Errors / Priv</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: {score_color};">{s.compliance_score_percent}%</div>
                <div class="metric-label">Control Pass Rate</div>
            </div>
        </div>

        <!-- Prioritized Remediation Action Plan -->
        <section class="section">
            <h2 class="section-title">Prioritized Remediation Action Plan</h2>
            <div class="section-desc">Identified gaps, privilege limitations, and items requiring human review, prioritized by risk level.</div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Control ID</th>
                            <th>Control Name</th>
                            <th>Status</th>
                            <th>Risk Level</th>
                            <th>Recommended Remediation / Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {remediation_rows}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Detailed Findings -->
        <section class="section">
            <h2 class="section-title">Detailed Control Findings & Evidence</h2>
            <div class="section-desc">Individual evaluation records, observed system state, gap analysis, and verification boundaries.</div>
            {finding_cards}
        </section>

        <!-- Scope & Assessment Limitations -->
        <section class="section">
            <h2 class="section-title">Audit Scope & Methodological Limitations</h2>
            <div class="section-desc">Critical context for interpreting these audit findings within enterprise cyber risk frameworks.</div>
            <ul class="disclaimer-list">
                {limitations_html}
            </ul>
        </section>

        <footer class="footer">
            Automated IT Security Controls Auditor • Educational Cyber Risk Assessment Tool • Generated for {html.escape(info.hostname)}
        </footer>
    </div>
</body>
</html>
"""
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_template)

        return html_template
