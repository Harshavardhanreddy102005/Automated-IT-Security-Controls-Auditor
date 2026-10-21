"""Professional consulting-grade HTML audit report generator."""

import html
import json
import os
from typing import Any, Dict, List, Optional

from auditor.models import AuditReport, CheckStatus, Finding, RiskLevel


class HtmlReporter:
    """Generates clean, restrained, consulting-grade HTML security audit reports."""

    @staticmethod
    def _status_badge(status: CheckStatus) -> str:
        style_map = {
            CheckStatus.PASS: ("#e6f4ea", "#137333", "#ceead6", "PASS"),
            CheckStatus.FAIL: ("#fce8e6", "#c5221f", "#fad2cf", "FAIL"),
            CheckStatus.REVIEW: ("#fef7e0", "#b06000", "#feefc3", "REVIEW"),
            CheckStatus.ERROR: ("#f3e8fd", "#7627bb", "#e9d2fd", "ERROR"),
            CheckStatus.NOT_APPLICABLE: ("#f1f3f4", "#5f6368", "#dadce0", "N/A"),
        }
        bg, text, border, label = style_map.get(status, ("#f1f3f4", "#5f6368", "#dadce0", status.value))
        return (
            f'<span class="status-badge" style="background-color: {bg}; color: {text}; border: 1px solid {border};">'
            f'{label}</span>'
        )

    @staticmethod
    def _risk_badge(risk: RiskLevel) -> str:
        style_map = {
            RiskLevel.CRITICAL: ("#fce8e6", "#c5221f", "#fad2cf", "Critical"),
            RiskLevel.HIGH: ("#fef0e7", "#b84200", "#fdd8be", "High"),
            RiskLevel.MEDIUM: ("#fef7e0", "#8a5100", "#feefc3", "Medium"),
            RiskLevel.LOW: ("#e6f4ea", "#137333", "#ceead6", "Low"),
            RiskLevel.INFORMATIONAL: ("#e8f0fe", "#1a73e8", "#d2e3fc", "Info"),
        }
        bg, text, border, label = style_map.get(risk, ("#f1f3f4", "#3c4043", "#dadce0", risk.value.capitalize()))
        return (
            f'<span class="risk-badge" style="background-color: {bg}; color: {text}; border: 1px solid {border};">'
            f'{label}</span>'
        )

    @classmethod
    def _format_evidence(cls, evidence: Any) -> str:
        if isinstance(evidence, (dict, list)):
            formatted = json.dumps(evidence, indent=2)
            return f"<pre class=\"evidence-code\"><code>{html.escape(formatted)}</code></pre>"
        return f"<pre class=\"evidence-code\"><code>{html.escape(str(evidence))}</code></pre>"

    @classmethod
    def generate(cls, report: AuditReport, output_path: Optional[str] = None) -> str:
        """
        Generate complete HTML audit document from AuditReport.
        
        Optionally writes to disk if output_path is provided.
        """
        s = report.summary
        info = report.system_info

        # Build Executive Summary narrative
        exec_summary_points = []
        if s.fail_count > 0:
            failed_controls = [f.check_id for f in report.findings if f.status == CheckStatus.FAIL]
            exec_summary_points.append(
                f"<strong>Attention Required:</strong> {s.fail_count} control(s) failed evaluation "
                f"({', '.join(failed_controls)}) and require corrective configuration to satisfy security baselines."
            )
        if s.review_count > 0:
            review_controls = [f.check_id for f in report.findings if f.status == CheckStatus.REVIEW]
            exec_summary_points.append(
                f"<strong>Review Required:</strong> {s.review_count} control(s) ({', '.join(review_controls)}) "
                "produced configurations requiring human assessment to verify business authorization."
            )
        if s.error_count > 0:
            error_controls = [f.check_id for f in report.findings if f.status == CheckStatus.ERROR]
            exec_summary_points.append(
                f"<strong>Verification Limitation:</strong> {s.error_count} control(s) ({', '.join(error_controls)}) "
                "could not be evaluated due to administrative elevation boundaries."
            )
        if s.pass_count > 0:
            exec_summary_points.append(
                f"<strong>Compliant Controls:</strong> {s.pass_count} of {s.total_checks} evaluated controls "
                "fully satisfied their designated security baseline criteria at the time of execution."
            )

        exec_summary_html = "<br><br>".join(exec_summary_points)

        # Assessment Results Summary Table Rows
        summary_table_rows = ""
        for f in report.findings:
            finding_text = html.escape(f.short_finding or f.explanation)
            summary_table_rows += f"""
            <tr>
                <td style="white-space: nowrap;">{cls._status_badge(f.status)}</td>
                <td><a href="#finding-{html.escape(f.check_id)}" class="table-link"><strong>{html.escape(f.check_id)}</strong></a></td>
                <td>{html.escape(f.control_name)}</td>
                <td style="white-space: nowrap;">{cls._risk_badge(f.risk_level)}</td>
                <td>{finding_text}</td>
            </tr>
            """

        # Detailed Findings Containers
        finding_blocks = ""
        for f in report.findings:
            evidence_html = cls._format_evidence(f.observed_evidence)
            impact_html = html.escape(f.impact) if f.impact else "Unauthorized access or exposure resulting from control degradation."
            verification_step = html.escape(f.suggested_verification) if f.suggested_verification else "Perform manual configuration audit."

            finding_blocks += f"""
            <div class="finding-block status-border-{f.status.value.lower()}" id="finding-{html.escape(f.check_id)}">
                <div class="finding-top">
                    <div class="finding-title-group">
                        <span class="finding-id">{html.escape(f.check_id)}</span>
                        <h3 class="finding-name">{html.escape(f.control_name)}</h3>
                    </div>
                    <div class="finding-badges">
                        {cls._status_badge(f.status)}
                        {cls._risk_badge(f.risk_level)}
                    </div>
                </div>

                <div class="finding-content">
                    <div class="finding-row">
                        <div class="row-label">Assessment Result</div>
                        <div class="row-value">{html.escape(f.explanation)}</div>
                    </div>

                    <div class="finding-row">
                        <div class="row-label">Expected Requirement</div>
                        <div class="row-value requirement-text">{html.escape(f.expected_requirement)}</div>
                    </div>

                    <div class="finding-row">
                        <div class="row-label">Observed Evidence</div>
                        <div class="row-value">{evidence_html}</div>
                    </div>

                    <div class="finding-row">
                        <div class="row-label">Security Impact</div>
                        <div class="row-value">{impact_html}</div>
                    </div>

                    <div class="finding-row remediation-row">
                        <div class="row-label">Recommended Remediation</div>
                        <div class="row-value">
                            <p>{html.escape(f.recommended_remediation)}</p>
                            <div class="verification-subrow">
                                <strong>Verification Step:</strong> {verification_step}
                            </div>
                        </div>
                    </div>

                    <div class="finding-row limitation-row">
                        <div class="row-label">Verification Limitations</div>
                        <div class="row-value text-muted">{html.escape(f.verification_limitations)}</div>
                    </div>
                </div>
            </div>
            """

        # Remediation Priorities Table
        risk_priority_map = {
            RiskLevel.CRITICAL: ("P1 - Immediate", 1),
            RiskLevel.HIGH: ("P2 - High", 2),
            RiskLevel.MEDIUM: ("P3 - Medium", 3),
            RiskLevel.LOW: ("P4 - Low", 4),
            RiskLevel.INFORMATIONAL: ("P5 - Advisory", 5),
        }

        actionable_findings = [
            f for f in report.findings
            if f.status in (CheckStatus.FAIL, CheckStatus.REVIEW, CheckStatus.ERROR)
        ]
        actionable_findings.sort(key=lambda x: risk_priority_map.get(x.risk_level, ("P9", 99))[1])

        remediation_rows = ""
        if actionable_findings:
            for f in actionable_findings:
                prio_label, _ = risk_priority_map.get(f.risk_level, ("P3 - Medium", 3))
                verif_text = html.escape(f.suggested_verification) if f.suggested_verification else "Perform manual configuration audit."
                remediation_rows += f"""
                <tr>
                    <td style="white-space: nowrap;"><strong>{prio_label}</strong></td>
                    <td style="white-space: nowrap;"><a href="#finding-{html.escape(f.check_id)}" class="table-link"><strong>{html.escape(f.check_id)}</strong></a> - {html.escape(f.control_name)}</td>
                    <td>{html.escape(f.recommended_remediation)}</td>
                    <td>{verif_text}</td>
                </tr>
                """
        else:
            remediation_rows = """
            <tr>
                <td colspan="4" style="text-align: center; padding: 18px; color: #137333;">
                    ✓ All evaluated controls satisfied baseline requirements. No immediate remediation actions required.
                </td>
            </tr>
            """

        limitations_html = "".join(f"<li>{html.escape(item)}</li>" for item in report.limitations)
        exec_mode = "Elevated (Administrator)" if info.is_elevated else "Standard User (Non-Elevated)"

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IT Security Controls Assessment &mdash; {html.escape(info.hostname)}</title>
    <style>
        :root {{
            --bg: #ffffff;
            --surface: #ffffff;
            --surface-subtle: #f8fafc;
            --border: #e2e8f0;
            --border-dark: #cbd5e1;
            --text-main: #0f172a;
            --text-secondary: #334155;
            --text-muted: #64748b;
            --primary: #1e3a8a;
            --primary-accent: #2563eb;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: var(--font-sans);
            background-color: #f8fafc;
            color: var(--text-main);
            line-height: 1.5;
            padding: 36px 20px;
        }}

        .report-sheet {{
            max-width: 980px;
            margin: 0 auto;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 44px 48px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}

        /* 1. Header */
        .report-header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}

        .report-header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }}

        .report-org {{
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: var(--primary);
            margin-bottom: 4px;
        }}

        .report-title {{
            font-size: 24px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.3px;
        }}

        .report-id-badge {{
            font-family: var(--font-mono);
            font-size: 11px;
            background: var(--surface-subtle);
            border: 1px solid var(--border);
            padding: 4px 10px;
            border-radius: 4px;
            color: var(--text-secondary);
        }}

        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px 16px;
            background: var(--surface-subtle);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 14px 18px;
            font-size: 12px;
        }}

        .meta-cell {{
            display: flex;
            flex-direction: column;
        }}

        .meta-label {{
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 2px;
        }}

        .meta-val {{
            color: var(--text-secondary);
            font-weight: 600;
        }}

        /* Sections */
        .section {{
            margin-bottom: 36px;
        }}

        .section-heading {{
            font-size: 16px;
            font-weight: 700;
            color: var(--primary);
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-bottom: 16px;
            letter-spacing: -0.2px;
        }}

        /* 2. Executive Summary */
        .exec-summary-box {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-left: 4px solid var(--primary);
            border-radius: 4px;
            padding: 18px 20px;
            font-size: 13.5px;
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 20px;
        }}

        .kpi-row {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin-bottom: 20px;
        }}

        .kpi-card {{
            background: var(--surface-subtle);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 12px 14px;
            text-align: center;
        }}

        .kpi-val {{
            font-size: 24px;
            font-weight: 700;
            line-height: 1.1;
            margin-bottom: 2px;
        }}

        .kpi-lbl {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
        }}

        /* Tables */
        .table-wrap {{
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 4px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            text-align: left;
        }}

        th {{
            background-color: var(--surface-subtle);
            color: var(--text-secondary);
            font-weight: 600;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }}

        td {{
            padding: 11px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            color: var(--text-secondary);
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr:hover td {{
            background-color: #fafbfd;
        }}

        .table-link {{
            color: var(--primary-accent);
            text-decoration: none;
        }}

        .table-link:hover {{
            text-decoration: underline;
        }}

        /* Badges */
        .status-badge, .risk-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10.5px;
            font-weight: 700;
            letter-spacing: 0.4px;
            text-transform: uppercase;
        }}

        /* 4. Detailed Findings */
        .finding-block {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 4px;
            margin-bottom: 18px;
            overflow: hidden;
        }}

        .status-border-pass {{ border-left: 4px solid #137333; }}
        .status-border-fail {{ border-left: 4px solid #c5221f; }}
        .status-border-review {{ border-left: 4px solid #b06000; }}
        .status-border-error {{ border-left: 4px solid #7627bb; }}
        .status-border-not_applicable {{ border-left: 4px solid #5f6368; }}

        .finding-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface-subtle);
            border-bottom: 1px solid var(--border);
            padding: 10px 16px;
        }}

        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .finding-id {{
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 11px;
            color: var(--text-secondary);
            background: #ffffff;
            border: 1px solid var(--border);
            padding: 2px 6px;
            border-radius: 3px;
        }}

        .finding-name {{
            font-size: 13.5px;
            font-weight: 700;
            color: var(--text-main);
        }}

        .finding-badges {{
            display: flex;
            gap: 6px;
        }}

        .finding-content {{
            padding: 14px 18px;
            font-size: 12.5px;
        }}

        .finding-row {{
            display: grid;
            grid-template-columns: 170px 1fr;
            gap: 12px;
            margin-bottom: 10px;
            line-height: 1.5;
        }}

        .finding-row:last-child {{
            margin-bottom: 0;
        }}

        .row-label {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }}

        .row-value {{
            color: var(--text-secondary);
        }}

        .requirement-text {{
            color: #1e293b;
        }}

        .evidence-code {{
            background: #f1f5f9;
            color: #0f172a;
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 8px 12px;
            font-family: var(--font-mono);
            font-size: 11px;
            line-height: 1.4;
            max-height: 180px;
            overflow-y: auto;
        }}

        .remediation-row {{
            background: #f9fbf9;
            border: 1px solid #e2ece3;
            border-radius: 3px;
            padding: 10px 12px;
            margin-top: 6px;
        }}

        .verification-subrow {{
            margin-top: 6px;
            padding-top: 6px;
            border-top: 1px dashed #d1e2d4;
            font-size: 11.5px;
            color: #1b4324;
        }}

        .limitation-row {{
            font-size: 11.5px;
            margin-top: 6px;
        }}

        .text-muted {{
            color: var(--text-muted);
        }}

        /* Limitations list */
        .limitations-list {{
            list-style-type: square;
            padding-left: 20px;
            font-size: 12.5px;
            color: var(--text-secondary);
        }}

        .limitations-list li {{
            margin-bottom: 6px;
        }}

        /* 7. Footer */
        .report-footer {{
            border-top: 1px solid var(--border);
            padding-top: 18px;
            margin-top: 36px;
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-muted);
        }}

        @media print {{
            body {{
                background: #ffffff;
                padding: 0;
            }}
            .report-sheet {{
                border: none;
                box-shadow: none;
                padding: 0;
                max-width: 100%;
            }}
            .finding-block {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-sheet">
        <!-- 1. Report Header -->
        <header class="report-header">
            <div class="report-header-top">
                <div>
                    <div class="report-org">Automated IT Security Controls Auditor</div>
                    <h1 class="report-title">IT Security Controls Assessment Report</h1>
                </div>
                <div>
                    <span class="report-id-badge">{html.escape(report.report_id)}</span>
                </div>
            </div>

            <div class="metadata-grid">
                <div class="meta-cell">
                    <span class="meta-label">Target Host</span>
                    <span class="meta-val">{html.escape(info.hostname)}</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Operating System</span>
                    <span class="meta-val">{html.escape(info.os_name)} {html.escape(info.os_release)} ({html.escape(info.os_architecture)})</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Execution Context</span>
                    <span class="meta-val">{exec_mode}</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Assessment Date</span>
                    <span class="meta-val">{html.escape(report.timestamp[:19].replace("T", " "))} UTC</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Tool Version</span>
                    <span class="meta-val">v{html.escape(report.tool_version)}</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Duration</span>
                    <span class="meta-val">{report.duration_seconds} seconds</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Auditor / Author</span>
                    <span class="meta-val">{html.escape(report.author)}</span>
                </div>
                <div class="meta-cell">
                    <span class="meta-label">Report ID</span>
                    <span class="meta-val">{html.escape(report.report_id)}</span>
                </div>
            </div>
        </header>

        <!-- 2. Executive Summary -->
        <section class="section">
            <h2 class="section-heading">1. Executive Summary</h2>
            <div class="kpi-row">
                <div class="kpi-card">
                    <div class="kpi-val" style="color: var(--primary);">{s.total_checks}</div>
                    <div class="kpi-lbl">Total Checks</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-val" style="color: #137333;">{s.pass_count}</div>
                    <div class="kpi-lbl">Passed</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-val" style="color: #c5221f;">{s.fail_count}</div>
                    <div class="kpi-lbl">Failed</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-val" style="color: #b06000;">{s.review_count}</div>
                    <div class="kpi-lbl">Needs Review</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-val" style="color: #7627bb;">{s.error_count}</div>
                    <div class="kpi-lbl">Could Not Verify</div>
                </div>
            </div>

            <div class="exec-summary-box">
                {exec_summary_html}
            </div>
        </section>

        <!-- 3. Assessment Results Summary Table -->
        <section class="section">
            <h2 class="section-heading">2. Assessment Results Overview</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Control ID</th>
                            <th>Control Name</th>
                            <th>Risk Level</th>
                            <th>Assessment Finding</th>
                        </tr>
                    </thead>
                    <tbody>
                        {summary_table_rows}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- 4. Detailed Findings -->
        <section class="section">
            <h2 class="section-heading">3. Detailed Control Findings &amp; Evidence</h2>
            {finding_blocks}
        </section>

        <!-- 5. Remediation Priorities -->
        <section class="section">
            <h2 class="section-heading">4. Prioritized Remediation Action Plan</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Related Control</th>
                            <th>Recommended Remediation</th>
                            <th>Suggested Verification Step</th>
                        </tr>
                    </thead>
                    <tbody>
                        {remediation_rows}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- 6. Scope and Limitations -->
        <section class="section">
            <h2 class="section-heading">5. Assessment Scope &amp; Limitations</h2>
            <ul class="limitations-list">
                {limitations_html}
            </ul>
        </section>

        <!-- 7. Footer -->
        <footer class="report-footer">
            <span>Automated IT Security Controls Auditor v{html.escape(report.tool_version)} &bull; Report ID: {html.escape(report.report_id)}</span>
            <span>Author: {html.escape(report.author)} &bull; Generated: {html.escape(report.timestamp[:19].replace("T", " "))} UTC</span>
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
