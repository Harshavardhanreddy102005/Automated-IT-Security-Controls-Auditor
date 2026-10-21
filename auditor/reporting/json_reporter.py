"""JSON report generator for machine-readable audit outputs."""

import json
import os
from typing import Optional

from auditor.models import AuditReport


class JsonReporter:
    """Generates standardized JSON reports for SIEM or automated compliance tracking."""

    @staticmethod
    def generate(report: AuditReport, output_path: Optional[str] = None) -> str:
        """
        Serialize AuditReport to JSON string and optionally save to file.
        
        Returns the formatted JSON string.
        """
        payload = report.to_dict()
        json_content = json.dumps(payload, indent=2, ensure_ascii=False)

        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_content)

        return json_content
