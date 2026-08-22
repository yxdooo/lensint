import json
import os
from typing import Optional
from lensint.core.models import AnalysisResult


def render_json_report(result: AnalysisResult, indent: int = 2) -> str:
    """Serialize AnalysisResult object to formatted JSON string."""
    return json.dumps(result.to_dict(), indent=indent, default=str)


def export_json_report(result: AnalysisResult, output_path: str, indent: int = 2) -> str:
    """Export JSON report to specified destination path."""
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(render_json_report(result, indent=indent))
    return abs_path
