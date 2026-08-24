"""ONNX Model Manager for LENSINT Neural Deepfake Pipeline.

Provides:
1. Model manifest validation with clear, actionable error messages.
2. Automatic manifest skeleton generation to guide users through model setup.
3. Model integrity verification (SHA-256) with human-readable diagnostics.
4. Status reporting for CLI `lensint model-info` sub-command.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("lensint.model_manager")

# Default model directory
DEFAULT_MODEL_DIR = Path.home() / ".lensint" / "models"

# Required manifest fields and their types
REQUIRED_MANIFEST_FIELDS: Dict[str, type] = {
    "model_sha256": str,
    "model_name": str,
    "input_size": list,
    "mean": list,
    "std": list,
    "expected_classes": int,
    "output_activation": str,
    "tensor_layout": str,
}

VALID_ACTIVATIONS = ("softmax", "sigmoid", "none")
VALID_LAYOUTS = ("NCHW", "NHWC")
VALID_COLOR_SPACES = ("RGB", "BGR")


class ModelSetupError(RuntimeError):
    """Raised when the ONNX model or manifest is missing/invalid."""
    pass


def get_model_dir() -> Path:
    """Return configured model directory."""
    try:
        from lensint.config import config
        model_dir = getattr(config, "onnx_model_dir", None)
        if model_dir:
            return Path(model_dir)
    except Exception:
        pass
    env_path = os.getenv("LENSINT_ONNX_MODEL_DIR", "")
    if env_path:
        return Path(env_path)
    return DEFAULT_MODEL_DIR


def get_model_status() -> Dict[str, Any]:
    """Return a structured status report for the neural ONNX pipeline."""
    model_dir = get_model_dir()
    model_path = model_dir / "deepfake_detector.onnx"
    manifest_path = model_dir / "manifest.json"

    issues: List[str] = []
    warnings: List[str] = []
    manifest_data: Dict[str, Any] = {}

    if not model_path.exists():
        issues.append(
            f"ONNX model file not found: {model_path}\n"
            "  -> Place your deepfake_detector.onnx file in that directory,\n"
            "     or set LENSINT_ONNX_MODEL_DIR env var to the parent directory."
        )
    else:
        model_size_mb = model_path.stat().st_size / (1024 * 1024)
        if model_size_mb < 0.1:
            warnings.append(
                f"ONNX model file is unusually small ({model_size_mb:.2f} MB). "
                "May be corrupt or a placeholder."
            )

    if not manifest_path.exists():
        issues.append(
            f"Model manifest not found: {manifest_path}\n"
            "  -> Run lensint model-setup to generate a manifest skeleton,\n"
            "     then fill in the correct values for your model."
        )
    else:
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
        except json.JSONDecodeError as e:
            issues.append(f"manifest.json contains invalid JSON: {e}")

        if manifest_data:
            manifest_issues = _validate_manifest(manifest_data)
            issues.extend(manifest_issues)

    # Integrity check only if both files present and manifest valid
    if not issues and model_path.exists() and manifest_data:
        expected_sha = manifest_data.get("model_sha256", "").lower()
        if expected_sha and not expected_sha.startswith("replace_"):
            actual_sha = _sha256_file(model_path)
            if actual_sha != expected_sha:
                issues.append(
                    "Model integrity check FAILED.\n"
                    f"  Expected SHA-256: {expected_sha}\n"
                    f"  Actual   SHA-256: {actual_sha}\n"
                    "  -> The model file may be corrupt or replaced. "
                    "Recompute the hash and update manifest.json."
                )

    onnx_available = False
    try:
        import onnxruntime  # type: ignore  # noqa: F401
        onnx_available = True
    except ImportError:
        warnings.append(
            "onnxruntime is not installed. Neural ONNX inference is disabled.\n"
            "  -> Install with: pip install onnxruntime"
        )

    model_name = manifest_data.get("model_name", "unknown") if manifest_data else "unknown"

    return {
        "available": (not issues) and onnx_available,
        "onnx_runtime_installed": onnx_available,
        "model_path": str(model_path) if model_path.exists() else None,
        "manifest_path": str(manifest_path) if manifest_path.exists() else None,
        "model_name": model_name,
        "manifest_data": manifest_data,
        "issues": issues,
        "warnings": warnings,
    }


def _validate_manifest(manifest: Dict[str, Any]) -> List[str]:
    """Validate all required manifest fields and return error strings."""
    errors: List[str] = []

    for field, expected_type in REQUIRED_MANIFEST_FIELDS.items():
        if field not in manifest:
            errors.append(f"manifest.json missing required field: '{field}'")
            continue
        value = manifest[field]
        if not isinstance(value, expected_type):
            errors.append(
                f"manifest.json field '{field}' has wrong type: "
                f"expected {expected_type.__name__}, got {type(value).__name__}"
            )

    if "input_size" in manifest and isinstance(manifest["input_size"], list):
        if (
            len(manifest["input_size"]) != 2
            or not all(isinstance(v, int) and v > 0 for v in manifest["input_size"])
        ):
            errors.append(
                "manifest.json 'input_size' must be [width, height] "
                "with two positive integers."
            )

    for vec_field in ("mean", "std"):
        if vec_field in manifest and isinstance(manifest[vec_field], list):
            if len(manifest[vec_field]) != 3:
                errors.append(
                    f"manifest.json '{vec_field}' must contain exactly 3 float "
                    "values (R, G, B)."
                )

    if "output_activation" in manifest:
        activation = str(manifest["output_activation"]).lower()
        if activation not in VALID_ACTIVATIONS:
            errors.append(
                f"manifest.json 'output_activation' must be one of "
                f"{VALID_ACTIVATIONS}, got '{manifest['output_activation']}'."
            )

    if "tensor_layout" in manifest:
        layout = str(manifest["tensor_layout"]).upper()
        if layout not in VALID_LAYOUTS:
            errors.append(
                f"manifest.json 'tensor_layout' must be one of "
                f"{VALID_LAYOUTS}, got '{manifest['tensor_layout']}'."
            )

    if "color_space" in manifest:
        cs = str(manifest["color_space"]).upper()
        if cs not in VALID_COLOR_SPACES:
            errors.append(
                f"manifest.json 'color_space' must be one of "
                f"{VALID_COLOR_SPACES}, got '{manifest['color_space']}'."
            )

    if "expected_classes" in manifest and isinstance(manifest["expected_classes"], int):
        if manifest["expected_classes"] <= 0:
            errors.append(
                "manifest.json 'expected_classes' must be a positive integer."
            )

    if "ai_class_index" in manifest and "expected_classes" in manifest:
        idx = manifest.get("ai_class_index", 0)
        n_classes = manifest.get("expected_classes", 1)
        if isinstance(idx, int) and isinstance(n_classes, int):
            if idx < 0 or idx >= n_classes:
                errors.append(
                    f"manifest.json 'ai_class_index' ({idx}) is out of bounds "
                    f"for expected_classes={n_classes}."
                )

    return errors


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file in streaming mode."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_manifest_skeleton(output_path: Optional[Path] = None) -> Path:
    """Generate a manifest.json skeleton with documentation.

    If the model .onnx file already exists in the same directory,
    its SHA-256 is pre-filled automatically.
    """
    if output_path is None:
        output_path = get_model_dir() / "manifest.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    model_path = output_path.parent / "deepfake_detector.onnx"
    sha256_hint = ""
    if model_path.exists():
        sha256_hint = _sha256_file(model_path)
        logger.info("Pre-filled model SHA-256: %s", sha256_hint)

    skeleton = {
        "_comment": (
            "LENSINT Neural Deepfake Model Manifest. "
            "Fill in all fields, then remove _comment and _field_docs before production use."
        ),
        "model_name": "deepfake_detector",
        "model_sha256": sha256_hint or "REPLACE_WITH_SHA256_HEX_OF_YOUR_ONNX_FILE",
        "input_size": [224, 224],
        "color_space": "RGB",
        "tensor_layout": "NCHW",
        "mean": [0.485, 0.456, 0.406],
        "std": [0.229, 0.224, 0.225],
        "expected_classes": 2,
        "ai_class_index": 1,
        "output_activation": "softmax",
        "_field_docs": {
            "model_sha256": (
                "SHA-256 hex digest of your .onnx file. "
                "Compute with: sha256sum deepfake_detector.onnx"
            ),
            "input_size": "[width, height] the model expects as input.",
            "color_space": "RGB or BGR channel ordering before normalization.",
            "tensor_layout": "NCHW (PyTorch/channels-first) or NHWC (TF/channels-last).",
            "mean": "Per-channel RGB mean for normalization (ImageNet defaults shown).",
            "std": "Per-channel RGB std dev for normalization (ImageNet defaults shown).",
            "expected_classes": "Number of output logits the model produces.",
            "ai_class_index": "Index of the AI/synthetic class in the output vector.",
            "output_activation": (
                "How to interpret logits: "
                "softmax (multi-class), sigmoid (binary), or none (already probabilities)."
            ),
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2, ensure_ascii=False)

    return output_path


def print_model_status_report() -> bool:
    """Print a human-readable model status report. Returns True if model is ready."""
    status = get_model_status()

    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()

        if status["available"]:
            content = (
                f"Model: [cyan]{status['model_name']}[/cyan]\n"
                f"Path:  [dim]{status['model_path']}[/dim]"
            )
            console.print(Panel(
                content,
                title="[bold green]Neural ONNX Pipeline — READY[/bold green]",
                border_style="green",
            ))
        else:
            lines = []
            for issue in status["issues"]:
                lines.append(f"[red]• {issue}[/red]")
            for warning in status["warnings"]:
                lines.append(f"[yellow]warning: {warning}[/yellow]")
            if not lines:
                lines.append("[yellow]onnxruntime package not installed.[/yellow]")
            console.print(Panel(
                "\n".join(lines),
                title="[bold red]Neural ONNX Pipeline — NOT AVAILABLE[/bold red]",
                border_style="red",
            ))
            console.print(
                "\n[dim]Run [bold]lensint model-setup[/bold] to generate "
                "a manifest skeleton in the model directory.[/dim]"
            )

        for w in status.get("warnings", []):
            if status["available"]:
                console.print(f"[yellow]warning: {w}[/yellow]")

    except ImportError:
        if status["available"]:
            print(f"[OK] Neural ONNX Pipeline ready — {status['model_name']}")
        else:
            print("[ERROR] Neural ONNX Pipeline NOT available:")
            for issue in status["issues"]:
                print(f"  - {issue}")
            for warning in status["warnings"]:
                print(f"  ! {warning}")

    return status["available"]
