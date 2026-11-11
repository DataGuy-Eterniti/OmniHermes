"""Model management and verified downloading for OmniHermes.

Downloads official OpenCV Zoo ONNX models and MediaPipe models,
verifying hard-coded SHA-256 checksums before loading.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional

# Official model definitions with hard-coded SHA-256 checksums
MODELS: Dict[str, Dict[str, str]] = {
    "yunet": {
        "filename": "face_detection_yunet_2023mar.onnx",
        "url": (
            "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/"
            "models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
        ),
        "sha256": "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
        "size_expected": 232589,
    },
    "sface": {
        "filename": "face_recognition_sface_2021dec.onnx",
        "url": (
            "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/"
            "models/face_recognition_sface/face_recognition_sface_2021dec.onnx"
        ),
        "sha256": "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
        "size_expected": 38696353,
    },
    "face_landmarker": {
        "filename": "face_landmarker.task",
        "url": (
            "https://storage.googleapis.com/mediapipe-models/face_landmarker/"
            "face_landmarker/float16/1/face_landmarker.task"
        ),
        "sha256": "64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff",
        "size_expected": 3758596,
    },
    "minifasnet": {
        "filename": "face_antispoof_minifasnet.onnx",
        "url": (
            "https://github.com/facenox/face-antispoof-onnx/releases/download/"
            "v1.0.0/best_model.onnx"
        ),
        "sha256": "af2381b88f38769222ed93379e12444e2a50814575de1c46170de570c55a42b6",
        "size_expected": 1912594,
    },
}


def is_real_data_dir(p: Path) -> bool:
    """Check if path targets the real user .hermes configuration or repo .data cache."""
    try:
        resolved = p.resolve()
        hermes_home = (Path.home() / ".hermes").resolve()
        if resolved == hermes_home or hermes_home in resolved.parents or str(resolved).startswith(str(hermes_home)):
            return True
        data_cache = (Path(__file__).resolve().parent.parent / ".data").resolve()
        if resolved == data_cache or data_cache in resolved.parents or str(resolved).startswith(str(data_cache)):
            return True
    except Exception:
        pass
    return False


def assert_not_real_data_dir(p: Path, operation: str = "write") -> None:
    """Hard security guard ensuring test executions never touch real user profiles or logs."""
    if os.environ.get("OMNIHERMES_TEST_MODE") == "1":
        if is_real_data_dir(p):
            raise RuntimeError(
                f"OMNIHERMES_TEST_MODE guard: Attempted {operation} on real user/repo data directory: {p}! "
                "Tests must use an isolated temporary directory (tempfile / pytest tmp_path)."
            )


def get_default_data_dir() -> Path:
    """Resolve data directory for models, profiles, and audit log.
    
    Guarded in test mode to guarantee zero leakage into real user data.
    """
    if os.environ.get("OMNIHERMES_TEST_MODE") == "1":
        if "HERMES_PLUGIN_DATA_DIR" in os.environ:
            p = Path(os.environ["HERMES_PLUGIN_DATA_DIR"])
            if is_real_data_dir(p):
                raise RuntimeError(
                    f"OMNIHERMES_TEST_MODE guard: HERMES_PLUGIN_DATA_DIR points to real user data: {p}! "
                    "Tests must specify an isolated temporary directory."
                )
            p.mkdir(parents=True, exist_ok=True)
            return p
        raise RuntimeError(
            "OMNIHERMES_TEST_MODE guard: get_default_data_dir() called in test mode without an isolated "
            "HERMES_PLUGIN_DATA_DIR! Tests must never access real user data."
        )

    if "HERMES_PLUGIN_DATA_DIR" in os.environ:
        p = Path(os.environ["HERMES_PLUGIN_DATA_DIR"])
    elif (Path.home() / ".hermes").exists():
        p = Path.home() / ".hermes" / "omnihermes"
    else:
        p = Path(__file__).resolve().parent.parent / ".data"
    p.mkdir(parents=True, exist_ok=True)
    return p


def verify_file_sha256(file_path: Path, expected_sha256: str) -> bool:
    """Verify SHA-256 hash of a file."""
    if not file_path.exists():
        return False
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower() == expected_sha256.lower()


def download_model(name: str, target_path: Path) -> Path:
    """Download a model file with verification. Checks local cache first."""
    spec = MODELS[name]
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check if already present and valid at target
    if target_path.exists() and verify_file_sha256(target_path, spec["sha256"]):
        return target_path

    # Check local fallback cache (.data/models/) before hitting internet
    local_cache = Path(__file__).resolve().parent.parent / ".data" / "models" / spec["filename"]
    if local_cache.exists() and verify_file_sha256(local_cache, spec["sha256"]):
        import shutil
        shutil.copyfile(local_cache, target_path)
        return target_path

    temp_path = target_path.with_suffix(".tmp")
    if temp_path.exists():
        temp_path.unlink()

    print(f"[OmniHermes] Downloading {name} ({spec['filename']})...")
    import urllib.request
    req = urllib.request.Request(spec["url"], headers={"User-Agent": "Mozilla/5.0 (OmniHermes)"})
    with urllib.request.urlopen(req) as response, open(temp_path, "wb") as out_file:
        while chunk := response.read(65536):
            out_file.write(chunk)

    # Verify SHA-256 checksum
    if not verify_file_sha256(temp_path, spec["sha256"]):
        temp_path.unlink(missing_ok=True)
        raise ValueError(
            f"Security Error: Checksum verification failed for model '{name}'! "
            f"Expected {spec['sha256']}."
        )

    # Rename temp to target atomically
    temp_path.replace(target_path)
    print(f"[OmniHermes] Verified {name} (SHA-256: {spec['sha256'][:16]}...)")
    return target_path


def ensure_models(data_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Ensure all required vision models are present and valid."""
    base_dir = data_dir or get_default_data_dir()
    models_dir = base_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, Path] = {}
    for name, spec in MODELS.items():
        dest = models_dir / spec["filename"]
        paths[name] = download_model(name, dest)

    return paths

