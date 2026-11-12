"""Model management and verified downloading for OmniHermes.

Downloads official OpenCV Zoo ONNX models and MediaPipe models,
verifying hard-coded SHA-256 checksums before loading.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Optional

# opencv_zoo is pinned to an exact commit so the URLs can never move under us.
OPENCV_ZOO_COMMIT = "48b10fa505aeb51fbd127fc60a5c660040e823b7"

PLUGIN_DATA_NAME = "omnihermes"

# Official model definitions with hard-coded SHA-256 checksums
MODELS: Dict[str, Dict[str, str]] = {
    "yunet": {
        "filename": "face_detection_yunet_2023mar.onnx",
        "url": (
            f"https://media.githubusercontent.com/media/opencv/opencv_zoo/{OPENCV_ZOO_COMMIT}/"
            "models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
        ),
        "sha256": "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
        "size_expected": 232589,
    },
    "sface": {
        "filename": "face_recognition_sface_2021dec.onnx",
        "url": (
            f"https://media.githubusercontent.com/media/opencv/opencv_zoo/{OPENCV_ZOO_COMMIT}/"
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


def get_hermes_home() -> Optional[Path]:
    """Return the active Hermes home (profile-aware) if Hermes exposes it, else HERMES_HOME, else None."""
    for module_name in ("hermes_constants", "hermes_cli.config", "hermes_cli.paths", "hermes_cli"):
        try:
            fn = getattr(importlib.import_module(module_name), "get_hermes_home", None)
            if callable(fn):
                home = fn()
                if home:
                    return Path(home)
        except Exception:
            continue
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        return Path(env_home)
    return None


def _detect_default_hermes_home() -> Optional[Path]:
    """Default Hermes home when running outside Hermes (CLIs): %LOCALAPPDATA%\\hermes on Windows, else ~/.hermes."""
    candidates = []
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        candidates.append(Path(local_app) / "hermes")
    candidates.append(Path.home() / ".hermes")
    for c in candidates:
        if c.is_dir():
            return c
    return None


def _legacy_data_dir() -> Path:
    """Location used by OmniHermes 1.0.0 (shared across all Hermes profiles)."""
    return Path.home() / ".hermes" / PLUGIN_DATA_NAME


def _real_data_roots() -> list:
    roots = [Path.home() / ".hermes", Path(__file__).resolve().parent.parent / ".data"]
    home = get_hermes_home()
    if home is not None:
        roots.append(home)
    return roots


def is_real_data_dir(p: Path) -> bool:
    """Check if path targets the real Hermes home, the legacy data dir, or the repo .data cache."""
    try:
        resolved = p.resolve()
        for root in _real_data_roots():
            root = root.resolve()
            if resolved == root or root in resolved.parents or str(resolved).startswith(str(root)):
                return True
    except Exception:
        pass
    return False


def secure_dir(p: Path) -> Path:
    """Create a directory readable only by the current user (0700 on POSIX)."""
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def write_private_file(path: Path, data: bytes) -> None:
    """Atomically write a file with mode 0600 (owner read/write only)."""
    path = Path(path)
    secure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _migrate_legacy_data(target: Path) -> None:
    """One-time copy of a 1.0.0 enrollment from ~/.hermes/omnihermes into the profile's data dir."""
    legacy = _legacy_data_dir()
    try:
        if legacy.resolve() == target.resolve() or not (legacy / "profile.enc").exists():
            return
        if (target / "profile.enc").exists():
            return
        for name in (".secret_key", "profile.enc", "config.json", "audit.jsonl"):
            src = legacy / name
            if src.exists():
                write_private_file(target / name, src.read_bytes())
        legacy_models = legacy / "models"
        if legacy_models.is_dir() and not (target / "models").exists():
            shutil.move(str(legacy_models), str(target / "models"))
    except Exception:
        pass


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
        return secure_dir(Path(os.environ["HERMES_PLUGIN_DATA_DIR"]))

    # <hermes home>/plugin-data/omnihermes, resolved the same way inside Hermes and from the CLIs,
    # so `python -m omnihermes.enroll` writes where the hook reads.
    p: Optional[Path] = None
    home = get_hermes_home() or _detect_default_hermes_home()
    if home is not None:
        p = home / "plugin-data" / PLUGIN_DATA_NAME
    if p is None:
        p = _legacy_data_dir() if (Path.home() / ".hermes").exists() else (
            Path(__file__).resolve().parent.parent / ".data"
        )

    secure_dir(p)
    _migrate_legacy_data(p)
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

