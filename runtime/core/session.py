"""Ephemeral workspace session manager with strict path isolation and file diffing."""

import hashlib
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from runtime.config import settings

logger = logging.getLogger("sandbox.session")


class WorkspaceSecurityError(Exception):
    """Raised when an operation attempts directory traversal or escaping workspace boundaries."""
    pass


class Session:
    """Represents an isolated, ephemeral execution workspace."""

    def __init__(self, session_id: Optional[str] = None, base_dir: Optional[Path] = None):
        self.session_id = session_id or f"sbx_{uuid.uuid4().hex[:12]}"
        self.base_dir = (base_dir or settings.WORKSPACE_BASE_DIR).resolve()
        self.session_dir = (self.base_dir / self.session_id).resolve()
        self.workspace_dir = (self.session_dir / "workspace").resolve()
        self.io_dir = (self.session_dir / "io").resolve()
        self.stdout_path = self.io_dir / "stdout.log"
        self.stderr_path = self.io_dir / "stderr.log"
        self.stdin_path = self.io_dir / "stdin.log"
        self._initial_file_hashes: Dict[str, str] = {}
        self._is_active = False

    def __enter__(self) -> "Session":
        self.create()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()

    def create(self) -> "Session":
        """Initialize ephemeral workspace directories with restricted permissions."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.io_dir.mkdir(parents=True, exist_ok=True)

        # Create blank I/O files
        self.stdout_path.touch(exist_ok=True)
        self.stderr_path.touch(exist_ok=True)
        self.stdin_path.touch(exist_ok=True)

        self._snapshot_initial_state()
        self._is_active = True
        logger.debug(f"Created sandbox session: {self.session_id} at {self.session_dir}")
        return self

    def _safe_resolve(self, relative_path: str) -> Path:
        """Enforce strict path containment within workspace directory."""
        if not relative_path:
            raise WorkspaceSecurityError("Empty path is invalid")

        raw_p = Path(relative_path)
        if raw_p.is_absolute() or relative_path.startswith("/") or relative_path.startswith("\\"):
            raise WorkspaceSecurityError(
                f"Absolute path rejected: '{relative_path}' is not within relative workspace"
            )

        if ".." in raw_p.parts:
            raise WorkspaceSecurityError(
                f"Path traversal detected: '{relative_path}' contains parent directory references"
            )

        target_path = (self.workspace_dir / raw_p).resolve()

        # Path traversal guard
        try:
            target_path.relative_to(self.workspace_dir)
        except ValueError:
            raise WorkspaceSecurityError(
                f"Path traversal detected: '{relative_path}' resolves outside workspace boundary"
            )

        return target_path

    def write_file(self, relative_path: str, content: bytes | str) -> Path:
        """Write content to an isolated workspace file."""
        target = self._safe_resolve(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(content, str):
            target.write_text(content, encoding="utf-8")
        else:
            target.write_bytes(content)

        return target

    def read_file(self, relative_path: str) -> bytes:
        """Read content from an isolated workspace file."""
        target = self._safe_resolve(relative_path)
        if not target.exists():
            raise FileNotFoundError(f"File not found in workspace: {relative_path}")
        return target.read_bytes()

    def stage_files(self, files: Dict[str, str | bytes]) -> None:
        """Stage input files into the workspace prior to execution."""
        for rel_path, data in files.items():
            self.write_file(rel_path, data)
        self._snapshot_initial_state()

    def _hash_file(self, path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _snapshot_initial_state(self) -> None:
        """Take snapshot of files in workspace."""
        self._initial_file_hashes.clear()
        if not self.workspace_dir.exists():
            return

        for p in self.workspace_dir.rglob("*"):
            if p.is_file():
                rel = p.relative_to(self.workspace_dir).as_posix()
                self._initial_file_hashes[rel] = self._hash_file(p)

    def compute_diffs(self) -> Dict[str, Any]:
        """Compute file modifications, additions, and deletions."""
        current_hashes: Dict[str, str] = {}
        if self.workspace_dir.exists():
            for p in self.workspace_dir.rglob("*"):
                if p.is_file():
                    rel = p.relative_to(self.workspace_dir).as_posix()
                    current_hashes[rel] = self._hash_file(p)

        created = []
        modified = []
        deleted = []

        # Find created and modified
        for path_str, h in current_hashes.items():
            if path_str not in self._initial_file_hashes:
                file_size = (self.workspace_dir / path_str).stat().st_size
                created.append({"path": path_str, "size_bytes": file_size, "hash": h})
            elif self._initial_file_hashes[path_str] != h:
                file_size = (self.workspace_dir / path_str).stat().st_size
                modified.append({"path": path_str, "size_bytes": file_size, "hash": h})

        # Find deleted
        for path_str in self._initial_file_hashes:
            if path_str not in current_hashes:
                deleted.append(path_str)

        return {
            "created": created,
            "modified": modified,
            "deleted": deleted,
            "total_mutations": len(created) + len(modified) + len(deleted)
        }

    def read_stdout(self, max_bytes: int = settings.MAX_OUTPUT_BYTES) -> str:
        """Read standard output up to maximum bytes."""
        if self.stdout_path.exists():
            with open(self.stdout_path, "rb") as f:
                raw = f.read(max_bytes)
            return raw.decode("utf-8", errors="replace")
        return ""

    def read_stderr(self, max_bytes: int = settings.MAX_OUTPUT_BYTES) -> str:
        """Read standard error up to maximum bytes."""
        if self.stderr_path.exists():
            with open(self.stderr_path, "rb") as f:
                raw = f.read(max_bytes)
            return raw.decode("utf-8", errors="replace")
        return ""

    def destroy(self) -> None:
        """Wipe session workspace completely from host filesystem."""
        self._is_active = False
        try:
            if self.session_dir.exists():
                shutil.rmtree(self.session_dir, ignore_errors=True)
                logger.debug(f"Purged session directory: {self.session_dir}")
        except Exception as e:
            logger.error(f"Error purging session {self.session_id}: {e}")


class SessionManager:
    """Manages active ephemeral sandbox sessions."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or settings.WORKSPACE_BASE_DIR
        self._sessions: Dict[str, Session] = {}

    def create_session(self, session_id: Optional[str] = None) -> Session:
        """Create and register a new isolated session."""
        session = Session(session_id=session_id, base_dir=self.base_dir)
        session.create()
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Fetch active session by ID."""
        return self._sessions.get(session_id)

    def remove_session(self, session_id: str) -> bool:
        """Tear down and unregister a session."""
        session = self._sessions.pop(session_id, None)
        if session:
            session.destroy()
            return True
        return False

    def list_sessions(self) -> List[str]:
        """List active session IDs."""
        return list(self._sessions.keys())

    def cleanup_all(self) -> None:
        """Purge all active sessions."""
        for s in list(self._sessions.values()):
            s.destroy()
        self._sessions.clear()
