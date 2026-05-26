"""
Read-only virtual Linux filesystem backed by a JSON tree.

The whole filesystem is loaded into memory once at startup from
`config/fake_fs.json`. Every command (ls, cat, cd, ...) goes through this
class so the attacker sees a coherent, deterministic environment with
believable files like `/etc/passwd`, `/var/log/auth.log`, etc.

The JSON layout is a flat map of absolute path → node:

    {
        "/etc/passwd": {"type": "file", "content": "...", "permissions": "-rw-r--r--", ...},
        "/etc":        {"type": "dir",  "children": ["passwd", "shadow", ...]},
        ...
    }

Flat-map is intentionally simpler than a real tree: most lookups are O(1)
and the code stays trivially auditable.
"""
from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Any

from app.core.exceptions import VirtualFSError


class VirtualFilesystem:
    def __init__(self, fs_path: Path) -> None:
        with open(fs_path, encoding="utf-8") as f:
            self._tree: dict[str, Any] = json.load(f)

    # ── Path helpers ──────────────────────────────────────────────────────────

    def resolve(self, cwd: str, path: str) -> str:
        """Resolve `path` (possibly relative) against `cwd` into an absolute path."""
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        return posixpath.normpath(path)

    # ── Existence / type checks ───────────────────────────────────────────────

    def exists(self, path: str) -> bool:
        return path in self._tree

    def is_dir(self, path: str) -> bool:
        node = self._tree.get(path)
        return node is not None and node.get("type") == "dir"

    def is_file(self, path: str) -> bool:
        node = self._tree.get(path)
        return node is not None and node.get("type") == "file"

    # ── Reading ───────────────────────────────────────────────────────────────

    def stat(self, path: str) -> dict[str, Any] | None:
        """Return a dict describing the node, or None if it doesn't exist."""
        node = self._tree.get(path)
        if node is None:
            return None
        return {
            "type": node.get("type"),
            "permissions": node.get("permissions", "-rw-r--r--"),
            "owner": node.get("owner", "root"),
            "group": node.get("group", "root"),
            "size": node.get("size", 0),
        }

    def read(self, path: str) -> str | None:
        """Return file contents, or None if the path isn't a file."""
        node = self._tree.get(path)
        if node is None or node.get("type") != "file":
            return None
        return node.get("content", "")

    def listdir(self, path: str) -> list[str]:
        node = self._tree.get(path)
        if node is None:
            raise VirtualFSError(f"No such file or directory: {path}")
        if node.get("type") != "dir":
            raise VirtualFSError(f"Not a directory: {path}")
        return node.get("children", [])

    # ── Formatting ────────────────────────────────────────────────────────────

    def format_ls_entry(self, path: str, name: str) -> str:
        """Return a single `ls -la` line for a child entry."""
        child_path = posixpath.join(path, name) if path != "/" else f"/{name}"
        node = self._tree.get(child_path, {})
        perms = node.get("permissions", "-rw-r--r--")
        owner = node.get("owner", "root")
        group = node.get("group", "root")
        size = node.get("size", 4096 if node.get("type") == "dir" else 0)
        # Static mtime keeps the output stable across runs (otherwise an attacker
        # could fingerprint our uptime by watching timestamps drift).
        mtime = "May 20 04:02"
        return f"{perms} 1 {owner:8} {group:8} {size:8} {mtime} {name}"
