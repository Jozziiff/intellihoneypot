"""
FakeShell — the interactive bash impersonation delivered over SSH.

This is the most user-visible component: every keystroke an attacker types
ends up here. Lifecycle of one shell session:

    1. `run()` sends the Ubuntu MOTD + first prompt.
    2. It loops over keystrokes, building a line and echoing each char back.
    3. On Enter, `_handle_line()` runs.
    4. `_dispatch()` either:
         (a) handles the command locally if it's in `_STATIC_COMMANDS`
             (whoami, ls, cd, ...), or
         (b) asks the LLM for an answer.
    5. ThreatClassifier escalates the session phase on suspicious commands.
"""
from __future__ import annotations

import asyncio
import posixpath
from datetime import datetime, timezone
from typing import Callable

import paramiko

from app.core.logging import get_logger
from app.llm.orchestrator import LLMOrchestrator
from app.session.manager import SessionManager
from app.session.models import AttackPhase, Session, SessionEvent
from app.session.virtual_fs import VirtualFilesystem
from app.telemetry.classifier import ThreatClassifier

logger = get_logger(__name__)

_NEWLINE = b"\r\n"

# Stateless — one shared instance is fine across all sessions.
_CLASSIFIER = ThreatClassifier()


class FakeShell:
    """Interactive fake bash shell delivered over an SSH channel."""

    def __init__(
        self,
        channel: paramiko.Channel,
        session: Session,
        session_mgr: SessionManager,
        fs: VirtualFilesystem,
        llm: LLMOrchestrator,
    ) -> None:
        self._ch = channel
        self._session = session
        self._session_mgr = session_mgr
        self._fs = fs
        self._llm = llm

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self) -> None:
        """Main loop — read keystrokes, build lines, dispatch commands."""
        await self._send_motd()
        await self._send_prompt()

        buf = ""
        try:
            while not self._ch.closed:
                # Paramiko's recv() is blocking; bounce it to a thread so we
                # don't freeze the asyncio loop.
                data = await asyncio.get_event_loop().run_in_executor(
                    None, self._ch.recv, 1024
                )
                if not data:
                    break

                for byte in data:
                    char = chr(byte)

                    if char == "\x03":           # Ctrl+C
                        self._ch.sendall(b"^C" + _NEWLINE)
                        buf = ""
                        await self._send_prompt()

                    elif char == "\x04":         # Ctrl+D — logout
                        self._ch.sendall(b"logout" + _NEWLINE)
                        return

                    elif char in ("\r", "\n"):   # Enter — submit line
                        self._ch.sendall(_NEWLINE)
                        line = buf.strip()
                        buf = ""
                        if line:
                            await self._handle_line(line)
                        await self._send_prompt()

                    elif char == "\x7f":         # Backspace / DEL
                        if buf:
                            buf = buf[:-1]
                            # Standard "erase last char" terminal sequence.
                            self._ch.sendall(b"\x08 \x08")

                    elif char.isprintable():
                        buf += char
                        self._ch.sendall(char.encode())

        except (OSError, EOFError):
            pass  # client disconnected — nothing more to do
        finally:
            # We do NOT delete the session here — the 24h Redis TTL handles
            # cleanup, and forensics may need to inspect the session later.
            logger.info("session_ended", session_id=self._session.session_id)

    # ── Command dispatch ──────────────────────────────────────────────────────

    async def _handle_line(self, line: str) -> None:
        """Classify + persist the command, then send its output to the channel."""

        # IMPORTANT: mutate the in-memory Session first, then persist ONCE.
        # If we used `append_event()` here instead, it would re-read from
        # Redis and clobber any in-memory changes — that's how we had a
        # race condition where command_count was always 0.
        self._session.command_history.append(line)
        new_phase = _CLASSIFIER.classify(line, self._session.phase)
        self._session.phase = new_phase
        self._session.events.append(
            SessionEvent(event_type="command", payload=line, phase=new_phase)
        )
        await self._session_mgr.update(self._session)

        output = await self._dispatch(line)

        if output:
            # SSH terminals expect CRLF line endings, not the LF the LLM gives us.
            normalized = output.replace("\r\n", "\n").replace("\n", "\r\n")
            try:
                self._ch.sendall(normalized.encode("utf-8", errors="replace"))
            except OSError:
                return
            self._ch.sendall(_NEWLINE)

    async def _dispatch(self, line: str) -> str:
        """Route to a built-in handler or fall back to the LLM."""
        parts = line.split()
        cmd = parts[0] if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        handler: Callable[..., str] | None = self._STATIC_COMMANDS.get(cmd)
        if handler is not None:
            try:
                return handler(self, args)
            except Exception:
                # If a static handler crashes for any reason, fall through to
                # the LLM rather than leaking a stack trace to the attacker.
                pass

        # Unknown command → ask the LLM.
        response, was_injected = await self._llm.generate(line, self._session)
        if was_injected:
            # The guardrail caught an injection attempt — bump the session
            # to EXPLOITATION so it stands out in the dashboard.
            self._session.phase = self._session.phase.escalate(
                AttackPhase.EXPLOITATION
            )
            await self._session_mgr.update(self._session)
        return response

    # ── Static command handlers ───────────────────────────────────────────────
    # Trivial / hot commands handled locally. Three reasons:
    #   1. Speed — no network round-trip to the LLM.
    #   2. Determinism — same answer every time, no model hallucination.
    #   3. Cost — keeps LLM API usage down.

    def _cmd_whoami(self, args: list[str]) -> str:
        return self._session.username

    def _cmd_pwd(self, args: list[str]) -> str:
        return self._session.current_dir

    def _cmd_id(self, args: list[str]) -> str:
        u = self._session.username
        if u == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({u}) gid=1000({u}) groups=1000({u}),27(sudo),4(adm)"

    def _cmd_hostname(self, args: list[str]) -> str:
        return "ubuntu-server"

    def _cmd_uname(self, args: list[str]) -> str:
        flag = args[0] if args else ""
        if flag == "-a":
            return (
                "Linux ubuntu-server 5.4.0-182-generic "
                "#202-Ubuntu SMP Fri Apr 26 12:29:36 UTC 2024 "
                "x86_64 x86_64 x86_64 GNU/Linux"
            )
        if flag == "-r":
            return "5.4.0-182-generic"
        if flag == "-s":
            return "Linux"
        if flag == "-n":
            return "ubuntu-server"
        if flag == "-m":
            return "x86_64"
        return "Linux"

    def _cmd_echo(self, args: list[str]) -> str:
        return " ".join(args)

    def _cmd_cd(self, args: list[str]) -> str:
        target = args[0] if args else "/home/admin"
        if target in ("~", ""):
            target = "/home/admin"
        resolved = self._fs.resolve(self._session.current_dir, target)
        if self._fs.is_dir(resolved):
            self._session.current_dir = resolved
            return ""
        if self._fs.is_file(resolved):
            return f"bash: cd: {target}: Not a directory"
        return f"bash: cd: {target}: No such file or directory"

    def _cmd_ls(self, args: list[str]) -> str:
        show_hidden = any(a in ("-a", "-la", "-al") for a in args)
        long_format = any(a in ("-l", "-la", "-al") for a in args)

        # First positional arg (anything not starting with -) is the target path.
        path_arg = next((a for a in args if not a.startswith("-")), None)
        target = self._fs.resolve(
            self._session.current_dir,
            path_arg if path_arg else self._session.current_dir,
        )

        if not self._fs.exists(target):
            return f"ls: cannot access '{path_arg}': No such file or directory"

        if self._fs.is_file(target):
            if long_format:
                name = posixpath.basename(target)
                return self._fs.format_ls_entry(posixpath.dirname(target), name)
            return posixpath.basename(target)

        children = self._fs.listdir(target)
        if not show_hidden:
            children = [c for c in children if not c.startswith(".")]

        if long_format:
            lines = ["total 48"]
            if show_hidden:
                lines.append("drwxr-xr-x 2 root root 4096 May 20 04:02 .")
                lines.append("drwxr-xr-x 3 root root 4096 May 20 04:02 ..")
            for child in sorted(children):
                lines.append(self._fs.format_ls_entry(target, child))
            return "\r\n".join(lines)

        return "  ".join(sorted(children))

    def _cmd_cat(self, args: list[str]) -> str:
        if not args:
            return ""
        path = self._fs.resolve(self._session.current_dir, args[0])
        content = self._fs.read(path)
        if content is None:
            if self._fs.is_dir(path):
                return f"cat: {args[0]}: Is a directory"
            return f"cat: {args[0]}: No such file or directory"
        return content.rstrip("\n")

    def _cmd_env(self, args: list[str]) -> str:
        u = self._session.username
        return (
            f"SHELL=/bin/bash\nTERM=xterm-256color\nUSER={u}\n"
            f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"PWD={self._session.current_dir}\nHOME=/home/admin\nLOGNAME={u}"
        )

    def _cmd_history(self, args: list[str]) -> str:
        lines = []
        for i, cmd in enumerate(self._session.command_history[-20:], start=1):
            lines.append(f"  {i:3}  {cmd}")
        return "\r\n".join(lines)

    def _cmd_exit(self, args: list[str]) -> str:
        self._ch.sendall(b"logout" + _NEWLINE)
        self._ch.close()
        return ""

    def _cmd_clear(self, args: list[str]) -> str:
        # ANSI escape: clear screen + move cursor home.
        self._ch.sendall(b"\x1b[2J\x1b[H")
        return ""

    # Dispatch table — `cmd name → handler function`. Both `exit` and `logout`
    # point at the same handler; `env` and `printenv` likewise.
    _STATIC_COMMANDS: dict[str, Callable] = {
        "whoami": _cmd_whoami,
        "pwd": _cmd_pwd,
        "id": _cmd_id,
        "hostname": _cmd_hostname,
        "uname": _cmd_uname,
        "echo": _cmd_echo,
        "cd": _cmd_cd,
        "ls": _cmd_ls,
        "cat": _cmd_cat,
        "env": _cmd_env,
        "printenv": _cmd_env,
        "history": _cmd_history,
        "exit": _cmd_exit,
        "logout": _cmd_exit,
        "clear": _cmd_clear,
    }

    # ── Prompt / MOTD helpers ─────────────────────────────────────────────────

    async def _send_motd(self) -> None:
        """Initial banner — looks like a freshly logged-in Ubuntu server."""
        now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        motd = (
            f"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-182-generic x86_64)\r\n"
            f"\r\n"
            f"  System load: 0.12    Users logged in: 0\r\n"
            f"  Memory usage: 38%    IPv4: 10.0.1.10\r\n"
            f"\r\nLast login: {now}\r\n\r\n"
        )
        self._ch.sendall(motd.encode())

    async def _send_prompt(self) -> None:
        """`user@host:cwd$ ` prompt. `cwd` collapses to `~` when in $HOME."""
        u = self._session.username
        cwd = self._session.current_dir
        if cwd == f"/home/{u}":
            cwd = "~"
        prompt = f"{u}@ubuntu-server:{cwd}$ "
        self._ch.sendall(prompt.encode())
