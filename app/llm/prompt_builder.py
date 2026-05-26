"""
PromptBuilder — turns a Session + current command into LLM-ready messages.

The persona (Ubuntu 20.04 server, hostname, etc.) lives in YAML at
`config/persona_ssh.yaml`. Keeping it out of code means we can tweak the
personality without redeploying.

The user message is just the recent shell transcript ending with the new
command, which the LLM treats as "predict the next line of bash output".
"""
from __future__ import annotations

from pathlib import Path

import yaml

from app.session.models import Session


class PromptBuilder:
    def __init__(self, persona_path: Path) -> None:
        with open(persona_path, encoding="utf-8") as f:
            self._persona: dict = yaml.safe_load(f)

    def get_system_prompt(self, session: Session) -> str:
        """Render the persona template with this session's live state."""
        template: str = self._persona.get("llm_system_prompt", "")
        # `history` placeholder gets the last 5 commands BEFORE the current one.
        prev = session.command_history[:-1] if session.command_history else []
        return template.format(
            username=session.username,
            cwd=session.current_dir,
            hostname=self._persona.get("persona", {}).get("hostname", "ubuntu-server"),
            history=", ".join(prev[-5:]),
        )

    def build_user_message(self, command: str, session: Session) -> str:
        """
        The user-turn message — recent shell transcript + current command.

        The current command is already appended to `command_history` by
        FakeShell before this method is called, so we slice it off here
        with `[:-1]` to avoid duplicating it in the user message.
        """
        prev = session.command_history[:-1] if session.command_history else []
        lines = [f"$ {cmd}" for cmd in prev[-4:]]  # last 4 commands for context
        lines.append(f"$ {command}")
        return "\n".join(lines)

    def context_string(self, session: Session) -> str:
        """
        Compact "recent context" string used to namespace the LLM cache key.

        Two identical commands get different cached answers if the recent
        history differs (e.g. `ls` after `cd /etc` vs `cd /home`).
        """
        last_3 = session.command_history[-3:] if session.command_history else []
        return " | ".join(last_3)
