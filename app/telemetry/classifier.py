from __future__ import annotations

import re

from app.session.models import AttackPhase

# Patterns ordered from lowest to highest severity
_PHASE_PATTERNS: list[tuple[AttackPhase, list[re.Pattern[str]]]] = [
    (
        AttackPhase.RECON,
        [
            re.compile(r"\b(nmap|masscan|ping|traceroute|whois|dig|host|nslookup|arping)\b", re.I),
            re.compile(r"\b(ls|dir|pwd|whoami|id|uname|hostname|ifconfig|ip\s+addr|ip\s+a)\b", re.I),
            re.compile(r"\bcat\s+(/etc/passwd|/etc/shadow|/etc/hosts|/proc/\w+)\b", re.I),
            re.compile(r"\b(find\s+/|locate\s+|which\s+|whereis\s+)\b", re.I),
            re.compile(r"\b(ps\s+(aux|ef)|top|htop|netstat|ss\s+-|lsof)\b", re.I),
            re.compile(r"\b(env|printenv|set\b|export\b)\b", re.I),
        ],
    ),
    (
        AttackPhase.BRUTE_FORCE,
        [
            re.compile(r"\b(hydra|medusa|john|hashcat|crunch|aircrack|patator)\b", re.I),
            re.compile(r"\b(rockyou|wordlist|dictionary\s+attack|password\s+spray)\b", re.I),
        ],
    ),
    (
        AttackPhase.EXPLOITATION,
        [
            re.compile(r"\b(wget|curl)\s+http", re.I),
            re.compile(r"\bchmod\s+\+x\b", re.I),
            re.compile(r"\b(bash|sh|zsh)\s+-[ic]\b", re.I),
            re.compile(r"\b(python|python3|perl|ruby|php)\s+-[ce]\b", re.I),
            re.compile(r"\bnc\s+.*-e\b|\bncat\b|\bnetcat\b", re.I),
            re.compile(r"/dev/(tcp|udp)/", re.I),
            re.compile(r"\b(exploit|payload|shellcode|msfvenom|msfconsole|metasploit)\b", re.I),
            re.compile(r"\b(base64\s+-d|xxd\s+-r|eval\s*\()\b", re.I),
            re.compile(r"\b(pkexec|sudo\s+-l|sudo\s+su|su\s+-)\b", re.I),
            re.compile(r"\[REDACTED\]", re.I),  # Triggered by guardrail prompt injection
        ],
    ),
    (
        AttackPhase.PERSISTENCE,
        [
            re.compile(r"\b(crontab\s+-[el]|/etc/cron)\b", re.I),
            re.compile(r"\b(systemctl\s+(enable|start)|service\s+\w+\s+start)\b", re.I),
            re.compile(r"\b(adduser|useradd|usermod|groupadd|passwd\s+\w+)\b", re.I),
            re.compile(r"\b(visudo|sudoers)\b", re.I),
            re.compile(r"\b(authorized_keys|ssh-keygen|\.ssh/)\b", re.I),
            re.compile(r"\b(~?/\.(bashrc|bash_profile|profile|zshrc))\b", re.I),
            re.compile(r"\b(/etc/rc\.local|/etc/init\.d/)\b", re.I),
        ],
    ),
]


class ThreatClassifier:
    def classify(self, command: str, current_phase: AttackPhase) -> AttackPhase:
        """
        Classify the command into an attack phase.
        Phase only escalates — never downgrades.
        """
        detected = current_phase

        for phase, patterns in _PHASE_PATTERNS:
            for pattern in patterns:
                if pattern.search(command):
                    detected = detected.escalate(phase)
                    break  # One match per phase is sufficient

        return detected
