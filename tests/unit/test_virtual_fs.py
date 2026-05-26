"""Unit tests for VirtualFilesystem."""
import pytest
from app.core.exceptions import VirtualFSError


def test_root_exists(virtual_fs):
    assert virtual_fs.exists("/")


def test_etc_passwd_readable(virtual_fs):
    content = virtual_fs.read("/etc/passwd")
    assert content is not None
    assert "admin" in content


def test_config_php_readable(virtual_fs):
    content = virtual_fs.read("/var/www/html/config.php")
    assert content is not None
    assert "DB_PASSWORD" in content


def test_resolve_relative_path(virtual_fs):
    resolved = virtual_fs.resolve("/home/admin", ".ssh")
    assert resolved == "/home/admin/.ssh"


def test_resolve_absolute_path(virtual_fs):
    resolved = virtual_fs.resolve("/home/admin", "/etc/passwd")
    assert resolved == "/etc/passwd"


def test_is_dir(virtual_fs):
    assert virtual_fs.is_dir("/etc")
    assert not virtual_fs.is_dir("/etc/passwd")


def test_is_file(virtual_fs):
    assert virtual_fs.is_file("/etc/passwd")
    assert not virtual_fs.is_file("/etc")


def test_listdir(virtual_fs):
    children = virtual_fs.listdir("/home/admin")
    assert ".ssh" in children
    assert ".bash_history" in children


def test_listdir_on_file_raises(virtual_fs):
    with pytest.raises(VirtualFSError):
        virtual_fs.listdir("/etc/passwd")


def test_nonexistent_returns_none(virtual_fs):
    assert virtual_fs.read("/does/not/exist") is None
    assert not virtual_fs.exists("/does/not/exist")


def test_ssh_private_key_exists(virtual_fs):
    content = virtual_fs.read("/home/admin/.ssh/id_rsa")
    assert content is not None
    assert "BEGIN RSA PRIVATE KEY" in content


def test_auth_log_has_brute_force_entries(virtual_fs):
    content = virtual_fs.read("/var/log/auth.log")
    assert content is not None
    assert "Failed password" in content
