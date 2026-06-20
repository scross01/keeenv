import pytest

from tests.test_cli import run_cli


@pytest.fixture
def kdbx_db(tmp_path):
    """Create a temp KeePass database with test entries."""
    from pykeepass import PyKeePass, create_database

    db_path = tmp_path / "test.kdbx"
    create_database(str(db_path), password="testpass")
    kp = PyKeePass(str(db_path), password="testpass")
    root = kp.root_group
    kp.add_entry(root, title="TestSecret", username="user1", password="pass123")
    kp.add_entry(root, title="API Entry", username="", password="key-abc")
    entry = kp.find_entries(title="API Entry", first=True)
    entry.set_custom_property("API Key", "custom-value-123")
    group = kp.add_group(root, "SubGroup")
    kp.add_entry(group, title="Nested Secret", username="", password="nested-pass")
    kp.save()
    return db_path, "testpass"


@pytest.fixture
def kdbx_config(tmp_path, kdbx_db):
    """Create a .keeenv config for the test database."""
    db_path, _ = kdbx_db
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'MY_PASS = ${"TestSecret".password}\n'
        'MY_API = ${"API Entry".password}\n'
        'MY_CUSTOM = ${"API Entry"."API Key"}\n'
        'MY_NESTED = ${"SubGroup/Nested Secret".password}\n',
        encoding="utf-8",
    )
    return cfg_path


def test_eval_exports_all_variables(tmp_path, kdbx_config):
    """eval exports all configured variables with correct values."""
    result = run_cli(["eval"], cwd=tmp_path, env={"KEEENV_PASSWORD": "testpass"})
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "export MY_PASS=pass123" in result.stdout
    assert "export MY_API=key-abc" in result.stdout
    assert "export MY_CUSTOM=custom-value-123" in result.stdout
    assert "export MY_NESTED=nested-pass" in result.stdout


def test_eval_strict_mode_resolves_all(tmp_path, kdbx_config):
    """eval --strict succeeds when all placeholders resolve."""
    result = run_cli(
        ["--strict", "eval"], cwd=tmp_path, env={"KEEENV_PASSWORD": "testpass"}
    )
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "export MY_PASS=pass123" in result.stdout


def test_list_shows_all_var_names(tmp_path, kdbx_config):
    """list displays all configured environment variable names."""
    result = run_cli(["list"], cwd=tmp_path)
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    for name in ["MY_PASS", "MY_API", "MY_CUSTOM", "MY_NESTED"]:
        assert name in result.stdout


def test_run_executes_command_with_secrets(tmp_path, kdbx_db):
    """run executes a command with secrets available as env vars."""
    db_path, _ = kdbx_db
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'RUN_VAR = ${"TestSecret".password}\n',
        encoding="utf-8",
    )
    script = tmp_path / "script.sh"
    script.write_text("#!/bin/bash\necho $RUN_VAR\n", encoding="utf-8")
    script.chmod(0o755)

    result = run_cli(
        ["run", "bash", str(script)],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "pass123" in result.stdout


def test_eval_preserves_custom_attribute_case(tmp_path, kdbx_db):
    """Custom attribute names with mixed case and spaces work correctly."""
    db_path, _ = kdbx_db
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'MIXED = ${"API Entry"."API Key"}\n',
        encoding="utf-8",
    )
    result = run_cli(["eval"], cwd=tmp_path, env={"KEEENV_PASSWORD": "testpass"})
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "export MIXED=custom-value-123" in result.stdout
