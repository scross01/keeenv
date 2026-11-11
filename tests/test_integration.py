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


def test_eval_nonstrict_partial_export(tmp_path, kdbx_db):
    """Non-strict eval exports resolvable vars and blanks the missing one."""
    db_path, _ = kdbx_db
    cfg = tmp_path / ".keeenv"
    cfg.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'GOOD = ${"TestSecret".password}\n'
        'BAD = ${"DoesNotExist".password}\n',
        encoding="utf-8",
    )
    result = run_cli(["eval"], cwd=tmp_path, env={"KEEENV_PASSWORD": "testpass"})
    assert result.returncode == 0, result.stderr
    assert "export GOOD=pass123" in result.stdout
    # The unresolved variable is blanked, not fatal: it is still exported, empty.
    assert "export BAD=''" in result.stdout


def test_eval_strict_fails_on_missing_entry(tmp_path, kdbx_db):
    """Strict eval must fail when one placeholder cannot be resolved."""
    db_path, _ = kdbx_db
    cfg = tmp_path / ".keeenv"
    cfg.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'GOOD = ${"TestSecret".password}\n'
        'BAD = ${"DoesNotExist".password}\n',
        encoding="utf-8",
    )
    result = run_cli(
        ["--strict", "eval"], cwd=tmp_path, env={"KEEENV_PASSWORD": "testpass"}
    )
    assert result.returncode == 1
    assert result.stdout.strip() == ""


def test_run_still_fails_closed_on_missing_entry(tmp_path, kdbx_db):
    """`run` keeps strict resolution: a child must not launch with blank secrets."""
    db_path, _ = kdbx_db
    cfg = tmp_path / ".keeenv"
    cfg.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'BAD = ${"DoesNotExist".password}\n',
        encoding="utf-8",
    )
    result = run_cli(
        ["run", "echo", "should-not-run"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 1
    assert "should-not-run" not in result.stdout


def test_add_declines_mapping_overwrite_leaves_no_orphan(tmp_path):
    """Declining the mapping prompt must not leave an orphaned KeePass entry."""
    from pykeepass import PyKeePass, create_database

    db_path = tmp_path / "orphan.kdbx"
    create_database(str(db_path), password="pw")
    seed = PyKeePass(str(db_path), password="pw")
    seed.add_entry(seed.root_group, title="Existing", username="u", password="v")
    seed.save()

    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        f'[keepass]\ndatabase = {db_path}\n\n[env]\nDUP = ${{"Existing".password}}\n',
        encoding="utf-8",
    )

    result = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "DUP",
            "newvalue",
            "-t",
            "BrandNewTitle",
        ],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "pw"},
        input_text="n\n",
    )
    assert result.returncode != 0

    verify = PyKeePass(str(db_path), password="pw")
    assert verify.find_entries(title="BrandNewTitle", first=True) is None
    assert 'DUP = ${"Existing".password}' in cfg_path.read_text()


def test_add_force_writes_both_stores(tmp_path):
    """--force writes the entry to both the database and the config."""
    from pykeepass import PyKeePass, create_database

    db_path = tmp_path / "both.kdbx"
    create_database(str(db_path), password="pw")
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(f"[keepass]\ndatabase = {db_path}\n\n[env]\n", encoding="utf-8")

    result = run_cli(
        ["--config", str(cfg_path), "add", "FORCED", "val", "--force"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "pw"},
    )
    assert result.returncode == 0, result.stderr

    verify = PyKeePass(str(db_path), password="pw")
    assert verify.find_entries(title="FORCED", first=True) is not None
    assert 'FORCED = ${"FORCED".password}' in cfg_path.read_text()


def test_add_creates_env_section_when_absent(tmp_path):
    """`add` must work against a config that has no [env] section yet."""
    from pykeepass import create_database

    db_path = tmp_path / "s.kdbx"
    create_database(str(db_path), password="pw")
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(f"[keepass]\ndatabase = {db_path}\n", encoding="utf-8")

    result = run_cli(
        ["--config", str(cfg_path), "add", "NEW_VAR", "secret", "--force"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "pw"},
    )
    assert result.returncode == 0, result.stderr
    content = cfg_path.read_text()
    assert "[env]" in content
    assert '"NEW_VAR"' in content


def test_add_and_eval_entry_title_with_percent(tmp_path):
    """A '%' in an entry title must round-trip through add -> config -> eval."""
    from pykeepass import create_database

    db_path = tmp_path / "pct.kdbx"
    create_database(str(db_path), password="pw")
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(f"[keepass]\ndatabase = {db_path}\n\n[env]\n", encoding="utf-8")
    env = {"KEEENV_PASSWORD": "pw"}

    added = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "PCT_VAR",
            "pctsecret",
            "-t",
            "100% Real",
            "--force",
        ],
        cwd=tmp_path,
        env=env,
    )
    assert added.returncode == 0, added.stderr
    assert '${"100% Real".password}' in cfg_path.read_text()

    evaluated = run_cli(["--config", str(cfg_path), "eval"], cwd=tmp_path, env=env)
    assert evaluated.returncode == 0, evaluated.stderr
    assert "export PCT_VAR=pctsecret" in evaluated.stdout


def test_config_relative_database_path_resolves_from_other_cwd(tmp_path):
    """`--config sub/.keeenv` works when the database path is relative to it."""
    from pykeepass import PyKeePass, create_database

    cfg_dir = tmp_path / "cfgdir"
    cfg_dir.mkdir()
    db_path = cfg_dir / "local.kdbx"
    create_database(str(db_path), password="pw")
    kp = PyKeePass(str(db_path), password="pw")
    kp.add_entry(kp.root_group, title="Rel", username="", password="relsecret")
    kp.save()

    cfg_path = cfg_dir / ".keeenv"
    cfg_path.write_text(
        '[keepass]\ndatabase = local.kdbx\n\n[env]\nREL = ${"Rel".password}\n',
        encoding="utf-8",
    )

    # Run from the parent directory, not cfgdir.
    result = run_cli(
        ["--config", str(cfg_path), "eval"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "pw"},
    )
    assert result.returncode == 0, result.stderr
    assert "export REL=relsecret" in result.stdout


def test_list_empty_env_section_message(tmp_path, kdbx_db):
    """An empty [env] section prints a message and exits 0."""
    db_path, _ = kdbx_db
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(f"[keepass]\ndatabase = {db_path}\n\n[env]\n", encoding="utf-8")
    result = run_cli(["--config", str(cfg_path), "list"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "No environment variables found" in result.stdout


def test_init_update_merges_keepass_fields(tmp_path):
    """The init update path preserves [env] while rewriting [keepass]."""
    from pykeepass import create_database

    db_path = tmp_path / "db.kdbx"
    create_database(str(db_path), password="pw")
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        f'[keepass]\ndatabase = {db_path}\n\n[env]\nKEEP = ${{"E".password}}\n',
        encoding="utf-8",
    )

    result = run_cli(
        ["--config", str(cfg_path), "init"],
        cwd=tmp_path,
        input_text="u\n\n\n",
    )
    assert result.returncode == 0, result.stderr
    content = cfg_path.read_text()
    assert "[keepass]" in content
    assert 'KEEP = ${"E".password}' in content


def test_relative_database_path_with_parent_segment(tmp_path):
    """A `../` path in [keepass] resolves relative to the config directory."""
    from pykeepass import PyKeePass, create_database

    shared = tmp_path / "shared"
    shared.mkdir()
    db_path = shared / "s.kdbx"
    create_database(str(db_path), password="pw")
    kp = PyKeePass(str(db_path), password="pw")
    kp.add_entry(kp.root_group, title="P", username="", password="pp")
    kp.save()

    cfg_dir = tmp_path / "app"
    cfg_dir.mkdir()
    cfg_path = cfg_dir / ".keeenv"
    cfg_path.write_text(
        '[keepass]\ndatabase = ../shared/s.kdbx\n\n[env]\nP = ${"P".password}\n',
        encoding="utf-8",
    )

    result = run_cli(
        ["--config", str(cfg_path), "eval"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "pw"},
    )
    assert result.returncode == 0, result.stderr
    assert "export P=pp" in result.stdout


def test_run_does_not_forward_master_password(tmp_path, kdbx_db):
    """The auth variable must not leak into the child process environment."""
    db_path, _ = kdbx_db
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n"
        f"database = {db_path}\n\n"
        "[env]\n"
        'RUN_VAR = ${"TestSecret".password}\n',
        encoding="utf-8",
    )
    result = run_cli(
        [
            "run",
            "sh",
            "-c",
            "echo PWVAR=${KEEENV_PASSWORD:-unset}; echo SECRET=$RUN_VAR",
        ],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 0, result.stderr
    assert "PWVAR=unset" in result.stdout
    assert "PWVAR=testpass" not in result.stdout
    # sanity: the intended secret did resolve for the child
    assert "SECRET=pass123" in result.stdout


def test_run_passes_dash_prefixed_args(tmp_path, kdbx_config):
    """Child flags are passed through, not consumed by keeenv's parser."""
    result = run_cli(
        ["run", "echo", "--foo", "bar"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 0, result.stderr
    assert "--foo bar" in result.stdout


def test_run_passes_flag_colliding_with_keeenv(tmp_path, kdbx_config):
    """A child flag matching a keeenv global flag must still reach the child."""
    result = run_cli(
        ["run", "echo", "--strict"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 0, result.stderr
    assert "--strict" in result.stdout


def test_run_passes_negative_number(tmp_path, kdbx_config):
    """echo -n consumes the flag, proving it reached the child."""
    result = run_cli(
        ["run", "echo", "-n", "hi"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "hi"


def test_run_keeps_literal_double_dash(tmp_path, kdbx_config):
    """A literal -- is forwarded, not stripped."""
    result = run_cli(
        ["run", "echo", "--", "x"],
        cwd=tmp_path,
        env={"KEEENV_PASSWORD": "testpass"},
    )
    assert result.returncode == 0, result.stderr
    assert "-- x" in result.stdout


def test_run_without_command_errors(tmp_path, kdbx_config):
    result = run_cli(["run"], cwd=tmp_path, env={"KEEENV_PASSWORD": "testpass"})
    assert result.returncode != 0
    assert "No command specified" in result.stderr


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
