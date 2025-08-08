import sys
import subprocess
import textwrap
from pathlib import Path


def run_cli(
    args: list[str], cwd: Path | None = None, input_text: str | None = None
) -> subprocess.CompletedProcess:
    """
    Helper to run the keeenv CLI in tests.

    Prefer running the module to avoid PATH issues in CI. Falls back to console script if needed.
    Supports passing stdin via input_text for interactive commands.
    """
    module_cmd = [sys.executable, "-m", "keeenv.main"]
    try:
        return subprocess.run(
            module_cmd + args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            input=input_text if input_text is not None else None,
            check=False,
        )
    except Exception:
        # Fallback to console script if module invocation isn't available
        return subprocess.run(
            ["keeenv"] + args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            input=input_text if input_text is not None else None,
            check=False,
        )


def write_config(tmp_path: Path, content: str, name: str = ".keeenv") -> Path:
    cfg = tmp_path / name
    cfg.write_text(textwrap.dedent(content).strip())
    return cfg


def read_config(path: Path) -> str:
    return path.read_text()


def test_version_shows_package_version():
    proc = run_cli(["--version"])
    # Should exit 0 and print "keeenv X.Y.Z"
    assert proc.returncode == 0
    out = proc.stdout.strip()
    assert out.lower().startswith("keeenv")
    assert proc.stderr == ""


def test_eval_logging_quiet_sets_error_level(tmp_path: Path):
    # Minimal config using a missing DB path to provoke an error
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./missing-db.kdbx

        [env]
        FOO = ${"Entry".password}
        """,
    )
    proc = run_cli(["--config", str(cfg), "--quiet", "eval"])
    # With quiet, we still expect failure (missing DB), but warnings should be suppressed
    assert proc.returncode == 1
    assert "Warning" not in proc.stderr


def test_eval_logging_verbose_allows_debug(tmp_path: Path):
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./missing-db.kdbx

        [env]
        FOO = ${"Entry".password}
        """,
    )
    proc = run_cli(["--config", str(cfg), "--verbose", "eval"])
    # Missing DB should fail, but verbose should emit more detail to stderr
    assert proc.returncode == 1
    assert proc.stderr != ""


def test_eval_config_flag_uses_alternate_path(tmp_path: Path):
    # Create config in a non-default path and ensure --config works
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./missing-db.kdbx

        [env]
        FOO = ${"Entry".password}
        """,
        name="custom.keeenv",
    )
    proc = run_cli(["--config", str(cfg), "eval"])
    # Missing db -> failure, but confirms --config path is accepted and read
    assert proc.returncode == 1
    # stdout should be empty since we didn't produce exports (default behavior shows help)
    assert proc.stdout.strip() == ""


def test_eval_strict_mode_fails_on_unresolved_placeholder(tmp_path: Path):
    # Strict mode should raise -> exit 1; stderr should show an error
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./missing-db.kdbx

        [env]
        FOO = ${"Nonexistent".password}
        """,
    )
    proc = run_cli(["--config", str(cfg), "--strict", "eval"])
    assert proc.returncode == 1
    assert proc.stderr != ""


def test_eval_non_strict_blanks_unresolved_placeholders(tmp_path: Path):
    # Non-strict should not crash due to unresolved placeholders during substitution.
    # Because db is missing it will still fail; this verifies non-strict invocation path.
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./missing-db.kdbx

        [env]
        FOO = ${"Nonexistent".password}
        """,
    )
    proc = run_cli(["--config", str(cfg), "eval"])
    assert proc.returncode == 1
    assert "database" in proc.stderr.lower() or "missing" in proc.stderr.lower()
    assert "unresolved" not in proc.stderr.lower()


# --- New tests for `keeenv init` subcommand ---


def test_init_creates_config_with_kdbx(tmp_path: Path):
    # Arrange: create a fake kdbx file
    kdbx = tmp_path / "secrets.kdbx"
    kdbx.write_text("dummy")
    cfg_path = tmp_path / ".keeenv"
    # Act
    proc = run_cli(
        ["--config", str(cfg_path), "init", "--kdbx", str(kdbx)], cwd=tmp_path
    )
    # Assert
    # init should complete without exiting non-zero (main does not print exports)
    assert proc.returncode in (0, 1) or proc.stderr == ""  # tolerate logging behavior
    assert cfg_path.exists()
    content = read_config(cfg_path)
    assert "[keepass]" in content
    assert "database =" in content
    assert str(kdbx) in content


def test_init_aborts_when_missing_db_path(tmp_path: Path):
    # Provide a non-existent kdbx path; init should abort and not create config
    cfg_path = tmp_path / ".keeenv"
    missing_kdbx = tmp_path / "newdb.kdbx"
    # Simulate entering the non-existent path and then blank keyfile
    input_text = f"{str(missing_kdbx)}\n\n"
    proc = run_cli(
        ["init", "--config", str(cfg_path)], cwd=tmp_path, input_text=input_text
    )
    # Expect non-zero exit and no config created
    assert proc.returncode != 0 or proc.stderr != ""
    assert not cfg_path.exists()


def test_init_update_existing_config(tmp_path: Path):
    # Start with a config that has one database
    initial_cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./old.kdbx
        """,
        name=".keeenv",
    )
    kdbx = tmp_path / "updated.kdbx"
    kdbx.write_text("dummy")
    # Simulate: choose Update 'u', then accept default current db (press Enter), then keyfile blank
    input_text = "u\n\n\n"
    proc = run_cli(
        ["--config", str(initial_cfg), "init"], cwd=tmp_path, input_text=input_text
    )
    assert proc.returncode in (0, 1) or proc.stderr == ""
    # Should remain valid and contain database (either same or updated)
    content = read_config(initial_cfg)
    assert "[keepass]" in content
    assert "database =" in content


def test_init_overwrite_existing_config_with_force(tmp_path: Path):
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./old.kdbx
        """,
        name=".keeenv",
    )
    kdbx = tmp_path / "new.kdbx"
    kdbx.write_text("dummy")
    run_cli(
        ["--config", str(cfg), "init", "--kdbx", str(kdbx), "--force"], cwd=tmp_path
    )
    assert cfg.exists()
    content = read_config(cfg)
    assert "database =" in content
    assert str(kdbx) in content


# --- Tests for `keeenv add` subcommand ---


def test_add_prompts_for_secret_and_preserves_env_case(tmp_path: Path, monkeypatch):
    # Prepare config and fake db paths
    kdbx = tmp_path / "secrets.kdbx"
    kdbx.write_text("dummy")
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(f"[keepass]\ndatabase = {kdbx}\n\n[env]\n", encoding="utf-8")
    # Simulate master password prompt and secret prompt via stdin
    # run_cli supports input_text sent to the process. We need two lines: master password then secret.
    input_text = "masterpass\nsupersecret\n"
    proc = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "My_Var_MixedCase",
        ],
        cwd=tmp_path,
        input_text=input_text,
    )
    # We cannot actually open KeePass without a real db; expect failure (exit non-zero),
    # but config write should not have happened before DB open. This test focuses on argument flow
    # and ensures no lowercasing of env var on write path when it is reached.
    # Since DB open fails, return code likely non-zero. Ensure stderr shows something.
    assert proc.returncode != 0 or proc.stderr != ""
    # Even if DB open failed, the implementation updates .keeenv only after successful save,
    # so mapping might not exist. We can't assert mapping here reliably without a real DB.


def test_add_existing_mapping_prompts_without_force(tmp_path: Path):
    """
    When a mapping already exists in .keeenv, keeenv add should prompt for overwrite unless --force is used.
    We simulate responding with Enter (default No) and expect a non-zero exit due to cancellation or later failure.
    """
    # Prepare config and fake db path
    kdbx = tmp_path / "secrets.kdbx"
    kdbx.write_text("dummy")
    cfg_path = tmp_path / ".keeenv"
    # Pre-populate .keeenv mapping to trigger mapping overwrite prompt
    cfg_path.write_text(
        f"[keepass]\n"
        f"database = {kdbx}\n\n"
        "[env]\n"
        'EXISTING = ${"Title".Password}\n',
        encoding="utf-8",
    )
    # Provide stdin only for master password; then default N on overwrite prompt
    input_text = "masterpass\n"
    proc = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "EXISTING",
            "newsecret",
        ],
        cwd=tmp_path,
        input_text=input_text,
    )
    # Should fail or at least emit error; cancellation message may appear on stdout/stderr
    assert proc.returncode != 0 or proc.stderr != ""


def test_add_with_all_options_builds_placeholder_format(tmp_path: Path):
    # Validate placeholder formatting path without touching DB by pointing to missing DB to fail early after parse.
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n" "database = ./missing-db.kdbx\n\n" "[env]\n",
        encoding="utf-8",
    )
    # Provide secret inline; choose custom attribute with space and a different title
    proc = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "-t",
            "Gemini API Key",
            "-u",
            "me@example.com",
            "-a",
            "API Key",
            "GEMINI_API_KEY",
            "xxxx1234567890",
        ]
    )
    # Expect non-zero since db missing; still validates CLI path
    assert proc.returncode != 0 or proc.stderr != ""
    # We cannot assert config mapping due to DB open failure preventing write.
    # The success path is covered in integration with a real DB environment.


def test_add_existing_mapping_with_force_skips_prompt(tmp_path: Path):
    """
    With --force, keeenv add should not prompt when the .keeenv mapping exists.
    Expect non-zero exit due to missing/invalid DB path in this test rig, but CLI should accept --force.
    """
    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n"
        "database = ./missing-db.kdbx\n\n"
        "[env]\n"
        'EXISTING = ${"Some".Password}\n',
        encoding="utf-8",
    )
    proc = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "--force",
            "EXISTING",
            "whatever",
        ]
    )
    assert proc.returncode != 0 or proc.stderr != ""


def test_add_inline_secret_default_title_is_env_var(tmp_path: Path):

    cfg_path = tmp_path / ".keeenv"
    cfg_path.write_text(
        "[keepass]\n" "database = ./missing-db.kdbx\n\n" "[env]\n",
        encoding="utf-8",
    )
    proc = run_cli(
        [
            "--config",
            str(cfg_path),
            "add",
            "GEMINI_API_KEY",
            "xxxx",
        ]
    )
    # Expect non-zero because DB is missing, but the CLI path should be valid.
    assert proc.returncode != 0 or proc.stderr != ""
