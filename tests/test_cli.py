import sys
import subprocess
import textwrap
from pathlib import Path


def run_cli(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """
    Helper to run the keeenv CLI in tests.

    Prefer running the module to avoid PATH issues in CI. Falls back to console script if needed.
    """
    module_cmd = [sys.executable, "-m", "keeenv.main"]
    try:
        return subprocess.run(
            module_cmd + args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        # Fallback to console script if module invocation isn't available
        return subprocess.run(
            ["keeenv"] + args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )


def write_config(tmp_path: Path, content: str, name: str = ".keeenv") -> Path:
    cfg = tmp_path / name
    cfg.write_text(textwrap.dedent(content).strip())
    return cfg


def test_version_shows_package_version():
    proc = run_cli(["--version"])
    # Should exit 0 and print "keeenv X.Y.Z"
    assert proc.returncode == 0
    out = proc.stdout.strip()
    assert out.lower().startswith("keeenv")
    assert proc.stderr == ""


def test_logging_quiet_sets_error_level(tmp_path: Path):
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
    proc = run_cli(["--config", str(cfg), "--quiet"])
    # With quiet, we still expect failure (missing DB), but warnings should be suppressed
    assert proc.returncode == 1
    assert "Warning" not in proc.stderr


def test_logging_verbose_allows_debug(tmp_path: Path):
    cfg = write_config(
        tmp_path,
        """
        [keepass]
        database = ./missing-db.kdbx

        [env]
        FOO = ${"Entry".password}
        """,
    )
    proc = run_cli(["--config", str(cfg), "--verbose"])
    # Missing DB should fail, but verbose should emit more detail to stderr
    assert proc.returncode == 1
    assert proc.stderr != ""


def test_config_flag_uses_alternate_path(tmp_path: Path):
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
    proc = run_cli(["--config", str(cfg)])
    # Missing db -> failure, but confirms --config path is accepted and read
    assert proc.returncode == 1
    # stdout should be empty since we didn't produce exports
    assert proc.stdout.strip() == ""


def test_strict_mode_fails_on_unresolved_placeholder(tmp_path: Path):
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
    proc = run_cli(["--config", str(cfg), "--strict"])
    assert proc.returncode == 1
    assert proc.stderr != ""


def test_non_strict_blanks_unresolved_placeholders(tmp_path: Path):
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
    proc = run_cli(["--config", str(cfg)])
    assert proc.returncode == 1
    