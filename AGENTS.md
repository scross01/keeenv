# AGENTS.md — keeenv

## Build / Lint / Test

```bash
# Dev install (one time)
uv sync

# Lint & format
flake8 keeenv tests      # .flake8 sets max-line-length=88 (matching black)
black keeenv tests       # configured in pyproject.toml

# Test
pytest tests/                          # all tests
pytest tests/test_cli.py::test_name   # single test
pytest --cov=keeenv tests/            # with coverage
```

No CI/workflows are configured — these commands are the sole quality gate.

## Architecture

- **`main.py`** — thin CLI entrypoint. Catches known exceptions and maps them to `sys.exit(1)`. Never exits zero on error.
- **`core.py`** — all subcommand logic (`eval`, `run`, `list`, `init`, `add`). Error handler `_handle_error()` logs and **re-raises** (does not call `sys.exit`); the `main.py` wrapper handles exit codes.
- **`config.py`** — `.keeenv` file I/O. Uses a custom `ConfigParser` subclass that disables `optionxform` and sets `_dict = dict` to preserve case in ENV var names AND section names. Standard ConfigParser would lowercase everything.
- **`keepass.py`** — full KeePass database wrapper (`KeePassManager`). Handles connection, entry CRUD, placeholder substitution. Always use `connect_with_password_fallback()` for real operations (tries no-password, prompts on failure). `connect()` directly is for tests only.
- **`validation.py`** — path validation (rejects `..`), entry titles (max 255 chars, printable ASCII only), attribute names (standard or `^[a-zA-Z_][a-zA-Z0-9_ ]*$`), file permission checks.
- **`constants.py`** — shared strings, regexes (`PLACEHOLDER_REGEX`, `IDENT_RE`), and the `STANDARD_ATTRS` set (`{"password", "username", "url", "notes"}`).
- **`exceptions.py`** — hierarchy: `KeeenvError` → `ConfigError`, `KeePassError`, `ValidationError`, `SecurityError` with subclasses.

## Build system

- Backend: `hatchling`
- Version: single source of truth in `keeenv/__init__.py` (`__version__ = "0.4.0"`)
- Dependencies: `pykeepass>=4.1.1.post1` (runtime), `pytest`, `flake8`, `black` (dev)
- Entry point: `keeenv = "keeenv.main:main"` — the CLI runs from `main.py`, not `core.py`

## Logging

Default level is **`WARNING`**. `--verbose` → `DEBUG`, `--quiet` → `ERROR`. Log output goes to stderr; stdout is reserved for `export` commands or subcommand output.

## Testing

- Test DB: `tests/secrets.kdbx` is a real KeePass database used as a fixture by multiple tests.
- CLI tests use the helper `run_cli(args, cwd, input_text)` at `tests/test_cli.py:7` — prefers `python -m keeenv.main` over console script.
- Unit tests (`test_core.py`, `test_keepass_manager.py`) heavily mock `KeePassManager` and `KeeenvConfig` with `unittest.mock.patch` and `Mock(spec=...)`.
- Test discovery: standard pytest (`test_*.py` files, `Test*` classes, `test_*` functions). No conftest.py.
- No integration test suite — tests are unit tests against mocks, with a real `.kdbx` fixture for config validation.

## Patterns & conventions

- **Placeholder syntax**: `${"Title".Attribute}` — title always double-quoted, attribute quoted only if not a valid identifier (`[A-Za-z_][A-Za-z0-9_]*`).
- **Subcommands**: All are dispatched in `core.main()` via `getattr(args, 'subcommand', None)`. Each subcommand has its own `_cmd_*` function.
- **pyright ignores**: The codebase has many `# pyright: ignore` comments due to pykeepass's dynamic API. These are intentional — do not remove them.
- **Database connection lifecycle**: Always `connect_with_password_fallback()` → try/finally → `disconnect()`. Database is never left open.
- **Secret input**: Supports stdin piping (`pbpaste | keeenv add ENV_VAR`), interactive prompt (via `getpass`), or inline argument.
- **Custom attributes** (non-standard): must match `^[a-zA-Z_][a-zA-Z0-9_ ]*$`. Standard attributes (password, username, url, notes) are matched case-insensitively.
- **Exit codes**: always `sys.exit(1)` on any error (known or unexpected). Success is 0.

## Version bumping

Update `__version__` in `keeenv/__init__.py:10`. No other version strings exist.
