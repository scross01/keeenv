# keeenv - Populate environment variables from Keepass

`keeenv` is a command line tool similar in principle to dotenv to populate environment variables from a local configuration file, but works with an encrypted Keepass database to dynamically fetch sensitive data rather than manually placing passwords and api keys in plain text on the local file system.

## Installation

```bash
uvx https://github.com/scross01/keeenv.git
```

```shell
uv tool install https://github.com/scross01/keeenv.git
```

For development:

```bash
git clone https://github.com/scross01/keeenv.git
cd keeenv
uv sync
```

## Usage

Create a `.keeenv` file in your project directory:

```toml
[keepass]
database = secrets.kdbx
keyfile = mykey.key

[env]
SECRET_USERNAME = ${"My Secret".Username}
SECRET_PASSWORD = ${"My Secret".Password}
SECRET_URL = ${"My Secret".URL}
SECRET_API_KEY = ${"My Secret"."API Key"}
```

### Command-line options

The CLI supports the following options:

- `--version`
  Show program version and exit.

- `--quiet`
  Reduce logging output (only errors).

- `--verbose`
  Increase logging verbosity (debug details).

- `--config PATH`
  Path to configuration file. Defaults to `.keeenv` in the current directory.

- `--strict`
  Fail if any placeholder cannot be resolved.

### Configuration Options

The `[keepass]` section configures the Keepass database to use:

- `database` - (required) full or relative path to the Keepass database file
- `keyfile` - (optional) full or relative path to the Keepass database key file

The `[env]` section sets the environment variables using `${}` to enclose substitutions from Keepass in the format of `"Entry Title".Attribute`, e.g. `"My Account".Password`

### Behavior and logging

- The tool prints shell-safe `export` commands to stdout to be consumed by your shell (e.g., using `eval "$(keeenv)"`).
- Logging goes to stderr using Python’s logging module and is controlled by `--quiet`/`--verbose`. Default level is WARNING.

### Examples

Basic usage:
```bash
eval "$(keeenv)"
```

Custom config path:
```bash
eval "$(keeenv --config ./config/.keeenv)"
```

Strict mode:
```bash
eval "$(keeenv --strict)"
```

Increase verbosity:
```bash
eval "$(keeenv --verbose)"
```

Quiet mode:
```bash
eval "$(keeenv --quiet)"
```

Combine options:
```bash
eval "$(keeenv --config ./secrets/.keeenv --strict --verbose)"
```

### Validation Rules

keeenv includes comprehensive input validation to ensure security and reliability:

#### Path Validation

- Database and keyfile paths must be valid and exist
- Directory traversal attempts (`..`) are blocked
- Path expansion (`~`) is supported
- Files must have proper permissions (not world-readable)

#### Entry Title Validation

- Entry titles must be 1-255 characters long
- Only printable ASCII characters are allowed
- Leading/trailing whitespace is trimmed

#### Attribute Validation

- Standard attributes: `username`, `password`, `url`, `notes`
- Custom attributes are supported with quoted names
- Attribute names must start with a letter or underscore
- Only alphanumeric characters, spaces, and underscores are allowed

#### Security Validation

- Database files cannot be world-readable
- Keyfiles cannot be world-readable
- File permissions are checked before access

### Supported Attributes

Standard attributes include:

- `Username`
- `Password`
- `URL`
- `Notes`

Custom attributes are also supported. If the name contains spaces or special characters, use quotes:

```toml
CUSTOM_KEY = ${"My Secret"."API Key"}
DATABASE_URL = ${"Production Database".Connection String}
```

## Exit codes

- `0` on success
- `1` on any failure (configuration errors, validation errors, KeePass access issues, or unexpected exceptions)

This single nonzero exit code policy is implemented in the CLI wrapper (see [keeenv/main.py](keeenv/main.py:9-26)).

## Why keeenv? The challenges with .env files

.env files are a very convinient way to set local project variables and are often used system credientials and api keys. But storing sensitive information in open text files has some challenges and concerns:

- While .env file aim to seaparte API keys from code there is still a chance .env files can be accidentally committed to version control systems like Git. Once committed, API keys become part of the permanent history and are difficult to remove completely. Even with .gitignore, developers may forget to add it or accidentally commit it
- API keys stored in .env files are only as secure as the local machine. If you account is compromised, or accessed by unauthorized users, all API keys are exposed.
- .env files are typically stored in plain text. Even with file system encryption, the keys are decrypted when the file is read. No additional layer of protection beyond basic file permissions
- Rotating API keys requires updating .env files, potentiall across multiple projects and across multiple machines. This is a manual process prone to human error and risk of inconsistent or broken environments if some developers don't update their keys.
- Different keys may be used for different projects or for seapratation of staging, testing, and production environments, but the key themselves lack identification of therr usage type.

**keeenv** addresses many of the downsides of traditional .env files by leveraging a dedicated password manager with proper encryption and access controls.

- 🔐 Integrates with KeePass for secure password management
- ✳️ Dynamically fetches API keys rather than storing them in plain text
- 📍 Uses placeholder syntax to reference stored secrets, making is easier to validate the appropriate credentils are being used.
- 📄 Avoids storing sensitive data in local configuration files

The key principle is to never store secrets in code or configuration files - instead, fetch them securely at runtime from a trusted source.

You can use a single common Keepass file to shared secrets across projects, or create a file per project environment.

## Hints and Tips

### Adding new passwords and keys to Keepass from the command line

A convinient was to add new keys to the database is to use the [KeypassXC CLI](https://keepassxc.org/docs/KeePassXC_UserGuide#_command_line_tool)

Create a Keepass database if you don't have one already

```shell
keepassxc-cli db-create -p secrets.kdbx
```

Add a new secret to the Keepass database

```shell
$ keepassxc-cli add -u "myusername" --url "https://example.com" -p secrets.kdbx "My Secret"
Enter password to unlock secrets.kdbx: ********
Enter password for new entry: ********
Successfully added entry My Secret.
```

Note: setting additional attributes using keepassxc-cli is not currently supported.

### Security Best Practices

1. **File Permissions**: Ensure your KeePass database and keyfiles have restrictive permissions:

   ```bash
   chmod 600 secrets.kdbx
   chmod 600 mykey.key
   ```

2. **Entry Names**: Use descriptive, unique entry names to avoid confusion

3. **Attribute Names**: Use consistent naming for custom attributes

4. **Environment Variables**: Use uppercase names for environment variables by convention

5. **Configuration Location**: Keep your `.keeenv` file in your project root
