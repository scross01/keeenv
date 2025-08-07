# keeenv - Populate environment variables from KeePass

`keeenv` is a command line tool similar in principle to dotenv to populate environment variables from a local configuration file, but works with an encrypted Keepass database to dynamically fetch sensitive data rather than manually placing passwords and api keys in plain text on the local file system.

## Installation

Dynamically fetch and run with `uvx`

```shell
uvx https://github.com/scross01/keeenv.git
```

Install locally with `uv`

```shell
uv tool install https://github.com/scross01/keeenv.git
keeenv
```

For development, clone the repository:

```shell
git clone https://github.com/scross01/keeenv.git
cd keeenv
uv sync
source .venv/bin/activate
keeenv
```

## Usage

Create a `.keeenv` file in your project directory:

```ini
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

`--version`: Show program version and exit.

`--quiet`: Reduce logging output (only errors).

`--verbose`: Increase logging verbosity (debug details).

`--config PATH`: Path to configuration file. Defaults to `.keeenv` in the current directory.

`--strict`: Fail if any placeholder cannot be resolved.

#### Subcommands

`init`: Initialize a new `.keeenv` configuration file with a `[keepass]` section.

- `keeenv init [--config PATH] [--kdbx PATH] [--keyfile PATH] [--force]`
  - `--config PATH`: Target `.keeenv` file location (defaults to `./.keeenv`).
  - `--kdbx PATH`: Path to an existing KeePass `.kdbx` file. If omitted, you will be prompted.
  - `--keyfile PATH`: Optional key file path. If omitted, you will be prompted and may leave blank.
  - `--force`: Overwrite an existing config without prompting.

Behavior:

- If no `--kdbx` is provided, you will be prompted to enter a path. If the path does not exist, you will be asked whether to create a new database at that path.
- If a config already exists at the target path, you will be offered to Update (merge/change only the `[keepass]` fields), Overwrite (replace file), or Abort (default).
- Paths are validated and expanded. If provided paths exist, they must be readable files.

`add`: Add a new credential to KeePass and map it in `.keeenv`.

- `keeenv add ENV_VAR [SECRET] [-t TITLE] [-u USERNAME] [--url URL] [--notes NOTES] [-a ATTRIBUTE] [--force] [--config PATH]`
  - `ENV_VAR`: Environment variable name to set. The exact case is preserved in `.keeenv`.
  - `SECRET`: Optional secret value. If omitted, you will be prompted securely.
  - `-t, --title TITLE`: KeePass entry Title. Defaults to `ENV_VAR`.
  - `-u, --user USERNAME`: Optional Username for the entry.
  - `--url URL`: Optional URL to set on the KeePass entry.
  - `--notes NOTES`: Optional notes to set on the KeePass entry.
  - `-a, --attribute ATTRIBUTE`: Attribute in which to store the secret. Defaults to `Password`. Standard attributes: `Username`, `Password`, `URL`, `Notes`. Custom attributes are supported; quotes are not required here and will be handled appropriately in the mapping.
  - `--force`: Overwrite existing KeePass entry and/or existing `.keeenv` mapping without prompting.
  - `--config PATH`: Path to the `.keeenv` configuration (defaults to `./.keeenv`).

Behavior:

- Opens the KeePass database configured under `[keepass]`.
- Creates the entry if it does not exist. If the entry already exists, you will be prompted to confirm overwrite unless `--force` is specified.
- Stores the provided secret into the specified attribute (default `Password`), and sets `Username` if provided via `-u/--user`.
- Updates `[env]` in `.keeenv` to map `ENV_VAR` to the entry using placeholder syntax `${"Title".Attribute}`. Attribute names that require quoting are quoted automatically. Environment variable case is preserved. If the mapping for `ENV_VAR` already exists, you will be prompted to confirm overwrite unless `--force` is specified.

Examples:

```shell
# Inline secret, default title = ENV var, default attribute = Password
keeenv add "GEMINI_API_KEY" "xxxx1234567890"

# Pipe secret from stdin (e.g., to pipe from clipboard)
pbpaste | keeenv add "GEMINI_API_KEY"

# Prompt for the secret interactively (no stdin and no inline value)
keeenv add "GEMINI_API_KEY"

# Custom title and username, store in custom attribute "API Key"
keeenv add -t "Gemini API Key" -u "me@example.com" --url "https://console.cloud.google.com/" --notes "Scopes: genai" -a "API Key" "GEMINI_API_KEY" "xxxx1234567890"

# Overwrite existing entry and mapping without interactive prompts
keeenv add --force "GEMINI_API_KEY" "new-secret-value"
```

### Grouped entries

keeenv supports entries stored inside KeePass groups by embedding the group path directly in the quoted title. Use forward slashes to delimit nested groups, followed by the entry title:

- `${"Parent/Child/Entry Title".Password}`
- `${"Infra/Databases/Production DB"."Connection String"}`

Notes:

- Group and entry names are matched exactly as they appear in KeePass.
- For custom attributes that contain spaces or special characters, keep the attribute quoted as usual: `${"Group/Sub/Entry"."API Key"}`.
- When using keeenv add with a title that includes slashes (e.g., `-t "Services/Github/Token"`), keeenv will traverse or create the groups as needed and place the entry there.

### Configuration Options

The `[keepass]` section configures the Keepass database to use:

- `database` - (required) full or relative path to the Keepass database file

- `keyfile` - (optional) full or relative path to the Keepass database key file

The `[env]` section sets the environment variables using `${}` to enclose substitutions from Keepass in the format of `"Entry Title".Attribute`, e.g. `"My Account".Password`.

Standard attributes include:

- `Username`
- `Password`
- `URL`
- `Notes`

Custom attributes are also supported. Use quotes around the attribute name if it contains spaces or special characters. Attribute names must start with a letter or underscore. Only alphanumeric characters, spaces, and underscores are allowed. For example:

```ini
CUSTOM_KEY = ${"My Secret"."API Key"}
DATABASE_URL = ${"Production Database"."Connection String"}
```

### Behavior and logging

The tool prints shell-safe `export` commands to stdout to be consumed by your shell (e.g., using `eval "$(keeenv)"`).

Logging goes to stderr and can be controlled by `--quiet`/`--verbose`.

### Examples

Initialize configuration interactively (in current directory):

```shell
keeenv init
```

Initialize configuration with explicit paths:

```shell
keeenv init --kdbx ./secrets.kdbx --keyfile ./mykey.key
```

Initialize at a custom location, overwrite if exists:

```shell
keeenv init --config ./config/.keeenv --kdbx ./secrets.kdbx --force
```

Export variables using the generated config:

```shell
eval "$(keeenv)"
```

Custom config path:

```shell
eval "$(keeenv --config ./config/.keeenv)"
```

Combine options:

```shell
eval "$(keeenv --config ./secrets/.keeenv --strict --verbose)"
```

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

**File Permissions**: Ensure your KeePass database and keyfiles have restrictive permissions:

  ```shell
  chmod 600 secrets.kdbx
  chmod 600 mykey.key
  ```

**Entry Names**: Use descriptive, unique entry names to avoid confusion.

**Attribute Names**: Use consistent naming for custom attributes. Attribute names must start with a letter or underscore and only alphanumeric characters, spaces, and underscores are allowed.

**Environment Variables**: Use uppercase names for environment variables by convention.

**Configuration Location**: Keep your `.keeenv` file in your project root.
