# keeenv - Populate environment variables from Keepass

`keeenv` is is a command line tool similar in principle to dotenv to populate environment variables from a local configuraiton file, but works with an encrypted Keepass database to dynamically fetch sensitive data rather than manually placing passwords and api keys in plain text on the local file system.

## Usage

Create a `.keeenv` file

```toml
[keepass]
database=secrets.kdbx

[env]
SECRET_USERNAME=${"My Secret".Username}
SECRET_PASSWORD=${"My Secret".Password}
SECRET_URL=${"My Secret".URL}
SECRET_API_KEY=${"My Secret"."API Key"}
```

The `[keepass]` section configures the Keepass database to use

`database` - (required) full or releative path to the Keepass database file
`keyfile` - (optional) full or releative path to the Keepass database key file

the `[env]` section sets the environment variables using ${} to enclose subtitutions from Keepass in the format of "Entry Title".Attribute, e.g. "My Account".Password

Supported attributes include:

- `Username`
- `Password`
- `URL`
- Any additional attributes. If the name contains spaces use quotes e.g. `${"My Secret"."API Key"}`

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

Note: setting attitional attributes using keepassxc-cli is not currently supported.