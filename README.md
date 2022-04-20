# secrets

`secrets` is a command-line tool to prevent committing secret keys into your source code. `secrets` has a few features that distinguish it from other secret scanning tools:

1. Focused on pre-commit. It's a lot cheaper to prevent secrets from getting committed in the first place than dealing with the consequences once a secret that has been committed to your repository has been detected.

2. Extremely fast. Using a secret scanner shouldn't slow down your development workflow, so `secrets` is 95 times faster or more than other tools. Learn more about how it's designed for performance [here](#performance).

3. Always local operation. Many other secret scanners try to verify that the secrets are valid, which is practice means sending strings from your source code to 3rd party services automatically. There's a security versus convienience tradeoff in that decision, but `secrets` is designed to be the best "local only" tool and will never send data off of your computer.

4. Low rate of false positives. While local-only tools are always going to have more false positives than one that verifies secrets, `secrets` uses a probability theory based approach in order to more accurately detect keys than other tools.

5. Single binary with no dependencies. Installing `secrets` is as easy as copying the binary into your `bin` directory.

## Usage

By default running `secrets` will recursively search source files in your current directory for secrets.

```
$ secrets
```

For every secret it finds it will print out the file, line number, and the secret that was found. If it finds any secrets it will exit with a non-zero status code.

You can optionally pass a list of files and directories to search as arguments.

```
$ secrets file1 file2 dir1
```

This most commonly used to search files that are about to be committed to source control for accidentically included secrets. For example, to use `secrets` as a git pre-commit hook you can add the following command to your `pre-commit` script:

```
$ secrets `git diff --cached --name-only --diff-filter=ACM`
```

This command will fail if `secrets` detects any secrets in the files modified by the commit. You can install `secrets` as a pre-commit hook automatically in your current git repository using the following command:

```
$ secrets --install-pre-commit
```

## Installation

You can download a prebuilt binary for the latest release from the [releases](https://github.com/sirwart/secrets/releases) page.

### Using pre-commit

`secrets` can work as a plugin for [pre-commit](https://pre-commit.com/) with
the following configuration.

Note that this may require having Cargo and a Rust compiler already installed.
See the [pre-commit rust plugin docs](https://pre-commit.com/#rust) for more
information.

```yaml
repos:
-   repo: https://github.com/sirwart/secrets.git
    # Set your version, be sure to use the latest and update regularly or use 'main'
    rev: v0.1.3
    hooks:
    -   id: secrets
```

## Ignoring secrets

`secrets` will respect your .gitignore files by default, but there might still be files you want to exclude from being scanned for secrets. To do that you can create a .secretsignore file, which supports similar syntax to a .gitignore file for ignoring files. In addition to excluding files, it also it also supports a `[secrets]` section that allows ignoring individual secrets.

```
test/*
dummy

[secrets]
pAznMW3DsrnVJ5TDWwBVCA
```

In addition to the .secretsignore file, `secrets` is compatible with `detect-secrets` style allowlist comments on the same line as the detected secret:

```
test_secret = "pAznMW3DsrnVJ5TDWwBVCA" # pragma: allowlist secret
```

## Performance

The slowest part of secret scanning is looking for potential secrets in a large number of files. To do this quickly `secrets` does a couple of things:

1. All the secret patterns are compiled into a single regex, so each file only needs to be processed once.

2. This regex is fed to [ripgrep](https://github.com/BurntSushi/ripgrep), which is specially optimized to running a regex against a large number of files quickly.

Additionally `secrets` is written in Rust, which means there's no interpreter startup time. To compare real world performance, here's the runtime of a few different scanning tools to search for secrets in the [Sentry repo](https://github.com/getsentry/sentry) on an M1 air laptop:

| tool           | avg. runtime | vs. baseline |
| -------------- | ------------ | ------------ |
| secrets        | 0.32s        | 1x           |
| trufflehog     | 31.2s        | 95x          |
| detect-secrets | 73.5s        | 226x         |

Most of the time your pre-commit will be running on a small number of files, so that runtime is not typical, but when working with large commits that touch a lot of files the runtime can become noticeable.

## Alternative tools

Even if `secrets` is not the right tool for you, if you're working on a service that deals with user data you should strongly consider using a secret scanner. Here are some alterative tools worth considering:

## [detect-secrets](https://github.com/Yelp/detect-secrets)

`detect-secrets` was the inspiration for `secrets`. `secrets` was originally conceived as a much faster, more focused version of `detect-secrets` with better random string detection. However, `detect-secrets` still has a lot more features that might be a better fit for your use case.

## [trufflehog](https://github.com/trufflesecurity/trufflehog)

`trufflehog` recently released a version 3, which was a complete re-write from the previous versions and promises better performance and no external dependencies. It's very focused on secret verification, which means fewer false positives but also sending secrets from your source code to external services. It also offers a range of secret scanning services whereas `secrets` is primarily focused on being a good pre-commit hook.
