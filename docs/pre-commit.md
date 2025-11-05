### Pre-commit and TruffleHog Setup Guide

This guide explains how to set up and run TruffleHog v3 with pre-commit on your local machine.

1. Installing TruffleHog locally
   \[TruffleHog]: https://github.com/trufflesecurity/trufflehog

> Note: You need to make sure you're running TruffleHog v3.
> Older versions (v2 or below) will not work with the pre-commit hook and may produce errors.

```bash
trufflehog --version
# Should show: TruffleHog 3.x.x
```

2. Install pre-commit
   Install pre-commit using your preferred method:

* Homebrew:

```bash
brew install pre-commit
```

* pip / pipx:

```bash
pip install pre-commit
```

3. Enable the Hooks
   Run this once in the repo root to activate both commit and push hooks:

```bash
pre-commit install --hook-type pre-commit --hook-type pre-push
```

4. Run the TruffleHog Check

* To scan all files

```bash
pre-commit run trufflehog --all-files
```

* To scan only staged changes

```bash
pre-commit run trufflehog
```

* To get output in json format

```bash
trufflehog filesystem . --json
```

> Note: TruffleHog scan must pass before you can commit or push your changes.
> This ensures that secrets are not accidentally added to the repository.

### What to Do if the Scan Fails

If TruffleHog detects secrets:

1. Do not commit or push the changes.

2. Review the JSON output to identify the file(s) and reason for detection.

3. Remove or redact the secrets from your code or configuration.

4. If the secret is legitimate and safe to ignore, discuss it with your team before allowing it.
   You can follow the official TruffleHog documentation for guidance on using the --allow flag to
   ignore specific files or patterns, creating custom rules to exclude certain secrets, or
   adding `# trufflehog:ignore` comments directly in code to bypass detection.

5. Re-run the scan to ensure no other secrets are detected before committing or pushing.
