# Installation

This document intentionally follows the current Hermes plugin model instead of assuming a generic Python virtualenv layout.

## 1. Prerequisites

Use a current first-party Hermes installation. Current Hermes documentation says its active runtime is Python 3.14, while Presidio Analyzer 2.2.364 declares Python `>=3.10,<3.15` and includes Python 3.14 support. The plugin's `pyproject.toml` therefore declares Python `>=3.14,<3.15`.

The plugin has these Python dependencies:

- `presidio-analyzer[langextract]>=2.2.362,<2.3`
- `cryptography>=50,<51`

Hermes's current plugin package manager reads a neighboring `pyproject.toml`, asks for dependency consent, and prepares the enabled plugin dependency union before activation.

## 2. Copy the plugin into the active Hermes profile

For a user plugin:

```bash
mkdir -p ~/.hermes/plugins/privacy-gateway
cp -R /path/to/hermes-privacy-gateway/. ~/.hermes/plugins/privacy-gateway/
```

If you use a non-default `HERMES_HOME` or a separate Hermes profile, use that profile's plugin directory instead. The alias database follows Hermes's profile-scoped plugin storage.

## 3. Generate the alias-vault key

Run:

```bash
cd ~/.hermes/plugins/privacy-gateway
python scripts/generate_key.py
```

It prints a URL-safe base64 string representing exactly 32 random bytes.

Set it as:

```text
HERMES_PRIVACY_GATEWAY_KEY=<generated value>
```

Store it through the active Hermes profile's normal secret/environment mechanism. `plugin.yaml` declares it through `requires_env` with `secret: true`, so Hermes can prompt for it during installation/enablement flows that support credential prompting.

### Back up this key separately

The encrypted alias database cannot be recovered without it. The plugin also writes a key-check marker and will refuse an existing vault when a different master key is supplied, preventing silent alias drift.

## 4. Install the configured spaCy model

`nlp.yaml` uses:

```text
en_core_web_lg
```

Presidio's official documentation states that the required spaCy/Stanza models must be downloaded before use, and its current default English NLP configuration uses `en_core_web_lg`.

Install that model **inside the Python environment that actually runs Hermes**:

```bash
python -m spacy download en_core_web_lg
```

Hermes's managed runtime does not expose a normal `pip` command. On Hermes
installations using the managed Python 3.14 environment, install the matching
spaCy model wheel with Hermes's pinned `uv`:

```bash
uv pip install --python /path/to/hermes/venv/bin/python \
  --no-deps \
  https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

The model is distributed as a GitHub release asset rather than a normal PyPI
package, so it is intentionally not listed as a `pyproject.toml` dependency.
If the model is missing, the plugin refuses to initialize its engine (model
requests are blocked) instead of letting Presidio download it at runtime.

Do not assume your system Python is the Hermes runtime. Verify the interpreter used by your Hermes installation/profile first.

Because spaCy language models are separate model packages rather than a normal dependency declared in this repo, re-check this model after a Hermes runtime/environment replacement.

## 5. Run Hermes Plugin Doctor

From the plugin directory:

```bash
hermes plugins doctor . --ci
```

Hermes documents Plugin Doctor as exercising discovery, manifest parsing, namespaced import, `register(ctx)`, hook registration, and tool registration using the same plugin paths as the runtime.

Fix all errors before enabling the plugin.

## 6. Enable the plugin

```bash
hermes plugins enable privacy-gateway
```

Confirm it is enabled:

```text
/plugins
```

or use the relevant Hermes plugin-list/status command for your surface.

## 7. Configure settings

See [CONFIGURATION.md](CONFIGURATION.md). A conservative starting configuration is available in:

```text
examples/hermes-config.yaml
```

The most important secure defaults are already in `plugin.yaml`:

- `block_non_text_content: true`
- `rehydrate_tool_allowlist: []`
- `enable_langextract: false`

## 8. Run the local smoke test

Once Presidio and `en_core_web_lg` are available:

```bash
export HERMES_PRIVACY_GATEWAY_KEY='...'
python scripts/smoke_test.py
```

Expected properties, not exact aliases:

1. The sanitized output should not contain the detected raw person's name/email.
2. It should contain stable typed aliases.
3. The restored output should return the original values.

## 9. Configure a hard egress boundary

Do not stop at the plugin if your requirement is "raw Gmail text must not reach a cloud LLM."

Hermes documents middleware failures as fail-open. The recommended deployment is:

```text
Hermes -> local fail-closed proxy -> cloud provider
```

and a network policy that prevents Hermes from contacting the cloud provider directly. See [SECURITY.md](SECURITY.md).
