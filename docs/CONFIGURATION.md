# Configuration

Hermes resolves the manifest's `config_schema` under:

```text
plugins.entries.privacy-gateway.settings
```

## Example

```yaml
plugins:
  enabled:
    - privacy-gateway

  entries:
    privacy-gateway:
      settings:
        language: en
        score_threshold: 0.55
        enable_langextract: false
        langextract_config_path: ""
        block_non_text_content: true
        rehydrate_tool_allowlist: []
```

## Settings

### `languages`

List of languages analyzed, default `[en, pt]`. Each text is analyzed once per language and the results are merged. `pt` adds NIF (checksum-validated), Portuguese phone numbers and postal codes. Trade-off: running the English model on Portuguese text can over-redact (e.g. the words "NIF" or "IBAN" tagged as organizations).

### `language`

Default: `en`

Passed to Presidio Analyzer. The included `nlp.yaml` only configures an English spaCy model. Adding another language requires updating both the NLP configuration and Presidio recognizer support; do not merely change this string and assume multilingual detection exists.

### `score_threshold`

Default: `0.55`

Passed to `AnalyzerEngine.analyze(..., score_threshold=...)`. Raising it usually reduces false positives and can increase false negatives. Lowering it does the reverse. Evaluate on a private corpus representative of your mail/data.

### `enable_langextract`

Default: `false`

When enabled, the plugin adds Presidio's `BasicLangExtractRecognizer` programmatically. Presidio marks this feature experimental and documents local Ollama support.

With no custom config path, the recognizer uses Presidio's default LangExtract configuration. Current Presidio docs say that default uses a local Ollama model and that the model must be pulled/running first.

### `langextract_config_path`

Default: empty string.

If set, the path is passed directly to:

```python
BasicLangExtractRecognizer(config_path=...)
```

Presidio's official LangExtract documentation lists configuration fields including:

- `model_id`
- provider name
- provider kwargs such as Ollama model URL / OpenAI-compatible base URL
- extraction parameters
- model parameters
- supported entities
- entity mappings
- minimum score

This repo intentionally does not invent a model/endpoint-specific config. Create it from the Presidio documentation for the Ollama model you actually run.

### `block_non_text_content`

Default: `true`.

The plugin pseudonymizes **text**. It detects common model-request shapes for images, audio, and files. When one is found, it replaces the main content root with a block marker instead of sending the non-text payload onward.

If you set this to `false`, image/audio/file content can bypass text redaction. Only do so when a separate trusted local privacy pipeline handles that modality.

### `rehydrate_tool_allowlist`

Default: `[]`.

This is deliberately deny-by-default. When the cloud model emits:

```text
[EMAIL_ADDRESS_ABC...]
```

the plugin does **not** automatically turn it back into a real address for every tool. Otherwise a web-search, browser, webhook, or unrelated external tool could receive the plaintext.

Add only exact trusted Hermes tool names that genuinely need real values. Example shape:

```yaml
rehydrate_tool_allowlist:
  - exact_tool_name_here
  - another_exact_tool_name_here
```

Do not copy those placeholders literally. Discover the exact tool identifiers in your Hermes installation/Gmail integration and review what each tool sends off-host before allowlisting it.

## Organization detection

The included `nlp.yaml` maps `ORG`/`ORGANIZATION` to Presidio's `ORGANIZATION` entity and does not put organizations in `labels_to_ignore`.

That is an intentional privacy-biased deviation from Presidio's conservative default behavior, because company/customer/vendor names in mail can be sensitive. Expect more false positives and tune against your data.

## Auxiliary Hermes models

The plugin's `llm_request` middleware protects the main provider request. Hermes documents auxiliary calls (for example session titling, context compression, MoA tasks, vision, approval, memory and other side jobs) as running outside the main tool-calling loop.

For a privacy-sensitive profile, route every auxiliary task that may see sensitive context to a local endpoint. Hermes documents the common pattern as:

```yaml
auxiliary:
  compression:
    model: your-local-model
    base_url: http://127.0.0.1:11434/v1
    api_key: local-key
```

That is an example for the documented `compression` slot, not an exhaustive list of every enabled auxiliary task in your Hermes build. Review your current Hermes model configuration and route all applicable auxiliary slots locally.
