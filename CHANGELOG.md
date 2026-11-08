# Changelog

## Unreleased

- Serialize alias vault access with a lock. Hermes shares one plugin storage
  connection across agent threads, so concurrent subagents raced on it and
  failed with `failed to persist alias` / `InterfaceError`, which blocked
  whole requests and tool results.
- Declare Hermes `>=0.20.4`, the first release providing the plugin storage API
  used by the encrypted alias vault.
- Register the middleware even when `presidio-analyzer` is not installed: a
  missing dependency now blocks model requests (and logs an error at startup)
  instead of making `register()` raise, which left no middleware installed and
  let plaintext reach the provider.
- Refuse to initialize when the configured spaCy model is not installed
  instead of letting Presidio pip-install it from GitHub at runtime.
- Declare `provides_middleware: [llm_request, tool_request]` in `plugin.yaml`.

## 0.1.1 - 2026-10-01

- Preserve provider protocol metadata such as Responses API item IDs, call IDs,
  roles, types, names, and status values while sanitizing model-visible text.
- Sanitize arbitrary strings inside tool argument/output payloads without
  mutating the surrounding provider schema.
- Block unfamiliar top-level provider request shapes instead of recursively
  rewriting every string and potentially corrupting protocol identifiers.
- Report dependency import failures directly instead of masking them as a
  missing flat `privacy` module.
- Replace the incompatible Presidio Anonymizer dependency with deterministic,
  overlap-aware local span replacement compatible with Hermes's
  `cryptography==50.0.1` runtime pin.
- Add regression coverage for structured provider requests, overlapping
  detections, existing aliases, and right-to-left offset preservation.

## 0.1.0 - 2026-09-30

- Initial reference implementation.
- Hermes `llm_request` text pseudonymization.
- Hermes `transform_tool_result` sanitization.
- Hermes `tool_request` exact-name allowlisted rehydration.
- Hermes `transform_llm_output` local final-response rehydration.
- Profile-scoped encrypted stable alias vault.
- Optional Presidio LangExtract/Ollama recognizer.
- Default non-text provider-content block.
- Installation, Gmail, architecture, testing, and security documentation.
