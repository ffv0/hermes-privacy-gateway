"""Presidio-backed text pseudonymization and local alias rehydration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

# Presidio is imported lazily in PrivacyEngine so that importing this module
# (which plugin registration does for the constants/helpers below) never
# depends on it. If Presidio is missing, engine creation fails inside the
# middleware and requests are blocked, instead of register() raising and the
# plugin silently not registering at all.
if TYPE_CHECKING:
    from presidio_analyzer import RecognizerResult

if __package__:
    from .vault import AliasVault, alias_ranges
else:  # direct local test/import outside Hermes plugin loader
    from vault import AliasVault, alias_ranges


# Only what identifies or pays a person. URLs, dates, organizations, cities/countries and
# postal codes are left alone: agents need them (store names, links, "ship to Portugal").
DEFAULT_ENTITIES = (
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD",
    "PT_NIF", "PT_ADDRESS", "IP_ADDRESS", "US_SSN", "US_PASSPORT", "UK_NHS",
)

BLOCKED_REQUEST = "[PRIVACY_GATEWAY_BLOCKED_REQUEST]"
BLOCKED_TOOL_RESULT = "[PRIVACY_GATEWAY_BLOCKED_TOOL_RESULT]"
NON_TEXT_BLOCK = "[PRIVACY_GATEWAY_BLOCKED_NON_TEXT_CONTENT]"

# Conservative structured-secret patterns. These are deliberately narrow;
# domain-specific secrets should be added as Presidio recognizers or local rules.
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_AUTH_HEADER = re.compile(
    r"(?im)^authorization\s*:\s*(?:bearer|basic)\s+\S+\s*$"
)
# Well-known credential shapes (OpenAI/OpenRouter/Anthropic, GitHub, AWS, Slack, JWT)
# and `password=...`-style assignments. Not exhaustive; Presidio does not detect these.
_SECRET_TOKENS = re.compile(
    r"\bsk-[A-Za-z0-9_\-]{20,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{50,}"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token)(\s*[:=]\s*)[\"']?[^\s\"']{6,}"
)

_NON_TEXT_TYPES = {
    "image_url",
    "input_image",
    "image",
    "input_audio",
    "audio",
    "input_file",
    "file",
}
_NON_TEXT_KEYS = {
    "image_url",
    "file_data",
    "b64_json",
    "input_audio",
    "audio_url",
}

# Provider request objects mix model-visible text with protocol metadata. Only
# these known fields are text/payload boundaries; unknown scalar fields (IDs,
# enum values, model names, item references, etc.) must remain byte-for-byte
# unchanged or the provider may reject an otherwise valid request.
_MODEL_TEXT_KEYS = {
    "content",
    "description",
    "input_text",
    "instructions",
    "output_text",
    "prompt",
    "refusal",
    "summary",
    "text",
}
_MODEL_PAYLOAD_KEYS = {
    "args",
    "arguments",
    "input",
    "output",
}


def walk_strings(value: Any, string_fn) -> Any:
    """Recursively transform strings while preserving container structure."""
    if isinstance(value, str):
        return string_fn(value)
    if isinstance(value, list):
        return [walk_strings(item, string_fn) for item in value]
    if isinstance(value, tuple):
        return tuple(walk_strings(item, string_fn) for item in value)
    if isinstance(value, dict):
        return {key: walk_strings(item, string_fn) for key, item in value.items()}
    return value


def walk_model_text(value: Any, string_fn, *, mode: str = "content") -> Any:
    """Transform model-visible strings without rewriting protocol metadata.

    ``content`` accepts a bare string or a list of content/message items.
    ``scan`` searches nested protocol containers but preserves unknown scalar
    fields. ``payload`` sanitizes every string value inside tool arguments or
    outputs, where arbitrary user-defined object keys are expected.
    """
    if isinstance(value, str):
        return string_fn(value) if mode in {"content", "payload"} else value
    if isinstance(value, list):
        child_mode = "payload" if mode == "payload" else mode
        return [walk_model_text(item, string_fn, mode=child_mode) for item in value]
    if isinstance(value, tuple):
        child_mode = "payload" if mode == "payload" else mode
        return tuple(walk_model_text(item, string_fn, mode=child_mode) for item in value)
    if isinstance(value, dict):
        if mode == "payload":
            return {
                key: walk_model_text(item, string_fn, mode="payload")
                for key, item in value.items()
            }

        transformed = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in _MODEL_TEXT_KEYS:
                item_mode = "content"
            elif normalized_key in _MODEL_PAYLOAD_KEYS:
                item_mode = "payload"
            else:
                item_mode = "scan"
            transformed[key] = walk_model_text(item, string_fn, mode=item_mode)
        return transformed
    return value


def contains_non_text_model_content(value: Any) -> bool:
    """Detect common provider payload shapes carrying image/audio/file content."""
    if isinstance(value, list) or isinstance(value, tuple):
        return any(contains_non_text_model_content(item) for item in value)
    if isinstance(value, dict):
        item_type = str(value.get("type", "")).lower()
        if item_type in _NON_TEXT_TYPES:
            return True
        if any(key in value for key in _NON_TEXT_KEYS):
            return True
        return any(contains_non_text_model_content(item) for item in value.values())
    return False


def blocked_content_for_key(key: str) -> Any:
    """Return a conservative provider-compatible replacement for common text roots."""
    if key == "messages":
        return [{"role": "user", "content": BLOCKED_REQUEST}]
    return BLOCKED_REQUEST


def select_non_overlapping_results(
    results: Sequence[RecognizerResult],
) -> list[RecognizerResult]:
    """Choose a deterministic, highest-confidence set of entity spans.

    Presidio can return overlapping recognizer results. Prefer confidence first,
    then the longer span, then the earlier span, and return results in source
    order for callers that need stable output.
    """
    selected: list[RecognizerResult] = []
    for result in sorted(
        results,
        key=lambda item: (
            -float(getattr(item, "score", 0.0)),
            -(int(item.end) - int(item.start)),
            int(item.start),
            int(item.end),
            str(getattr(item, "entity_type", "")),
        ),
    ):
        # Presidio normally returns few spans, so this clear O(n²) check keeps
        # overlap policy explicit and is preferable to a more fragile sweep.
        if any(result.start < other.end and result.end > other.start for other in selected):
            continue
        selected.append(result)
    return sorted(selected, key=lambda item: (int(item.start), int(item.end)))


_NAME_PARTICLES = {"da", "de", "do", "das", "dos", "e", "di", "du", "del", "la", "le", "van", "von", "der", "y"}
_WORD = re.compile(r"\S+")


def trim_person_span(text: str, start: int, end: int) -> tuple[int, int] | None:
    """Shrink a PERSON span to its longest run of capitalized words.

    NER models (especially the English one on Portuguese text) tag lowercase phrases
    such as "encontra o champô de cetoconazol" as PERSON. Real names are capitalized,
    with particles (da, de, dos...) allowed only between capitalized words.
    """
    words = [(m.start() + start, m.end() + start, m.group()) for m in _WORD.finditer(text[start:end])]
    best, run = None, []
    for w in words + [None]:
        token = w[2].strip(".,;:!?()\"'") if w else ""
        if w and token[:1].isupper():
            run.append(w)
            continue
        if w and token.lower() in _NAME_PARTICLES and run:
            run.append(w)
            continue
        while run and run[-1][2].strip(".,;:!?()\"'").lower() in _NAME_PARTICLES:
            run.pop()
        if run and (best is None or run[-1][1] - run[0][0] > best[1] - best[0]):
            best = (run[0][0], run[-1][1])
        run = []
    if best is None:
        return None
    s, e = best
    while e > s and text[e - 1] in ".,;:!?)\"'":
        e -= 1
    return s, e


def _nif_valid(digits: str) -> bool:
    """Portuguese NIF/NIPC mod-11 check digit."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    total = sum(int(d) * (9 - i) for i, d in enumerate(digits[:8]))
    check = 11 - total % 11
    return int(digits[8]) == (0 if check >= 10 else check)


def portuguese_recognizers() -> list:
    """Pattern recognizers for Portugal (NIF, phone, postal code)."""
    from presidio_analyzer import Pattern, PatternRecognizer

    class PtNifRecognizer(PatternRecognizer):
        def validate_result(self, pattern_text: str):
            return True if _nif_valid(re.sub(r"\D", "", pattern_text)) else None

    return [
        PtNifRecognizer(
            supported_entity="PT_NIF",
            supported_language="pt",
            patterns=[Pattern("pt_nif", r"\b\d{3}[ .]?\d{3}[ .]?\d{3}\b", 0.3)],
            context=["nif", "nipc", "contribuinte", "fiscal"],
        ),
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            supported_language="pt",
            patterns=[
                Pattern("pt_phone_intl", r"(?:\+|00)351[ .-]?[239]\d{2}[ .-]?\d{3}[ .-]?\d{3}\b", 0.8),
                Pattern("pt_phone_local", r"\b(?:9[1236]\d|2\d{2})[ .-]?\d{3}[ .-]?\d{3}\b", 0.6),
            ],
            context=["telefone", "telemóvel", "telemovel", "tlm", "contacto"],
        ),
        PatternRecognizer(
            supported_entity="PT_ADDRESS",
            supported_language="pt",
            patterns=[Pattern(
                "pt_street",
                r"\b(?:rua|avenida|av\.|travessa|pra[cç]a|largo|estrada|alameda|beco|cal[cç]ada)\s+"
                r"(?:d[aeo]s?\s+)?\w[\w'’.-]*(?:\s+(?:d[aeo]s?\s+)?\w[\w'’.-]*){0,4}"
                r",?\s*(?:n\.?[ºo°]\s*)?\d{1,4}[a-z]?\b(?:\s*,?\s*\d{1,2}\.?[ºo°]?\s*(?:esq|dto|fte)?\.?)?",
                0.7,
            )],
            context=["morada", "resido", "moro", "entrega"],
        ),
        PatternRecognizer(
            supported_entity="PT_POSTAL_CODE",
            supported_language="pt",
            patterns=[Pattern("pt_postal", r"\b\d{4}-\d{3}\b", 0.6)],
            context=["código postal", "codigo postal", "morada"],
        ),
    ]


class PrivacyEngine:
    """Local detector + stable pseudonymizer."""

    def __init__(
        self,
        nlp_config_path: Path,
        *,
        language: str = "en",
        languages: Sequence[str] | None = None,
        entities: Sequence[str] | None = DEFAULT_ENTITIES,
        score_threshold: float = 0.55,
        enable_langextract: bool = False,
        langextract_config_path: str = "",
        vault: AliasVault | None = None,
    ) -> None:
        self.language = language
        self.languages = list(languages) if languages else [language]
        self.entities = list(entities) if entities else None  # None = every entity Presidio knows
        self.score_threshold = score_threshold
        self.vault = vault or AliasVault()

        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(conf_file=str(nlp_config_path))
        # Presidio's spaCy engine silently runs `spacy.cli.download` (an
        # unpinned pip install into the Hermes runtime) for a missing model.
        # Refuse instead; the model is a documented manual install.
        if provider.nlp_configuration.get("nlp_engine_name") == "spacy":
            import spacy.util

            for model in provider.nlp_configuration.get("models") or []:
                name = str(model.get("model_name", ""))
                if not (spacy.util.is_package(name) or Path(name).exists()):
                    raise RuntimeError(
                        f"spaCy model {name!r} is not installed; install it as "
                        "described in docs/INSTALL.md (the plugin will not "
                        "download it at runtime)"
                    )
        nlp_engine = provider.create_engine()
        registry = RecognizerRegistry(supported_languages=self.languages)
        registry.load_predefined_recognizers(
            languages=self.languages, nlp_engine=nlp_engine
        )
        if "pt" in self.languages:
            for recognizer in portuguese_recognizers():
                registry.add_recognizer(recognizer)
        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=self.languages,
        )

        if enable_langextract:
            from presidio_analyzer.predefined_recognizers.third_party.basic_langextract_recognizer import (
                BasicLangExtractRecognizer,
            )

            if langextract_config_path:
                recognizer = BasicLangExtractRecognizer(
                    config_path=langextract_config_path
                )
            else:
                recognizer = BasicLangExtractRecognizer()
            self.analyzer.registry.add_recognizer(recognizer)

    @staticmethod
    def remove_high_confidence_secrets(text: str) -> str:
        text = _PEM_PRIVATE_KEY.sub("[SECRET_REMOVED]", text)
        text = _AUTH_HEADER.sub("Authorization: [SECRET_REMOVED]", text)
        text = _SECRET_TOKENS.sub("[SECRET_REMOVED]", text)
        return _SECRET_ASSIGNMENT.sub(r"\1\2[SECRET_REMOVED]", text)

    def sanitize(self, text: str) -> str:
        """Replace detected PII with stable aliases; never alias secrets."""
        if not text:
            return text

        text = self.remove_high_confidence_secrets(text)
        protected = alias_ranges(text)
        # Run every configured language and merge; overlaps are resolved below.
        results = []
        for lang in getattr(self, "languages", None) or [self.language]:
            wanted = getattr(self, "entities", None)
            if wanted:  # only ask each language for entities it has recognizers for (no warnings)
                supported = set(self.analyzer.get_supported_entities(language=lang))
                wanted = [e for e in wanted if e in supported]
                if not wanted:
                    continue
            results.extend(
                self.analyzer.analyze(
                    text=text,
                    language=lang,
                    entities=wanted,
                    score_threshold=self.score_threshold,
                )
            )

        # Do not feed already-issued aliases back through Presidio.
        if protected:
            results = [
                result
                for result in results
                if not any(
                    result.start < end and result.end > start
                    for start, end in protected
                )
            ]

        trimmed = []
        for result in results:
            if result.entity_type == "PERSON":
                span = trim_person_span(text, result.start, result.end)
                if span is None:
                    continue
                result.start, result.end = span
            trimmed.append(result)
        results = trimmed

        if not results:
            return text

        results = select_non_overlapping_results(results)

        # Replace from right to left so Presidio's character offsets remain
        # valid while each detected span is converted to its stable alias.
        sanitized = text
        for result in sorted(results, key=lambda item: item.start, reverse=True):
            value = text[result.start : result.end]
            alias = self.vault.alias(result.entity_type, value)
            sanitized = sanitized[: result.start] + alias + sanitized[result.end :]
        return sanitized

    def sanitize_tree(self, value: Any) -> Any:
        return walk_strings(value, self.sanitize)

    def sanitize_model_content(self, value: Any) -> Any:
        """Sanitize provider text while preserving protocol IDs and enums."""
        return walk_model_text(value, self.sanitize)

    def rehydrate(self, text: str) -> str:
        return self.vault.rehydrate(text)

    def rehydrate_tree(self, value: Any) -> Any:
        return walk_strings(value, self.rehydrate)
