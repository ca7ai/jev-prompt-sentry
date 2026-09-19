"""The only module that knows the Anthropic Messages wire format.

Supporting a second API shape means writing a sibling of this file and nothing
else.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# Block types known to carry no recoverable text in a text-only v1. Anything
# NOT listed here and NOT `text` is treated as untrusted content when any text
# can be pulled out of it, and counted as an unknown block when it cannot.
_KNOWN_NON_TEXT_BLOCK_TYPES = frozenset({"image"})


@dataclass(frozen=True)
class UntrustedBlock:
    source: str
    text: str


@dataclass(frozen=True)
class ExtractedInput:
    user_message: str
    untrusted: tuple[UntrustedBlock, ...]
    # Blocks of a type we know to be non-textual (images) - "a PDF we cannot
    # read". Nothing was withheld from the guard that the guard could have used.
    skipped_non_text: int
    # Blocks of an unrecognised type from which no text could be recovered.
    # These are the risky ones: the upstream model may still read text out of a
    # shape this extractor does not understand, so an operator needs to see them
    # separately from the benign image case.
    skipped_unknown_text: int

    @property
    def is_empty(self) -> bool:
        """True when there is nothing for the guard to judge."""
        return not self.user_message.strip() and not self.untrusted


def _block_text(block: Mapping[str, Any]) -> str:
    """Pull text out of a block whose `content` may be a string or a list."""
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence):
        parts = [
            str(item.get("text", ""))
            for item in content
            if isinstance(item, Mapping) and item.get("type") == "text"
        ]
        return "\n\n".join(p for p in parts if p)
    source = block.get("source")
    if isinstance(source, Mapping) and source.get("type") == "text":
        return str(source.get("data", ""))
    return ""


def extract(body: Mapping[str, Any]) -> ExtractedInput:
    messages = body.get("messages")
    if not isinstance(messages, Sequence):
        return ExtractedInput("", (), 0, 0)

    # Scan backwards: an assistant-prefill request ends with an assistant turn,
    # and guarding messages[-1] would leave the user's text unscreened.
    last_user: Mapping[str, Any] | None = None
    for message in reversed(messages):
        if isinstance(message, Mapping) and message.get("role") == "user":
            last_user = message
            break
    if last_user is None:
        return ExtractedInput("", (), 0, 0)

    content = last_user.get("content")
    if isinstance(content, str):
        return ExtractedInput(content, (), 0, 0)
    if not isinstance(content, Sequence):
        return ExtractedInput("", (), 0, 0)

    texts: list[str] = []
    untrusted: list[UntrustedBlock] = []
    skipped_non_text = 0
    skipped_unknown_text = 0
    for block in content:
        if not isinstance(block, Mapping):
            continue
        block_type = block.get("type")
        if block_type == "text":
            text = str(block.get("text", ""))
            if text:
                texts.append(text)
            continue

        # Default to screening, not to allowing: the decision is driven by
        # whether text can be recovered at all, never by membership in a fixed
        # list of known block types. A block type this file has never heard of
        # that carries text the upstream model will read is exactly the case an
        # allowlist forwards unscreened.
        text = _block_text(block)
        if text:
            untrusted.append(
                UntrustedBlock(source=str(block_type or "unknown"), text=text)
            )
        elif block_type in _KNOWN_NON_TEXT_BLOCK_TYPES:
            skipped_non_text += 1
        else:
            skipped_unknown_text += 1

    return ExtractedInput(
        "\n\n".join(texts), tuple(untrusted), skipped_non_text, skipped_unknown_text
    )


def to_state(extracted: ExtractedInput) -> dict[str, Any]:
    """Build Jev state. Trust zones stay in separate named fields so a question
    about one cannot silently read the other."""
    state: dict[str, Any] = {"user_message": extracted.user_message}
    if extracted.untrusted:
        # Omitted entirely when empty: an empty list invites noise on the
        # question that references it, and omitting it saves tokens.
        state["untrusted_content"] = [
            {"source": b.source, "text": b.text} for b in extracted.untrusted
        ]
    return state
