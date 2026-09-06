from app.services.parsing.base import ConfigNode, ConfigTree, ParseWarning, parse_indented

__all__ = ["ConfigNode", "ConfigTree", "ParseWarning", "parse_cisco"]


def parse_cisco(text: str) -> ConfigTree:
    """Build an indentation tree from an IOS-style configuration.

    Thin vendor adapter over the shared indentation parser (services/parsing/base.py)
    — Cisco IOS uses `!` for comments and has no vendor-specific parsing quirks of
    its own today, so this is currently just that call. Existing imports of
    `ConfigNode`/`ConfigTree`/`ParseWarning` from this module keep working.
    """
    return parse_indented(text, comment_chars="!")
