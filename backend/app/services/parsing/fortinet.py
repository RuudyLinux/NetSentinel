from app.services.parsing.base import ConfigTree, parse_indented

__all__ = ["parse_fortinet"]


def parse_fortinet(text: str) -> ConfigTree:
    """Build an indentation tree from a FortiOS configuration.

    FortiOS backup/`show full-configuration` output nests `set`/`edit`/`next` lines
    under their enclosing `config ... / end` block with consistent leading-space
    indentation, same as Cisco IOS — so this is the shared indentation parser
    (services/parsing/base.py) with FortiOS's comment character (`#`) instead of
    Cisco's (`!`). The `#config-version=...` header line is itself a comment and
    is skipped the same way.
    """
    return parse_indented(text, comment_chars="#")
