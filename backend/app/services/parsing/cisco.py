import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParseWarning:
    lineno: int
    message: str


@dataclass
class ConfigNode:
    """One configuration command, with any indented commands beneath it."""

    text: str
    lineno: int
    indent: int
    children: list["ConfigNode"] = field(default_factory=list)

    def find(self, pattern: str) -> list["ConfigNode"]:
        """Every descendant whose text matches, depth-first. Does not match self."""
        compiled = re.compile(pattern)
        found: list[ConfigNode] = []
        for child in self.children:
            if compiled.search(child.text):
                found.append(child)
            found.extend(child.find(pattern))
        return found

    def first(self, pattern: str) -> "ConfigNode | None":
        matches = self.find(pattern)
        return matches[0] if matches else None


@dataclass
class ConfigTree:
    roots: list[ConfigNode] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)

    def find(self, pattern: str) -> list[ConfigNode]:
        compiled = re.compile(pattern)
        found: list[ConfigNode] = []
        for root in self.roots:
            if compiled.search(root.text):
                found.append(root)
            found.extend(root.find(pattern))
        return found

    def first(self, pattern: str) -> ConfigNode | None:
        matches = self.find(pattern)
        return matches[0] if matches else None


def _is_noise(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("!")


def parse_cisco(text: str) -> ConfigTree:
    """Build an indentation tree from an IOS-style configuration.

    Unparseable indentation is recorded as a warning rather than raised: a ragged
    block should not cost the operator an entire audit.
    """
    tree = ConfigTree()
    stack: list[ConfigNode] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _is_noise(raw):
            continue

        indent = len(raw) - len(raw.lstrip())
        node = ConfigNode(text=raw.strip(), lineno=lineno, indent=indent)

        while stack and stack[-1].indent >= indent:
            stack.pop()

        if not stack:
            if indent > 0 and not tree.roots:
                tree.warnings.append(
                    ParseWarning(lineno=lineno, message="indented line with no parent block")
                )
            tree.roots.append(node)
        else:
            parent = stack[-1]
            if indent <= parent.indent:  # pragma: no cover - guarded by the while loop
                tree.warnings.append(ParseWarning(lineno=lineno, message="unexpected dedent"))
            parent.children.append(node)

        stack.append(node)

    _warn_on_ragged_indentation(tree)
    return tree


def _warn_on_ragged_indentation(tree: ConfigTree) -> None:
    """Siblings at differing indents mean the source formatting is inconsistent."""

    def walk(nodes: list[ConfigNode]) -> None:
        indents = {node.indent for node in nodes}
        if len(indents) > 1:
            tree.warnings.append(
                ParseWarning(
                    lineno=nodes[0].lineno,
                    message=f"sibling commands at differing indents: {sorted(indents)}",
                )
            )
        for node in nodes:
            if node.children:
                walk(node.children)

    for root in tree.roots:
        if root.children:
            walk(root.children)
