from app.services.parsing.cisco import parse_cisco

CONFIG = """!
hostname core-sw-01
!
ip ssh version 2
no ip http server
!
line vty 0 4
 transport input ssh
 exec-timeout 5 0
 access-class MGMT-ACL in
!
line con 0
 exec-timeout 10 0
!
end
"""


def test_top_level_commands_become_roots() -> None:
    tree = parse_cisco(CONFIG)
    texts = [node.text for node in tree.roots]
    assert "hostname core-sw-01" in texts
    assert "line vty 0 4" in texts


def test_indented_commands_become_children() -> None:
    tree = parse_cisco(CONFIG)
    vty = tree.first(r"^line vty")
    assert vty is not None
    assert [child.text for child in vty.children] == [
        "transport input ssh",
        "exec-timeout 5 0",
        "access-class MGMT-ACL in",
    ]


def test_line_numbers_are_one_indexed_and_accurate() -> None:
    tree = parse_cisco(CONFIG)
    hostname = tree.first(r"^hostname")
    assert hostname is not None
    assert hostname.lineno == 2


def test_comment_and_blank_lines_are_dropped() -> None:
    tree = parse_cisco(CONFIG)
    assert all(not node.text.startswith("!") for node in tree.roots)
    assert all(node.text.strip() for node in tree.roots)


def test_find_searches_recursively() -> None:
    tree = parse_cisco(CONFIG)
    matches = tree.find(r"^exec-timeout")
    assert len(matches) == 2


def test_node_scoped_find_does_not_leak_across_blocks() -> None:
    tree = parse_cisco(CONFIG)
    vty = tree.first(r"^line vty")
    con = tree.first(r"^line con")
    assert vty is not None and con is not None
    assert len(vty.find(r"^exec-timeout")) == 1
    assert vty.first(r"^access-class") is not None
    assert con.first(r"^access-class") is None


def test_dedent_closes_nested_blocks() -> None:
    nested = (
        "router bgp 65001\n address-family ipv4\n  network 10.0.0.0\n exit-address-family\nend\n"
    )
    tree = parse_cisco(nested)
    bgp = tree.first(r"^router bgp")
    assert bgp is not None
    af = bgp.first(r"^address-family")
    assert af is not None
    assert [child.text for child in af.children] == ["network 10.0.0.0"]


def test_unexpected_dedent_records_a_warning_without_failing() -> None:
    ragged = "line vty 0 4\n   transport input ssh\n  exec-timeout 5 0\n"
    tree = parse_cisco(ragged)
    assert tree.warnings, "ragged indentation should warn"
    assert tree.first(r"^line vty") is not None
