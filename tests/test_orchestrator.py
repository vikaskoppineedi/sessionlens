from sessionlens.orchestrator import lan_ip, preflight


def test_preflight_all_ok() -> None:
    checks = preflight(which=lambda _: "/bin/x", can_capture=lambda: True, exists=lambda _: True)
    assert all(c.ok for c in checks)


def test_preflight_reports_fixes() -> None:
    checks = preflight(which=lambda _: None, can_capture=lambda: False, exists=lambda _: False)
    fixes = {c.name: c.fix for c in checks if not c.ok}
    assert fixes["tshark installed"] == "brew install wireshark"
    assert "wireshark-chmodbpf" in fixes["Packet capture permission"]
    assert "npm run build" in fixes["Analyzer UI built"]


def test_lan_ip_is_ipv4_or_none() -> None:
    ip = lan_ip()
    assert ip is None or ip.count(".") == 3
