"""API-010.1 vendor-specific accuracy checks and negative regression tests."""
from app.core.vendor_review import review_cisco_asa, review_fortios, review_snort, review_suricata
from app.parsers.firewalls.fortios import FortiOSParser
from app.parsers.ids.snort import SnortParser
from app.parsers.ids.suricata import SuricataParser
import pytest


def codes(review):
    return [check["code"] for check in review["checks"]]


def test_asa_telnet_all():
    r = review_cisco_asa(["hostname ASA", "telnet 0.0.0.0 0.0.0.0 outside"])
    assert codes(r) == ["ASA-DEEP-001"]
    assert r["checks"][0]["line_number"] == 2


def test_asa_ssh_all():
    assert "ASA-DEEP-002" in codes(review_cisco_asa(["ssh 0.0.0.0 0.0.0.0 inside"]))


def test_asa_explicit_logging_disabled():
    assert "ASA-DEEP-003" in codes(review_cisco_asa(["no logging enable"]))


@pytest.mark.parametrize("line", [
    "! telnet 0.0.0.0 0.0.0.0 outside",
    "# ssh 0.0.0.0 0.0.0.0 inside",
    "telnet timeout 3",
    "telnet 192.168.1.0 255.255.255.0 inside",
    "ssh 198.51.100.0 255.255.255.0 outside",
    "logging enable",
    "no logging buffered",
])
def test_asa_does_not_overflag(line):
    assert review_cisco_asa([line])["checks"] == []


def parse_fortios(src):
    return FortiOSParser().parse(src.strip().splitlines())


def test_fortios_all_address_policy_but_limited_service():
    r = review_fortios(parse_fortios("""
config firewall policy
 edit 17
  set action accept
  set srcaddr all
  set dstaddr all
  set service HTTPS
 next
end
"""))
    assert codes(r) == ["FORTIOS-DEEP-001"]
    assert r["checks"][0]["rule_id"] == "17"


def test_fortios_no_extra_duplicate_for_all_service():
    r = review_fortios(parse_fortios("""
config firewall policy
 edit 17
  set action accept
  set srcaddr all
  set dstaddr all
  set service ALL
 next
end
"""))
    assert "FORTIOS-DEEP-001" not in codes(r)


def test_fortios_disabled_policy_ignored():
    r = review_fortios(parse_fortios("""
config firewall policy
 edit 17
  set action accept
  set status disable
  set srcaddr all
  set dstaddr all
  set service HTTPS
 next
end
"""))
    assert r["checks"] == []


def test_fortios_wan_explicit_secure_management():
    r = review_fortios(parse_fortios("""
config system interface
 edit wan1
  set role wan
  set allowaccess ping https ssh
 next
end
"""))
    assert codes(r) == ["FORTIOS-DEEP-002"]
    assert "ssh" in r["checks"][0]["detail"]


def test_fortios_no_wan_guess():
    r = review_fortios(parse_fortios("""
config system interface
 edit wan1
  set allowaccess https
 next
end
"""))
    assert r["checks"] == []


def test_fortios_down_wan_ignored():
    r = review_fortios(parse_fortios("""
config system interface
 edit wan1
  set role wan
  set status down
  set allowaccess https
 next
end
"""))
    assert r["checks"] == []


def test_fortios_full_service_port_span():
    r = review_fortios(parse_fortios("""
config firewall service custom
 edit "very-wide"
  set tcp-portrange 1-65535
 next
end
"""))
    assert codes(r) == ["FORTIOS-DEEP-003"]


def test_fortios_partial_ports_not_flagged():
    r = review_fortios(parse_fortios("""
config firewall service custom
 edit "web"
  set tcp-portrange 443
 next
end
"""))
    assert r["checks"] == []


def test_snort_unrestricted_drop_rule():
    lines = ["drop tcp any any -> any any (sid:10001; msg:\"block\"; rev:1;)"]
    r = review_snort(SnortParser().parse(lines))
    assert codes(r) == ["SNORT-DEEP-001"]
    assert r["checks"][0]["rule_id"] == 10001


@pytest.mark.parametrize("rule", [
    '# drop tcp any any -> any any (sid:10001;)',
    'alert tcp any any -> any any (sid:10001;)',
    'drop tcp $HOME_NET any -> any any (sid:10001;)',
    'drop tcp any any -> any any (content:"foo"; sid:10001;)',
])
def test_snort_nonblocking_or_restricted_not_flagged(rule):
    assert review_snort(SnortParser().parse([rule]))["checks"] == []


def test_snort_home_net_zero_prefix():
    r = review_snort(SnortParser().parse(["ipvar HOME_NET 0.0.0.0/0"]))
    assert codes(r) == ["SNORT-DEEP-002"]


def test_snort_home_net_concrete():
    assert review_snort(SnortParser().parse(["ipvar HOME_NET 10.0.0.0/8"]))["checks"] == []


def test_suricata_unrestricted_drop_rule():
    lines = ["drop tcp any any -> any any (sid:211; rev:1;)"]
    r = review_suricata(SuricataParser().parse(lines))
    assert codes(r) == ["SURICATA-DEEP-001"]
    assert r["checks"][0]["line_number"] == 1


@pytest.mark.parametrize("rule", [
    '# drop tcp any any -> any any (sid:211;)',
    'alert tcp any any -> any any (sid:211;)',
    'drop tcp any any -> any any (content:"x"; sid:211;)',
    '# Log some explanation and do not parse it as a rule',
])
def test_suricata_nonblocking_comment_restricted_not_flagged(rule):
    assert review_suricata(SuricataParser().parse([rule]))["checks"] == []


def test_suricata_home_net_zero_prefix():
    lines = ["vars:", "  address-groups:", '    HOME_NET: "[0.0.0.0/0]"']
    assert codes(review_suricata(SuricataParser().parse(lines))) == ["SURICATA-DEEP-002"]


def test_suricata_home_net_concrete():
    lines = ["vars:", "  address-groups:", '    HOME_NET: "[10.0.0.0/8]"']
    assert review_suricata(SuricataParser().parse(lines))["checks"] == []


def test_deep_route_preserves_other_report_contracts():
    from fastapi.testclient import TestClient
    from app.api.main import app
    lines = b"drop tcp any any -> any any (sid:1001; rev:1;)"
    with TestClient(app) as client:
        deep = client.post("/api/v1/analyze/deep-review?platform=snort",
                           files={"file": ("rules.rules", lines, "text/plain")})
        validated = client.post("/api/v1/analyze/validated?platform=snort",
                                files={"file": ("rules.rules", lines, "text/plain")})
    assert deep.status_code == validated.status_code == 200
    deep_body = deep.json()
    extra = deep_body.pop("vendor_review")
    assert extra["checks"][0]["code"] == "SNORT-DEEP-001"
    assert deep_body == validated.json()


def test_universal_legacy_route_no_extra_field():
    from fastapi.testclient import TestClient
    from app.api.main import app
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze/universal?platform=snort",
            files={"file": ("rules.rules", b"drop tcp any any -> any any (sid:10;)", "text/plain")})
    assert response.status_code == 200
    assert "vendor_review" not in response.json()

def test_bounded_results_no_raw_lines_leaked():
    lines = ["no logging enable"] * 300
    r = review_cisco_asa(lines)
    assert len(r["checks"]) <= 40
    assert r["suppressed_checks"] > 0
    assert all("no logging enable" not in str(x.get("recommendation")) for x in r["checks"])


def test_four_platform_review_limits_are_explicit():
    instances = (
        review_cisco_asa([]), review_fortios(parse_fortios('config firewall policy\nend')),
        review_snort(SnortParser().parse([])), review_suricata(SuricataParser().parse([])),
    )
    for review in instances:
        assert review["limitations"]
        assert review["scope"] == "supplemental_vendor_specific_static_review"
        assert "not included" in review["interpretation"]

@pytest.mark.parametrize("platform,filename,content,code", [
    ("cisco_asa", "firewall.conf", b"hostname ASA\nssh 0.0.0.0 0.0.0.0 outside\n", "ASA-DEEP-002"),
    ("fortios", "fortios.conf", b"config firewall policy\n edit 7\n set action accept\n set srcaddr all\n set dstaddr all\n set service HTTPS\n next\nend\n", "FORTIOS-DEEP-001"),
    ("snort", "test.rules", b"drop tcp any any -> any any (sid:1101; rev:1;)\n", "SNORT-DEEP-001"),
    ("suricata", "test.rules", b"drop tcp any any -> any any (sid:1101; rev:1;)\n", "SURICATA-DEEP-001"),
])
def test_deep_endpoint_all_platforms(platform, filename, content, code):
    from fastapi.testclient import TestClient
    from app.api.main import app
    with TestClient(app) as client:
        response = client.post(f"/api/v1/analyze/deep-review?platform={platform}",
                               files={"file": (filename, content, "text/plain")})
    assert response.status_code == 200, response.text
    doc = response.json()
    assert doc["platform"]["platform_id"] == platform
    assert code in codes(doc["vendor_review"])
    assert doc["quality"]["summary"]["errors"] == 0
    assert doc["summary"]["total_findings"] == len(doc["findings"])


def test_suricata_yaml_comments_do_not_trigger_deep_rule_detections():
    from fastapi.testclient import TestClient
    from app.api.main import app
    payload = b"%YAML 1.1\n---\nrule-files:\n  - local.rules\n# Log all traffic\n# drop tcp bad invalid\n"
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze/deep-review?platform=suricata",
                               files={"file": ("suricata.yaml", payload, "text/plain")})
    assert response.status_code == 200, response.text
    assert response.json()["vendor_review"]["checks"] == []
