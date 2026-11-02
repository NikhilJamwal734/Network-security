import unittest
from app.f5_phase1_addon.parser import parse
from app.f5_phase1_addon.checks import analyze
from app.f5_phase2_addon.review import extend_report
from app.f5_phase5_addon.assurance import build_assurance

CONFIG = '''ltm profile client-ssl /Common/client { defaults-from /Common/base options { no-tlsv1.3 } }
ltm profile server-ssl /Common/server { ciphers DEFAULT peer-cert-mode ignore }
ltm virtual /Common/web { profiles { /Common/client { } /Common/server { } /Common/missing { } } rules { /Common/test { } } }
ltm rule /Common/test { when HTTP_REQUEST { if { [HTTP::uri] contains "/test" } { ASM::disable } } }
'''

class AssuranceTests(unittest.TestCase):
    def test_additive_no_change_to_findings(self):
        objects = parse(CONFIG)
        report = extend_report(analyze(objects),objects,CONFIG)
        before = (report['summary']['total_findings'], report['summary']['total_review_observations'])
        extra = build_assurance(objects,CONFIG,report)
        self.assertEqual(before, (report['summary']['total_findings'],report['summary']['total_review_observations']))
        self.assertEqual(extra['assessment_type'],'static_evidence_quality_review')
        self.assertEqual(extra['device_version']['status'],'not_verified')
        self.assertEqual(extra['coverage']['runtime_verification'],'not_performed')
        self.assertTrue(extra['profile_inheritance'])
        self.assertTrue(extra['unresolved_profile_references'])
        self.assertTrue(extra['irule_control_flow_review'])
        self.assertFalse(extra['irule_control_flow_review'][0]['live_waf_bypass_proven'])
        self.assertTrue(all(x['resolved_cipher_suites'] is None for x in extra['profile_tls_evidence']))

    def test_no_unwarranted_runtime_claim(self):
        objects=parse('ltm profile server-ssl /Common/s { ciphers DEFAULT peer-cert-mode ignore }')
        extra=build_assurance(objects,'ltm profile server-ssl /Common/s { ciphers DEFAULT peer-cert-mode ignore }',analyze(objects))
        self.assertFalse(extra['coverage']['logging_delivery_verified'])
        self.assertFalse(extra['coverage']['signature_package_verified'])
        self.assertFalse(extra['coverage']['HTTP_HSTS_header_verified'])

if __name__ == '__main__': unittest.main()
