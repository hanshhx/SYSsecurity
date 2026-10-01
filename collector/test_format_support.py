"""5.1 지원에서 틀린 규칙 선택·정보 손실·기존 결과 덮어쓰기를 확인함."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

import normalize_cve as normalizer
import test_normalize_cve as existing_tests

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'fixtures' / 'CVE-2021-32803.json'
SCHEMA51 = HERE.parent / 'schemas' / 'cve-5.1.1' / 'CVE_Record_Format_bundled.json'
SCHEMA52 = HERE.parent / 'schemas' / 'cve-5.2.0' / 'CVE_Record_Format_bundled.json'


class FormatSupportTests(unittest.TestCase):
    def setUp(self):
        # 기존 시험의 수집 폴더 준비만 재사용함. 제품의 저장·검사 코드는 실제로 실행함.
        self.helper = existing_tests.NormalizeTests()
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)
        self.folder = self.helper.folder
        self.record = json.loads(FIXTURE.read_bytes())
        self.helper.save(self.record)

    def normalize(self):
        try:
            path = normalizer.normalize_collection(self.folder)
        except normalizer.CollectorError as exc:
            self.fail('정상 5.1 자료를 처리하지 못함: ' + exc.code)
        return path, json.loads(path.read_bytes())

    def assert_refused(self, code, **kwargs):
        with self.assertRaises(normalizer.CollectorError) as caught:
            normalizer.normalize_collection(self.folder, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(list(self.folder.glob('normalized-*/normalized.json')), [])

    def test_actual_51_uses_511_rules_and_preserves_original_version_ranges(self):
        raw = (self.folder / 'original.json').read_bytes()
        _, result = self.normalize()
        self.assertEqual(result['dataVersion'], '5.1')
        self.assertEqual(result['validation']['schemaRelease'], '5.1.1')
        self.assertEqual(result['validation']['schemaSha256'],
                         'c5f31c951a2934858e0925d40eec81006c9daad554cad133e00bc181ca578c74')
        product = result['products'][0]['data']
        self.assertEqual((product['vendor'], product['product']), ('npm', 'node-tar'))
        self.assertEqual([v['version'] for v in product['versions']],
                         ['< 3.2.3', '>= 4.0.0, < 4.4.15', '>= 5.0.0, < 5.0.7', '>= 6.0.0, < 6.1.2'])
        self.assertEqual((self.folder / 'original.json').read_bytes(), raw)
        self.assertEqual(result['source']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertFalse(result['readyForMatching'])

    def test_actual_51_provider_contents_can_be_reconstructed_without_loss(self):
        _, result = self.normalize()
        originals = [self.record['containers']['cna'], *self.record['containers'].get('adp', [])]
        self.assertEqual(len(result['sources']), len(originals))
        for source, original in zip(result['sources'], originals):
            restored = copy.deepcopy(source['information'])
            restored['providerMetadata'] = source['provider']
            for field, group in (('affected', 'products'), ('metrics', 'metrics')):
                if field not in source['missingFields']:
                    restored[field] = [item['data'] for item in result[group] if item['sourcePath'] == source['path']]
            self.assertEqual(restored, original)

    def test_51_rejection_reason_is_kept_without_creating_a_protection_candidate(self):
        self.record['cveMetadata']['state'] = 'REJECTED'
        self.record['containers'] = {'cna': {
            'providerMetadata': self.record['containers']['cna']['providerMetadata'],
            'rejectedReasons': [{'lang': 'en', 'value': 'Synthetic test: duplicate record.'}]}}
        self.helper.save(self.record)
        _, result = self.normalize()
        self.assertEqual(result['recordState'], 'REJECTED')
        self.assertEqual(result['products'], [])
        self.assertFalse(result['readyForMatching'])
        self.assertEqual(result['sources'][0]['information']['rejectedReasons'][0]['value'],
                         'Synthetic test: duplicate record.')

    def test_incomplete_51_is_refused_instead_of_only_accepting_its_version_label(self):
        self.record['containers']['cna'] = {}
        self.helper.save(self.record)
        self.assert_refused('SCHEMA_INVALID')

    def test_51_cannot_be_validated_using_the_52_schema_override(self):
        self.assert_refused('SCHEMA_INTEGRITY', schema_path=SCHEMA52)

    def test_changed_51_rules_are_refused_before_validation(self):
        altered = self.folder / 'changed-schema.json'
        altered.write_bytes(SCHEMA51.read_bytes() + b' ')
        self.assert_refused('SCHEMA_INTEGRITY', schema_path=altered)

    def test_repeated_51_normalization_keeps_first_result_and_original(self):
        original = (self.folder / 'original.json').read_bytes()
        first, _ = self.normalize()
        first_raw = first.read_bytes()
        second, _ = self.normalize()
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), first_raw)
        self.assertEqual((self.folder / 'original.json').read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
