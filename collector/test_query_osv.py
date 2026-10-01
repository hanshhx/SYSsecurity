"""OSV 수집의 관측 가능한 결과를 시험함. 가상 응답은 실제 API 형태의 자작 자료임."""
from copy import deepcopy
import hashlib
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

try:
    import query_osv as subject
    import osv_io
    import osv_records
except ModuleNotFoundError as exc:
    if exc.name not in ('query_osv', 'osv_io', 'osv_records'):
        raise
    subject = None

HERE = Path(__file__).resolve().parent
QUERY = {'package': {'name': 'tar', 'ecosystem': 'npm'}, 'version': '6.1.0'}


def record(identifier='GHSA-r628-mhmh-qjhw', **changes):
    # 실제 사건처럼 꾸미지 않고 공식 형식에 맞춘 시험 전용 자료를 사용함.
    value = {'schema_version':'1.9.0', 'id':identifier, 'modified':'2026-01-01T00:00:00Z',
             'aliases':['CVE-2021-32803'], 'summary':'Synthetic test record',
             'affected':[{'package':{'ecosystem':'npm','name':'tar'},
                          'ranges':[{'type':'SEMVER','events':[{'introduced':'6.0.0'},{'fixed':'6.1.2'}]}]}]}
    value.update(changes)
    return value


def encode(value):
    return json.dumps(value, ensure_ascii=True).encode('utf-8')


class Response(io.BytesIO):
    def __init__(self, body, status=200, kind='application/json', length=None):
        super().__init__(body)
        self.status = status
        self.headers = {'Content-Type':kind, 'Content-Length':str(len(body) if length is None else length)}


class OsvTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(subject, 'OSV_NOT_IMPLEMENTED: 새 OSV 조회 기능이 아직 없음')
        self.temp = tempfile.TemporaryDirectory(prefix='syssecurity-osv-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.attempt = self.root/'attempt'
        self.attempt.mkdir()

    def collect(self, pages):
        # HTTP 반환 경계만 교체함. 읽기·자료 검사·저장·최종 대조는 실제 코드임.
        responses = [v if isinstance(v, Exception) or isinstance(v, Response) else Response(encode(v)) for v in pages]
        with patch.object(osv_io, 'open_response', side_effect=responses) as connection:
            subject.collect_pages(QUERY, self.attempt, pause_seconds=0)
        return subject.verify_result(QUERY, self.attempt), connection

    def assert_failure(self, pages, code):
        with self.assertRaises(osv_io.OsvError) as caught:
            self.collect(pages)
        self.assertEqual(caught.exception.code, code)
        self.assertFalse((self.attempt/'result.json').exists())
        return caught.exception

    def test_two_pages_use_same_target_and_token_and_preserve_raw_sources(self):
        a = {'vulns':[record()], 'next_page_token':'next:one'}
        b = {'vulns':[record('GHSA-aaaa-bbbb-cccc', aliases=[])]}
        result, connection = self.collect([a,b])
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(result['counts']['uniqueRecords'],2)
        self.assertEqual(result['cveIds'], ['CVE-2021-32803'])
        self.assertFalse(result['readyForMatching'])
        self.assertEqual(connection.call_args_list[0].args[0], QUERY)
        self.assertEqual(connection.call_args_list[1].args[0], {**QUERY, 'page_token':'next:one'})
        self.assertEqual((self.attempt/'page-0001.json').read_bytes(), encode(a))
        self.assertEqual(result['pages'][0]['sha256'], hashlib.sha256(encode(a)).hexdigest())
        self.assertIn('Attribution 4.0', (self.attempt/'GHSA_CC_BY_4_0.txt').read_text(encoding='utf-8'))
        self.assertEqual(result['records'][0]['source']['license'], 'CC-BY-4.0')

    def test_empty_response_is_complete_query_not_safe_verdict(self):
        result, _ = self.collect([{}])
        self.assertEqual(result['counts']['uniqueRecords'], 0)
        self.assertEqual(result['queryOutcome'], 'NO_RECORDS_RETURNED')
        self.assertFalse(result['readyForMatching'])
        self.assertNotIn('verdict',result)

    def test_token_only_page_keeps_querying(self):
        result, connection = self.collect([{'next_page_token':'more'}, {'vulns':[record()]}])
        self.assertEqual(len(result['pages']), 2)
        self.assertEqual(result['counts']['uniqueRecords'], 1)
        self.assertEqual(connection.call_count,2)

    def test_second_page_failure_keeps_first_page_but_never_completes(self):
        self.assert_failure([{'vulns':[record()], 'next_page_token':'more'}, URLError('offline')], 'NETWORK_ERROR')
        self.assertTrue((self.attempt/'page-0001.json').exists())
        self.assertFalse((self.attempt/'draft-result.json').exists())

    def test_repeated_pagination_token_is_failure(self):
        self.assert_failure([{'next_page_token':'same'}, {'next_page_token':'same'}], 'PAGINATION_LOOP')

    def test_page_limit_cannot_be_called_complete(self):
        with patch.object(subject,'MAX_PAGES',2):
            self.assert_failure([{'next_page_token':'a'}, {'next_page_token':'b'}], 'PAGE_LIMIT')

    def test_duplicate_id_same_data_is_counted_once_but_aliases_do_not_merge_ids(self):
        result, _ = self.collect([{'vulns':[record(),record(),record('GHSA-aaaa-bbbb-cccc')]}])
        self.assertEqual(result['counts']['uniqueRecords'],2)
        self.assertEqual(result['counts']['duplicateRecords'],1)
        self.assertEqual(len(result['cveIds']),1)

    def test_conflicting_duplicate_is_failure_not_last_write_wins(self):
        self.assert_failure([{'vulns':[record(),record(summary='changed')]}], 'CONFLICTING_RECORD')

    def test_withdrawn_and_missing_fields_are_kept_separate(self):
        withdrawn=record(withdrawn='2026-02-01T00:00:00Z', affected=None, aliases=None)
        result, _ = self.collect([{'vulns':[withdrawn]}])
        entry=result['records'][0]
        self.assertEqual(entry['state'],'WITHDRAWN')
        self.assertIn('severity',entry['missingFields'])
        self.assertIn('affected',entry['missingFields'])
        self.assertEqual(entry['data'],withdrawn)
        self.assertEqual(entry['cveIds'],[])
        self.assertEqual(result['counts']['withdrawn'],1)

    def test_active_missing_affected_and_unknown_license_are_review_items(self):
        value={'id':'OSV-2020-111','modified':'2026-01-01T00:00:00Z'}
        result,_=self.collect([{'vulns':[value]}])
        entry=result['records'][0]
        self.assertEqual(entry['schemaVersion'],'1.0.0')
        self.assertIn('TARGET_INFORMATION_MISSING',entry['issues'])
        self.assertIn('LICENSE_REVIEW_REQUIRED',entry['issues'])
        self.assertIsNone(entry['source']['license'])
        self.assertIsNone(entry['source']['licenseFile'])
        self.assertNotEqual(entry['state'],'WITHDRAWN')

    def test_query_target_mismatch_is_not_silently_attributed_to_requested_package(self):
        v=record(affected=[{'package':{'name':'other','ecosystem':'npm'}}])
        result,_=self.collect([{'vulns':[v]}])
        self.assertIn('TARGET_NOT_IN_RECORD',result['records'][0]['issues'])
        self.assertEqual(result['records'][0]['matchingPackageIndexes'],[])

    def test_actual_ghsa_ranges_scores_and_all_fields_are_preserved(self):
        v=json.loads((HERE/'fixtures/GHSA-r628-mhmh-qjhw.json').read_bytes())
        result,_=self.collect([{'vulns':[v]}])
        entry=result['records'][0]
        self.assertEqual(entry['data'],v)
        self.assertEqual(entry['matchingPackageIndexes'],[0,1,2,3])
        self.assertEqual(entry['cveIds'],['CVE-2021-32803'])
        self.assertTrue(entry['data']['severity'][0]['score'].startswith('CVSS:3.1/'))
        self.assertNotIn('baseScore',entry)

    def test_invalid_timestamp_range_and_top_level_values_are_refused(self):
        examples=[record(modified='2026-02-30T00:00:00Z'),record(aliases=[3]),
                  record(affected=[{'package':{'name':'tar'}}]),
                  record(affected=[{'package':{'name':'tar','ecosystem':'npm'},'ranges':[{'type':'SEMVER','events':[]}]}])]
        for v in examples:
            with self.subTest(value=v):
                with self.assertRaises(osv_io.OsvError):
                    osv_records.normalize(v, QUERY, osv_records.load_validator())

    def test_future_schema_major_or_minor_is_not_guessed(self):
        for version in ('2.0.0','1.10.0','bad',None):
            with self.subTest(version=version), self.assertRaises(osv_io.OsvError) as caught:
                osv_records.normalize(record(schema_version=version), QUERY, osv_records.load_validator())
            self.assertEqual(caught.exception.code,'UNSUPPORTED_OSV_FORMAT')

    def test_modified_official_schema_and_notice_are_refused_before_http(self):
        fake=self.root/'schema.json';fake.write_bytes(b'{}')
        with patch.object(osv_records,'SCHEMA_PATH',fake), patch.object(osv_io,'open_response') as connection:
            with self.assertRaises(osv_io.OsvError):
                subject.collect_pages(QUERY,self.attempt,pause_seconds=0)
            connection.assert_not_called()
        fake.write_bytes(b'not the license')
        with patch.dict(subject.NOTICE_FILES,{'GHSA_CC_BY_4_0.txt':(fake,'9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94')}), patch.object(osv_io,'open_response') as connection:
            with self.assertRaises(osv_io.OsvError):
                subject.collect_pages(QUERY,self.attempt,pause_seconds=0)
            connection.assert_not_called()

    def test_json_duplicates_nonfinite_invalid_utf8_and_deep_nesting_are_refused(self):
        for raw in (b'{"vulns":[],"vulns":[]}', b'{"n":NaN}', b'{"n":1e999}', b'\xff', b'['*65+b']'*65, b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(osv_io.OsvError):
                osv_io.parse_json(raw)

    def test_bad_page_shape_and_token_are_refused(self):
        for value in ({'vulns':None},{'vulns':{}},{'next_page_token':None},{'next_page_token':23}, {'next_page_token':'\n'}):
            with self.subTest(value=value), self.assertRaises(osv_io.OsvError):
                subject.page_contents(value)

    def test_error_or_unrecognized_pagination_is_not_empty_success(self):
        for value in ({'error': {'code': 503, 'message': 'backend unavailable'}},
                      {'vulns': [], 'nextPageToken': 'page2'}):
            with self.subTest(value=value):
                # 매번 새 시도에서 실제 수집 경로를 시험함.
                self.attempt = self.root / ('bad-page-' + str(len(list(self.root.iterdir()))))
                self.attempt.mkdir()
                self.assert_failure([value], 'INVALID_PAGE')
                self.assertFalse((self.attempt / 'draft-result.json').exists())

    def test_wrong_http_type_status_size_and_truncation_are_refused(self):
        cases=[(Response(b'{}',status=500),'HTTP_STATUS'),(Response(b'{}',kind='text/html'),'CONTENT_TYPE'),
               (Response(b'{}',length=500),'INCOMPLETE_RESPONSE'),
               (Response(b'x'*(osv_io.MAX_PAGE_BYTES+1)),'RESPONSE_TOO_LARGE')]
        for response, code in cases:
            with self.subTest(code=code),patch.object(osv_io,'open_response',return_value=response):
                with self.assertRaises(osv_io.OsvError) as caught:
                    osv_io.receive_page(QUERY)
                self.assertEqual(caught.exception.code,code)

    def test_network_read_break_is_failure(self):
        broken=Response(b'{}')
        broken.read=lambda *args: (_ for _ in ()).throw(IncompleteRead(b'{'))
        with patch.object(osv_io,'open_response',return_value=broken):
            with self.assertRaises(osv_io.OsvError) as caught:
                osv_io.receive_page(QUERY)
        self.assertEqual(caught.exception.code,'NETWORK_ERROR')

    def test_redirect_is_refused_and_post_uses_fixed_api(self):
        with self.assertRaises(osv_io.OsvError):
            osv_io.NoRedirect().redirect_request(None,None,302,'',{},'https://elsewhere.example/')
        with patch.object(osv_io,'build_opener') as factory:
            osv_io.open_response(QUERY)
        request=factory.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url,'https://api.osv.dev/v1/query')
        self.assertEqual(request.method,'POST')
        self.assertEqual(json.loads(request.data),QUERY)

    def test_invalid_cli_target_is_refused_before_output_or_request(self):
        for name, version in (('tar;whoami','6.1.0'),('../tar','6.1.0'),('tar','latest'),('tar','>=6'),('tar','01.2.3'),('tar','1.2.3-01'),('','1.2.3')):
            with self.subTest(name=name, version=version),patch.object(subject,'_worker_command') as command:
                with self.assertRaises(osv_io.OsvError):
                    subject.run_query(name,version,self.root/'unused')
                command.assert_not_called()
        self.assertFalse((self.root/'unused').exists())

    def test_scoped_name_and_exact_prerelease_are_validated_without_shell(self):
        q=subject.make_query('@example/package','1.2.3-beta.2+build.5')
        self.assertEqual(q['package']['name'],'@example/package')
        self.assertEqual(q['version'],'1.2.3-beta.2+build.5')

    def test_changed_raw_notice_or_draft_cannot_be_published(self):
        self.collect([{'vulns':[record()]}])
        for filename in ('page-0001.json','OSV_DATA_NOTICE.txt','draft-result.json'):
            p=self.attempt/filename; old=p.read_bytes();p.write_bytes(b'{}')
            with self.subTest(filename=filename),self.assertRaises(osv_io.OsvError):
                subject.verify_result(QUERY,self.attempt)
            p.write_bytes(old)

    def test_changed_query_or_escape_page_name_cannot_be_verified(self):
        self.collect([{'vulns':[record()]}])
        draft=self.attempt/'draft-result.json';v=json.loads(draft.read_bytes());v['pages'][0]['file']='../outside.json'
        draft.write_bytes(encode(v))
        with self.assertRaises(osv_io.OsvError):
            subject.verify_result(QUERY,self.attempt)

    def test_write_failure_leaves_no_completed_result(self):
        original=osv_io.write_bytes
        def fail_page(path, raw):
            if Path(path).name=='page-0001.json':
                raise OSError('disk full')
            return original(path,raw)
        with patch.object(osv_io,'write_bytes',side_effect=fail_page):
            self.assert_failure([{'vulns':[record()]}],'STORAGE_ERROR')

    def test_query_record_limit_is_failure_not_truncated_success(self):
        with patch.object(subject,'MAX_RECORDS',1):
            self.assert_failure([{'vulns':[record(),record('GHSA-aaaa-bbbb-cccc')]}],'RECORD_LIMIT')

    def test_query_byte_limit_is_failure_not_truncated_success(self):
        with patch.object(subject,'MAX_QUERY_BYTES',1):
            self.assert_failure([{'vulns':[]}],'QUERY_TOO_LARGE')

    def test_supervisor_timeout_kills_worker_and_saves_failure(self):
        with patch.object(subject,'_worker_command',return_value=[sys.executable,'-c','import time; time.sleep(30)']):
            with self.assertRaises(osv_io.OsvError) as caught:
                subject.run_query('tar','6.1.0',self.root/'runs',timeout_seconds=0.1)
        self.assertEqual(caught.exception.code,'TIMEOUT')
        self.assertEqual(len(list((self.root/'runs').glob('*/failure.json'))),1)
        self.assertEqual(list((self.root/'runs').glob('*/result.json')),[])

    def test_worker_exit_zero_without_files_is_failure(self):
        with patch.object(subject,'_worker_command',return_value=[sys.executable,'-c','pass']):
            with self.assertRaises(osv_io.OsvError):
                subject.run_query('tar','6.1.0',self.root/'runs')
        self.assertEqual(list((self.root/'runs').glob('*/result.json')),[])

    def test_parent_publishes_only_verified_result_and_preserves_repeated_runs(self):
        # 외부 서버를 대신하는 새 Python 프로세스도 실제 collect_pages를 실행함.
        worker='''import sys,json,io
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import query_osv,osv_io
class R(io.BytesIO):
 status=200
 headers={'Content-Type':'application/json','Content-Length':'2'}
osv_io.open_response=lambda payload:R(b'{}')
query_osv.collect_pages(query_osv.make_query('tar','6.1.0'),Path(sys.argv[2]),pause_seconds=0)
'''
        def command(query,attempt):
            return [sys.executable,'-c',worker,str(HERE),str(attempt)]
        with patch.object(subject,'_worker_command',side_effect=command):
            first=subject.run_query('tar','6.1.0',self.root/'runs')
            old=first.read_bytes()
            second=subject.run_query('tar','6.1.0',self.root/'runs')
        self.assertNotEqual(first,second)
        self.assertEqual(first.read_bytes(),old)
        result=json.loads(second.read_bytes())
        self.assertEqual(result['status'],'COMPLETE')
        self.assertEqual(result['counts']['uniqueRecords'],0)

    def test_cli_invalid_input_is_nonzero_and_has_no_success_message(self):
        result=subprocess.run([sys.executable,str(HERE/'query_osv.py'),'--package','tar','--version','latest','--output-root',str(self.root/'runs')],capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'OSV_QUERY_COMPLETE',result.stdout)
        self.assertFalse((self.root/'runs').exists())

    def test_symlink_output_is_refused(self):
        link=self.root/'linked'
        try:
            link.symlink_to(self.attempt,target_is_directory=True)
        except OSError:
            self.skipTest('Windows account cannot create symbolic links')
        with self.assertRaises(osv_io.OsvError):
            subject.run_query('tar','6.1.0',link)


if __name__=='__main__':
    unittest.main()
