from datetime import datetime, timezone
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ENDPOINT_ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ENDPOINT_ROOT/"src"))

from shielddome_endpoint.local_mail_intake import LocalMailIntakeError, LocalMailIntakeService
from shielddome_endpoint.local_detection import LocalDetectionService

NOW=datetime(2026,8,10,10,0,tzinfo=timezone.utc)

class Store:
    def __init__(self, fail=False): self.values=[]; self.fail=fail
    def cleanup_expired(self, **kwargs):
        if self.fail: raise RuntimeError("C:\\private\\mail.eml secret")
    def put(self,*values,**kwargs):
        if self.fail: raise RuntimeError("private body")
        self.values.append((values,kwargs))

class LocalMailIntakeTests(unittest.TestCase):
    def test_requires_explicit_confirmation_without_reading(self):
        with self.assertRaises(LocalMailIntakeError) as caught:
            LocalMailIntakeService().detect_file("C:\\private.eml", confirmed_by_user=False)
        self.assertEqual("confirmation_required",caught.exception.code)
        self.assertEqual("confirmation_required",str(caught.exception))

    def test_detects_and_saves_evidence_and_pending_context(self):
        evidence=Store(); pending=Store()
        with TemporaryDirectory() as root:
            path=Path(root)/"synthetic.eml"; path.write_text("Subject: urgent password\n\nverify password",encoding="utf-8")
            outcome=LocalMailIntakeService(clock=lambda:NOW,event_id_factory=lambda:"event-local-eml",evidence_store_factory=lambda:evidence,pending_store_factory=lambda:pending).detect_file(path,confirmed_by_user=True)
        self.assertEqual("event-local-eml",outcome.local_event_id)
        self.assertEqual(1,len(evidence.values)); self.assertEqual(1,len(pending.values))
        self.assertEqual("manual_local",evidence.values[0][0][0].source_kind)

    def test_store_failures_do_not_block_or_change_detection(self):
        with TemporaryDirectory() as root:
            path=Path(root)/"synthetic.eml"; path.write_text("Subject: routine\n\nhello",encoding="utf-8")
            baseline=LocalMailIntakeService(clock=lambda:NOW,event_id_factory=lambda:"event-stable",evidence_store_factory=lambda:Store(),pending_store_factory=lambda:Store()).detect_file(path,confirmed_by_user=True)
            failed=LocalMailIntakeService(clock=lambda:NOW,event_id_factory=lambda:"event-stable",evidence_store_factory=lambda:Store(True),pending_store_factory=lambda:Store(True)).detect_file(path,confirmed_by_user=True)
        self.assertEqual(baseline,failed)
        self.assertNotIn("private body",repr(failed))
        self.assertNotIn("private\\mail.eml",repr(failed))

    def test_reader_errors_remain_stable_and_private(self):
        with self.assertRaises(LocalMailIntakeError) as caught:
            LocalMailIntakeService().detect_file("C:\\secret-person\\mail.txt",confirmed_by_user=True)
        self.assertEqual("unsupported_file",caught.exception.code)
        self.assertNotIn("secret-person",repr(caught.exception))

if __name__=='__main__': unittest.main()
