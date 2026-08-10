from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
import uuid

from .domain import DetectionOutcome
from .evidence_record import EndpointEvidenceRecord
from .local_detection import LocalDetectionService, default_local_detection_service
from .safe_eml_intake import SafeEmlIntakeError, SafeEmlReader


class LocalMailIntakeError(RuntimeError):
    @property
    def code(self):
        return self.args[0] if self.args else "intake_failed"


def _evidence_store():
    from .evidence_store import EvidenceStore
    return EvidenceStore()


def _pending_store():
    from .pending_confirmation_store import PendingConfirmationStore
    return PendingConfirmationStore()


class LocalMailIntakeService:
    def __init__(self, *, reader: SafeEmlReader | None = None,
                 detection_service: LocalDetectionService | None = None,
                 clock: Callable[[], datetime] | None = None,
                 event_id_factory: Callable[[], str] | None = None,
                 evidence_store_factory: Callable[[], object] | None = None,
                 pending_store_factory: Callable[[], object] | None = None):
        self._reader=reader or SafeEmlReader()
        self._clock=clock or (lambda: datetime.now(timezone.utc))
        self._event_id_factory=event_id_factory or (lambda:f"event-{uuid.uuid4()}")
        self._evidence_store_factory=evidence_store_factory or _evidence_store
        self._pending_store_factory=pending_store_factory or _pending_store
        self._pending=None
        self._detection=detection_service or default_local_detection_service(feature_sink=self._save_pending)

    def _save_pending(self,event_id,features,observed_at):
        try:
            if self._pending is None: self._pending=self._pending_store_factory()
            self._pending.cleanup_expired(now=observed_at)
            self._pending.put(event_id,features,created_at=observed_at)
        except Exception: pass

    def detect_file(self,path: str | Path, *, confirmed_by_user: bool) -> DetectionOutcome:
        if confirmed_by_user is not True: raise LocalMailIntakeError("confirmation_required")
        observed_at=self._clock()
        try: observation=self._reader.read_explicit(path,observed_at=observed_at)
        except SafeEmlIntakeError as error: raise LocalMailIntakeError(error.code) from None
        except Exception: raise LocalMailIntakeError("intake_failed") from None
        try:
            outcome=self._detection.detect(observation,local_event_id=self._event_id_factory(),observed_now=observed_at)
        except Exception: raise LocalMailIntakeError("intake_failed") from None
        try:
            store=self._evidence_store_factory()
            try: store.cleanup_expired(now=observed_at)
            except Exception: pass
            store.put(EndpointEvidenceRecord.from_detection_outcome(outcome,detected_at=observed_at,source_kind=observation.source_kind))
        except Exception: pass
        return outcome


__all__=["LocalMailIntakeError","LocalMailIntakeService"]
