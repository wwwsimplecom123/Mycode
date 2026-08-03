from shielddome_endpoint.domain import FeatureVector, ModelAssessment
from shielddome_endpoint.inference import InferenceContext


class FakeModelAdapter:
    def __init__(
        self,
        assessment: ModelAssessment | None = None,
        error: Exception | None = None,
    ) -> None:
        self.assessment = assessment
        self.error = error
        self.calls: list[tuple[FeatureVector, InferenceContext]] = []

    def infer(
        self,
        feature_vector: FeatureVector,
        context: InferenceContext,
    ) -> ModelAssessment:
        self.calls.append((feature_vector, context))
        if self.error is not None:
            raise self.error
        if self.assessment is None:
            raise AssertionError("fake_assessment_not_configured")
        return self.assessment
