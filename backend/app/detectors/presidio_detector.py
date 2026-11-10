from __future__ import annotations
import threading
from ..models import Finding
from .base import Detector


class PresidioDetector(Detector):
    """NLP-based detection: Presidio + spaCy NER. Imports are lazy so the
    rule-only mode works even if spaCy/Presidio are not installed."""
    name = "presidio"

    def __init__(self, entities=("PERSON", "LOCATION"),
                 model: str = "en_core_web_sm", threshold: float = 0.4):
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_engine = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        }).create_engine()
        self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine,
                                        supported_languages=["en"])
        self._lock = threading.Lock()   # spaCy pipelines are not guaranteed thread-safe
        self.entities = list(entities)
        self.threshold = threshold

    def detect(self, text: str) -> list[Finding]:
        with self._lock:
            results = self._analyzer.analyze(text=text, language="en",
                                             entities=self.entities,
                                             score_threshold=self.threshold)
        return [Finding(r.entity_type, r.start, r.end, float(r.score),
                        "presidio") for r in results]
