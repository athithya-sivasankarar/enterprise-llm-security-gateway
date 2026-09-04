import logging
from typing import List, Optional
from pydantic import BaseModel, Field
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

logger = logging.getLogger(__name__)


class DLPResult(BaseModel):
    """
    Structured result returned by the DLP inspection engine.
    """
    sanitized_prompt: str
    pii_detected: bool
    detected_entities: List[str] = Field(default_factory=list)
    risk_score: int
    action: str  # ALLOW, SANITIZE, BLOCK


# Risk score weights by entity type
ENTITY_RISK_WEIGHTS = {
    # High sensitivity entities
    "US_SSN": 40,
    "CREDIT_CARD": 40,
    "API_KEY": 50,
    "AWS_ACCESS_KEY": 50,
    "CRYPTO": 30,
    "US_BANK_NUMBER": 35,
    "US_PASSPORT": 35,
    "US_DRIVER_LICENSE": 30,
    # Standard PII entities
    "EMAIL_ADDRESS": 20,
    "PHONE_NUMBER": 20,
    "PERSON": 15,
    "IP_ADDRESS": 15,
    "LOCATION": 10,
    "DATE_TIME": 5,
    "NRP": 10,
    "URL": 10,
}

TARGET_PII_ENTITIES = list(ENTITY_RISK_WEIGHTS.keys())

DEFAULT_ENTITY_WEIGHT = 15

# Global singletons for analyzer and anonymizer
_analyzer: Optional[AnalyzerEngine] = None
_anonymizer: Optional[AnonymizerEngine] = None


def _init_analyzer() -> AnalyzerEngine:
    """
    Initialize Presidio AnalyzerEngine with en_core_web_sm and custom enterprise recognizers.
    """
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
    })
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

    # Custom API Key & Secret Recognizer
    api_key_patterns = [
        Pattern(name="openai_api_key", regex=r"\bsk-[a-zA-Z0-9_-]{20,}\b", score=0.95),
        Pattern(name="aws_access_key", regex=r"\bAKIA[0-9A-Z]{16}\b", score=0.95),
        Pattern(name="bearer_token", regex=r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b", score=0.90),
        Pattern(
            name="generic_secret_key",
            regex=r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?\b",
            score=0.85
        ),
    ]
    api_key_recognizer = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=api_key_patterns,
        name="EnterpriseApiKeyRecognizer"
    )
    analyzer.registry.add_recognizer(api_key_recognizer)

    # General US SSN fallback format recognizer (XXX-XX-XXXX)
    ssn_fallback_pattern = Pattern(
        name="generic_ssn_format",
        regex=r"\b\d{3}-\d{2}-\d{4}\b",
        score=0.80
    )
    ssn_recognizer = PatternRecognizer(
        supported_entity="US_SSN",
        patterns=[ssn_fallback_pattern],
        context=["ssn", "social", "security", "taxpayer", "id"],
        name="GenericSSNRecognizer"
    )
    analyzer.registry.add_recognizer(ssn_recognizer)

    return analyzer


def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        _analyzer = _init_analyzer()
    return _analyzer


def get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


def calculate_risk_score(detected_entities: List[str]) -> int:
    """
    Calculate a risk score (0-100) based on detected entity types.
    """
    if not detected_entities:
        return 0

    total_score = sum(
        ENTITY_RISK_WEIGHTS.get(entity, DEFAULT_ENTITY_WEIGHT)
        for entity in detected_entities
    )
    return min(100, total_score)


def inspect_prompt(prompt: str, block_threshold: int = 100) -> DLPResult:
    """
    Inspect a prompt for PII and enterprise-sensitive entities.
    Returns structured DLPResult with sanitized text, detected entities, risk score, and action.
    Never logs or persists raw sensitive values.
    """
    if not prompt or not prompt.strip():
        return DLPResult(
            sanitized_prompt=prompt,
            pii_detected=False,
            detected_entities=[],
            risk_score=0,
            action="ALLOW"
        )

    analyzer = get_analyzer()
    anonymizer = get_anonymizer()

    # Analyze prompt for targeted PII entities
    results = analyzer.analyze(
        text=prompt,
        language="en",
        entities=TARGET_PII_ENTITIES,
        score_threshold=0.35
    )

    if not results:
        return DLPResult(
            sanitized_prompt=prompt,
            pii_detected=False,
            detected_entities=[],
            risk_score=0,
            action="ALLOW"
        )

    # Anonymize/sanitize prompt
    anonymized_result = anonymizer.anonymize(text=prompt, analyzer_results=results)
    sanitized_prompt = anonymized_result.text

    # Extract distinct detected entity types without storing raw sensitive values
    detected_entities = sorted(list(set(r.entity_type for r in results)))
    
    # Filter out secondary/overlapping URL if EMAIL_ADDRESS was already detected
    if "EMAIL_ADDRESS" in detected_entities and "URL" in detected_entities:
        detected_entities.remove("URL")

    risk_score = calculate_risk_score(detected_entities)

    # Determine action (PII is sanitized; block only if threshold strictly exceeded)
    if risk_score > block_threshold:
        action = "BLOCK"
    else:
        action = "SANITIZE"

    logger.info(
        "DLP inspection complete: pii_detected=%s, entity_count=%d, risk_score=%d, action=%s",
        True,
        len(detected_entities),
        risk_score,
        action
    )

    return DLPResult(
        sanitized_prompt=sanitized_prompt,
        pii_detected=True,
        detected_entities=detected_entities,
        risk_score=risk_score,
        action=action
    )
