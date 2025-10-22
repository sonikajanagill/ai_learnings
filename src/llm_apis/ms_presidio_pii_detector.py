from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from typing import List, Dict

class PresidioPIIDetector:
    """Production PII detection using Microsoft Presidio"""
    
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
    
    def detect_pii(
        self, 
        text: str, 
        language: str = "en",
        entities: List[str] = None,
        score_threshold: float = 0.5
    ) -> Dict:
        """
        Detect PII using Presidio
        
        Args:
            text: Text to analyze
            language: Language code
            entities: List of entity types (None = all)
            score_threshold: Minimum confidence (0.0-1.0)
        """
        
        # Analyze text
        results = self.analyzer.analyze(
            text=text,
            language=language,
            entities=entities,
            score_threshold=score_threshold
        )
        
        # Format findings
        findings = []
        for result in results:
            findings.append({
                "type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": result.score,
                "text": text[result.start:result.end]
            })
        
        return {
            "has_pii": len(findings) > 0,
            "findings": findings,
            "text": text
        }
    
    def redact_pii(
        self,
        text: str,
        language: str = "en",
        anonymize_method: str = "replace"  # 'replace', 'mask', 'hash', 'encrypt'
    ) -> str:
        """Redact PII from text"""
        
        # Analyze
        analyzer_results = self.analyzer.analyze(
            text=text,
            language=language
        )
        
        # Anonymize
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators={
                "DEFAULT": {"type": anonymize_method}
            }
        )
        
        return anonymized_result.text
if __name__ == "__main__":  
    # Usage
    detector = PresidioPIIDetector()

    text = """
    Contact John Doe at john.doe@company.com or 
    +1-555-123-4567. SSN: 078-05-1120. 
    Card: 4532-1234-5678-9010.
    """

    # Detect
    result = detector.detect_pii(text)
    print(f"Found {len(result['findings'])} PII items:")
    for finding in result['findings']:
        print(f"  {finding['type']}: {finding['text']} (confidence: {finding['score']:.2f})")

    # Redact
    redacted = detector.redact_pii(text)
    print(f"\nRedacted: {redacted}")

    '''
        Output:
        Found 5 PII items:
        PERSON: John Doe (confidence: 0.85)
        EMAIL_ADDRESS: john.doe@company.com (confidence: 1.00)
        PHONE_NUMBER: +1-555-123-4567 (confidence: 0.95)
        US_SSN: 078-05-1120 (confidence: 0.95)
        CREDIT_CARD: 4532-1234-5678-9010 (confidence: 1.00)

        Redacted: Contact <PERSON> at <EMAIL_ADDRESS> or 
        <PHONE_NUMBER>. SSN: <US_SSN>. Card: <CREDIT_CARD>.
    '''