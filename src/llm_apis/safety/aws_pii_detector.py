import boto3
from typing import Dict, List

class AWSPIIDetector:
    """PII detection using AWS Comprehend"""
    
    def __init__(self, region_name: str = "us-east-1"):
        self.client = boto3.client('comprehend', region_name=region_name)
    
    def detect_pii(self, text: str, language_code: str = "en") -> Dict:
        """Detect PII using AWS Comprehend"""
        
        response = self.client.detect_pii_entities(
            Text=text,
            LanguageCode=language_code
        )
        
        findings = []
        for entity in response['Entities']:
            findings.append({
                "type": entity['Type'],
                "score": entity['Score'],
                "start": entity['BeginOffset'],
                "end": entity['EndOffset'],
                "text": text[entity['BeginOffset']:entity['EndOffset']]
            })
        
        return {
            "has_pii": len(findings) > 0,
            "findings": findings
        }
    
    def redact_pii(self, text: str, language_code: str = "en") -> str:
        """Redact PII using AWS Comprehend"""
        
        # Detect entities
        response = self.client.detect_pii_entities(
            Text=text,
            LanguageCode=language_code
        )
        
        # Sort by position (reverse to avoid offset issues)
        entities = sorted(
            response['Entities'],
            key=lambda x: x['BeginOffset'],
            reverse=True
        )
        
        # Redact from end to start
        redacted_text = text
        for entity in entities:
            start = entity['BeginOffset']
            end = entity['EndOffset']
            redacted_text = (
                redacted_text[:start] + 
                f"[{entity['Type']}]" + 
                redacted_text[end:]
            )
        
        return redacted_text

# Usage
detector = AWSPIIDetector()
result = detector.detect_pii(text)
redacted = detector.redact_pii(text)