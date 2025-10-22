class SafetyPipeline:
    def check_input(self, text: str) -> tuple[bool, str, dict]:
        """Check user input for PII and harmful content"""
        
        # 1. PII Detection (regex)
        EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.search(EMAIL_PATTERN, text):
            text = re.sub(EMAIL_PATTERN, "[EMAIL_REDACTED]", text)
        
        # 2. Content Moderation (OpenAI)
        moderation = client.moderations.create(input=text)
        if moderation.results[0].flagged:
            return False, text, {"reason": "content_policy_violation"}
        
        return True, text, {}
    
    def check_output(self, text: str) -> tuple[bool, dict]:
        """Check AI output before returning to user"""
        
        moderation = client.moderations.create(input=text)
        
        if moderation.results[0].flagged:
            # Log to BigQuery for compliance
            log_to_bigquery(text, moderation.results[0].categories)
            return False, {"action": "blocked"}
        
        return True, {}

if __name__ == "__main__":
    # Usage
    pipeline = SafetyPipeline()
    is_safe, processed_input, meta = pipeline.check_input(user_message)

    if not is_safe:
        print('{"error": "Content policy violation"}, 400')

    # Generate AI response...

    output_safe, output_meta = pipeline.check_output(ai_response)
    if not output_safe:
        print("{'response': 'I cannot provide that information.'}, 200")