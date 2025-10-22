from google.cloud import dlp_v2

project_id = "static-concept-459810-q7"
dlp_client = dlp_v2.DlpServiceClient()
parent = f"projects/{project_id}"

text = """
Hi, my name is John Smith. You can reach me at john.smith@email.com 
or call (555) 123-4567. My SSN is 123-45-6789 and I live at 
123 Main Street, Springfield, IL 62701. My credit card is 
4532-1234-5678-9010. I was born on January 15, 1985.
"""

# Test which info types are available
info_types_to_test = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER", 
    "CREDIT_CARD_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
    "PERSON_NAME",
]

for info_type in info_types_to_test:
    try:
        inspect_config = {
            "info_types": [{"name": info_type}],
            "min_likelihood": "POSSIBLE",
        }
        
        response = dlp_client.inspect_content(
            request={
                "parent": parent,
                "inspect_config": inspect_config,
                "item": {"value": text},
            }
        )
        
        found = len(response.result.findings)
        print(f"✓ {info_type}: {found} findings")
        
    except Exception as e:
        print(f"✗ {info_type}: {str(e)[:80]}")
