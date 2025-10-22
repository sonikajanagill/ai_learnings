# 1. Code Generation (Deterministic)
CODE_PARAMS = {
    "temperature": 0.0, # OR 0.1
    "top_p": 0.1,
    "frequency_penalty": 0.0,
    "max_tokens": 2000,
    "stop": ["\n\n", "```"]
}

# 2. Documentation (Consistent but Natural)
DOCS_PARAMS = {
    "temperature": 0.3,
    "top_p": 0.7,
    "frequency_penalty": 0.3,  # Reduce repetition
    "max_tokens": 1000
}

# 3. Creative Marketing (High Variance)
CREATIVE_PARAMS = {
    "temperature": 1.0,
    "top_p": 0.95,
    "frequency_penalty": 0.8,  # Force variety
    "max_tokens": 500
}

# 4. Data Extraction (Ultra Consistent)
EXTRACT_PARAMS = {
    "temperature": 0.0,
    "top_p": 0.05,
    "max_tokens": 500
}