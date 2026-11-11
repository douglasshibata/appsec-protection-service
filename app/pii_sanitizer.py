import re
import json
from typing import Any, Dict, Union, List

# Compiled regex patterns for PII detection
EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
CPF_REGEX = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')
CNPJ_REGEX = re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b')
# Credit Card pattern (matches 13-16 digits with optional hyphens/spaces)
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')

# Words to search for in dictionary keys to redact
SENSITIVE_KEYS = {
    'password', 'senha', 'token', 'secret', 'key', 'auth', 'authorization',
    'cvv', 'cvc', 'card_number', 'numero_cartao', 'cookie', 'bearer',
    'cpf', 'email', 'cnpj', 'access_token', 'private_key', 'api_key'
}

def mask_text(text: str) -> str:
    """
    Applies regex masking on a raw string to sanitize standard PII patterns.
    """
    if not isinstance(text, str):
        return str(text)

    # Mask Emails
    text = EMAIL_REGEX.sub("[EMAIL_REDACTED]", text)

    # Mask CPFs
    text = CPF_REGEX.sub("[CPF_REDACTED]", text)

    # Mask CNPJs
    text = CNPJ_REGEX.sub("[CNPJ_REDACTED]", text)

    # Mask Credit Cards (leave last 4 digits visible)
    def mask_card(match):
        card = match.group(0)
        digits_only = re.sub(r'\D', '', card)
        if len(digits_only) >= 13:
            return f"[*CARD_REDACTED_Ending_{digits_only[-4:]}]"
        return "[CARD_REDACTED]"

    text = CREDIT_CARD_REGEX.sub(mask_card, text)

    return text

def sanitize_dict_or_list(data: Union[Dict, List, Any]) -> Any:
    """
    Recursively scans and sanitizes dictionary values and list elements.
    If a dictionary key is in SENSITIVE_KEYS, its value is directly redacted.
    Otherwise, string values are evaluated against the regex patterns.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = k.lower()
            # If the key itself implies sensitive data, redact it
            if any(sensitive in k_lower for sensitive in SENSITIVE_KEYS):
                if isinstance(v, str):
                    # For strings, if they are extremely short, maybe don't fully redact or just do standard redacting
                    sanitized[k] = "[REDACTED]"
                elif isinstance(v, (int, float)):
                    sanitized[k] = "[REDACTED_NUMERIC]"
                else:
                    sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_dict_or_list(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict_or_list(item) for item in data]
    elif isinstance(data, str):
        return mask_text(data)
    else:
        return data

def sanitize_payload(payload: Union[str, Dict, List, Any]) -> str:
    """
    Main sanitizer entrypoint. Returns a sanitized JSON string or plain text.
    """
    if not payload:
        return ""

    if isinstance(payload, (dict, list)):
        sanitized_data = sanitize_dict_or_list(payload)
        try:
            return json.dumps(sanitized_data, ensure_ascii=False)
        except Exception:
            return str(sanitized_data)

    if isinstance(payload, str):
        # Try to parse string as JSON to sanitize structure-aware
        try:
            parsed = json.loads(payload)
            sanitized_data = sanitize_dict_or_list(parsed)
            return json.dumps(sanitized_data, ensure_ascii=False)
        except json.JSONDecodeError:
            # Fallback to pure regex text masking
            return mask_text(payload)

    return str(payload)
