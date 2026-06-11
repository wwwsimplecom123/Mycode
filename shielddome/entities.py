"""Entity labeling sanitizer.

The sanitizer keeps security-relevant meaning while removing direct personal or
business identifiers before content is sent to deep semantic analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any

from .config import INTERNAL_EXECUTIVE_NAMES, INTERNAL_SYSTEM_ALIASES, TRUSTED_ROOT_DOMAINS
from .links import is_trusted_domain, normalize_domain


URL_RE = re.compile(r"https?://[^\s<>'\"\])}]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
LANDLINE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?0\d{2,3}[- ]?\d{7,8}(?!\d)")
NATIONAL_ID_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
BANK_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){15,19}\d(?!\d)")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PERSON_FIELD_RE = re.compile(
    r"(?P<prefix>(?:姓名|联系人|经办人|申请人|发件人|收件人)\s*[:：]\s*)(?P<value>[\u4e00-\u9fff·]{2,8})"
)
PERSON_CONTEXT_RE = re.compile(r"(?P<prefix>联系人)(?P<value>[\u4e00-\u9fff·]{2,4})(?=的|，|,|\s|$)")
PERSON_ACTION_RE = re.compile(
    r"(?P<prefix>(?:请联系|联系|抄送|通知|经办人是|申请人是)\s*)"
    r"(?P<value>[\u4e00-\u9fff·]{2,4})(?=，|,|。|；|;|\s|$)"
)
PERSON_EN_FIELD_RE = re.compile(
    r"(?P<prefix>\b(?:Name|Contact|Applicant|Requester|Sender|Recipient)\s*[:=]?\s+)"
    r"(?P<value>[A-Z][A-Za-z'-]{1,30}(?:\s+[A-Z][A-Za-z'-]{1,30})?)"
)
SECRET_RE = re.compile(
    r"(?P<prefix>(?:验证码|校验码|密码|口令|令牌|password|passcode|otp|token|secret|api[_ -]?key)"
    r"(?:\s*[:：=]\s*|\s+))"
    r"(?P<value>(?!_VALUE\b)[A-Za-z0-9+/_.@-]{4,})",
    re.I,
)
CHINESE_SECRET_RE = re.compile(
    r"(?P<prefix>(?:验证码|校验码|密码|口令|令牌)\s*)(?P<value>(?!_VALUE\b)[A-Za-z0-9+/_.@-]{4,})"
)
AMOUNT_RE = re.compile(
    r"(?:(?:RMB|CNY|USD|\$|¥)\s*(\d+(?:,\d{3})*(?:\.\d+)?)\s*(万元|万|元|块|dollars|usd)?"
    r"|(\d+(?:,\d{3})*(?:\.\d+)?)\s*(万元|万|元|块|dollars|usd))",
    re.I,
)
PROJECT_ID_RE = re.compile(
    r"(?:(?:项目|合同|工单)[编号号:：\s-]*|(?:\bPO|\bPR|\bREQ)[编号号:：\s-]+)([A-Za-z0-9_-]{5,})",
    re.I,
)


@dataclass
class EntityLabel:
    source_type: str
    label: str
    value_hint: str = ""


def _amount_bucket(raw_number: str, unit: str | None) -> str:
    value = float(raw_number.replace(",", ""))
    if unit in {"万元", "万"}:
        value *= 10000
    if value >= 100000:
        return "AMOUNT_RANGE_HIGH"
    if value >= 10000:
        return "AMOUNT_RANGE_MEDIUM"
    return "AMOUNT_RANGE_LOW"


def generalize_entities(text: str, sender: str | None = None) -> dict[str, object]:
    sanitized = text or ""
    labels: list[EntityLabel] = []

    def replace_url(match: re.Match[str]) -> str:
        domain = normalize_domain(match.group(0))
        token = f"[URL_DOMAIN: {domain}]" if domain else "[URL]"
        labels.append(EntityLabel("url", token, domain))
        return token

    sanitized = URL_RE.sub(replace_url, sanitized)

    def replace_email(match: re.Match[str]) -> str:
        domain = normalize_domain(match.group(1))
        label = "INTERNAL_EMAIL_DOMAIN" if is_trusted_domain(domain) else "EXTERNAL_EMAIL_DOMAIN"
        token = f"[{label}: {domain}]"
        labels.append(EntityLabel("email", token, domain))
        return token

    sanitized = EMAIL_RE.sub(replace_email, sanitized)

    def replace_person(match: re.Match[str]) -> str:
        token = "[PERSON_NAME]"
        labels.append(EntityLabel("person", token))
        return f"{match.group('prefix')}{token}"

    sanitized = PERSON_FIELD_RE.sub(replace_person, sanitized)
    sanitized = PERSON_CONTEXT_RE.sub(replace_person, sanitized)
    sanitized = PERSON_ACTION_RE.sub(replace_person, sanitized)
    sanitized = PERSON_EN_FIELD_RE.sub(replace_person, sanitized)

    for name in sorted(INTERNAL_EXECUTIVE_NAMES, key=len, reverse=True):
        if name in sanitized:
            token = "[INTERNAL_EXECUTIVE_NAME_A]"
            sanitized = sanitized.replace(name, token)
            labels.append(EntityLabel("person", token, "internal_executive"))

    for system in sorted(INTERNAL_SYSTEM_ALIASES, key=len, reverse=True):
        if system and system in sanitized:
            token = f"[INTERNAL_SYSTEM: {system}]"
            sanitized = sanitized.replace(system, token)
            labels.append(EntityLabel("system", token, system))

    def replace_amount(match: re.Match[str]) -> str:
        number = match.group(1) or match.group(3)
        unit = match.group(2) or match.group(4)
        token = f"[{_amount_bucket(number, unit)}]"
        labels.append(EntityLabel("amount", token))
        return token

    sanitized = AMOUNT_RE.sub(replace_amount, sanitized)

    if PHONE_RE.search(sanitized):
        sanitized = PHONE_RE.sub("[PHONE_NUMBER]", sanitized)
        labels.append(EntityLabel("phone", "[PHONE_NUMBER]"))

    if LANDLINE_RE.search(sanitized):
        sanitized = LANDLINE_RE.sub("[LANDLINE_NUMBER]", sanitized)
        labels.append(EntityLabel("phone", "[LANDLINE_NUMBER]"))

    if NATIONAL_ID_RE.search(sanitized):
        sanitized = NATIONAL_ID_RE.sub("[NATIONAL_ID]", sanitized)
        labels.append(EntityLabel("national_id", "[NATIONAL_ID]"))

    if BANK_CARD_RE.search(sanitized):
        sanitized = BANK_CARD_RE.sub("[BANK_CARD]", sanitized)
        labels.append(EntityLabel("bank_card", "[BANK_CARD]"))

    if IP_RE.search(sanitized):
        sanitized = IP_RE.sub("[IP_ADDRESS]", sanitized)
        labels.append(EntityLabel("ip_address", "[IP_ADDRESS]"))

    def replace_secret(match: re.Match[str]) -> str:
        token = "[SECRET_VALUE]"
        labels.append(EntityLabel("secret", token))
        return f"{match.group('prefix')}{token}"

    sanitized = SECRET_RE.sub(replace_secret, sanitized)
    sanitized = CHINESE_SECRET_RE.sub(replace_secret, sanitized)

    def replace_project(match: re.Match[str]) -> str:
        prefix = match.group(0).split(match.group(1), 1)[0].strip()
        token = f"{prefix}[BUSINESS_REFERENCE_ID]"
        labels.append(EntityLabel("business_reference", "[BUSINESS_REFERENCE_ID]"))
        return token

    sanitized = PROJECT_ID_RE.sub(replace_project, sanitized)

    sender_domain = normalize_domain(sender)
    if sender_domain:
        sender_label = "INTERNAL_SENDER_DOMAIN" if sender_domain in TRUSTED_ROOT_DOMAINS else "EXTERNAL_SENDER_DOMAIN"
        labels.append(EntityLabel("sender", f"[{sender_label}: {sender_domain}]", sender_domain))

    return {
        "text": sanitized,
        "labels": [asdict(label) for label in labels],
    }


def sanitize_model_value(value: Any) -> Any:
    """Recursively sanitize free-form strings before sending them to an external model."""

    if isinstance(value, str):
        return generalize_entities(value)["text"]
    if isinstance(value, list):
        return [sanitize_model_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_model_value(item) for key, item in value.items()}
    return value
