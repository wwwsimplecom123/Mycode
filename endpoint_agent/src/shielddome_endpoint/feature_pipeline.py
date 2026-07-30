from email.utils import parseaddr
import hashlib
from ipaddress import ip_address
import math
import re
import unicodedata

from .domain import FeatureVector, MailObservation


TEXT_HASH_DIMENSION = 64
FEATURE_TEXT_MAX_CHARACTERS = 8192
FEATURE_URL_MAX_ITEMS = 256
FEATURE_ATTACHMENT_MAX_ITEMS = 256
FEATURE_AUTHENTICATION_MAX_ITEMS = 64
TEXT_HASH_MAX_CHARACTERS = FEATURE_TEXT_MAX_CHARACTERS

NUMERIC_FEATURE_NAMES = (
    "subject_present",
    "subject_length",
    "body_present",
    "body_length",
    "sender_present",
    "sender_length",
    "reply_to_present",
    "reply_to_length",
    "sender_reply_domain_match",
    "auth_spf_present",
    "auth_dkim_present",
    "auth_dmarc_present",
    "url_count",
    "https_url_count",
    "ip_literal_url_count",
    "suspicious_port_url_count",
    "unique_domain_count",
    "punycode_domain_count",
    "unicode_domain_count",
    "attachment_count",
    "double_extension_count",
    "dangerous_extension_count",
    "intent_credential_count",
    "intent_payment_count",
    "intent_urgency_count",
    "intent_impersonation_count",
)
CATEGORICAL_FEATURE_NAMES = (
    "sender_domain_state",
    "reply_to_domain_state",
    "auth_spf_value",
    "auth_dkim_value",
    "auth_dmarc_value",
    "language",
)
DANGEROUS_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cmd",
        ".com",
        ".dll",
        ".exe",
        ".hta",
        ".img",
        ".iso",
        ".js",
        ".jse",
        ".lnk",
        ".msi",
        ".ps1",
        ".scr",
        ".vbe",
        ".vbs",
    }
)
SUSPICIOUS_PORTS = frozenset({21, 22, 23, 25, 445, 3389, 4444, 8080, 8443})
KNOWN_AUTH_VALUES = frozenset(
    {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
)
INTENT_TERMS = {
    "credential": (
        "password",
        "passcode",
        "login",
        "verify identity",
        "credential",
        "密码",
        "口令",
        "登录",
        "验证身份",
        "凭据",
    ),
    "payment": (
        "payment",
        "invoice",
        "bank",
        "wire",
        "refund",
        "付款",
        "发票",
        "银行",
        "转账",
        "退款",
    ),
    "urgency": (
        "urgent",
        "immediately",
        "action required",
        "deadline",
        "紧急",
        "立即",
        "尽快",
        "截止",
    ),
    "impersonation": (
        "ceo",
        "boss",
        "executive",
        "it support",
        "finance department",
        "领导",
        "老板",
        "高管",
        "技术支持",
        "财务",
    ),
}


def _normalized_hash_text(observation: MailObservation) -> str:
    combined = f"{observation.subject}\n{observation.sanitized_body_text}"[
        :FEATURE_TEXT_MAX_CHARACTERS
    ]
    normalized = unicodedata.normalize("NFKC", combined).casefold()
    return re.sub(r"\s+", " ", normalized).strip()[:FEATURE_TEXT_MAX_CHARACTERS]


def _hash_text(text: str) -> tuple[float, ...]:
    values = [0.0] * TEXT_HASH_DIMENSION
    for width in (2, 3, 4):
        for offset in range(max(0, len(text) - width + 1)):
            digest = hashlib.sha256(text[offset : offset + width].encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:8], "big") % TEXT_HASH_DIMENSION
            sign = 1.0 if digest[8] & 1 == 0 else -1.0
            values[bucket] += sign

    norm = math.sqrt(sum(value * value for value in values))
    if norm:
        values = [value / norm for value in values]
    return tuple(values)


def _domain(value: str | None) -> str | None:
    address = parseaddr(value or "")[1]
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().rstrip(".").casefold()
    return domain or None


def _language(observation: MailObservation, bounded_text: str) -> str:
    hint = (observation.language_hint or "").strip().casefold()
    if hint in {"zh", "chinese", "zh-cn"}:
        return "zh"
    if hint in {"en", "english"}:
        return "en"
    if hint in {"mixed", "zh-en", "en-zh"}:
        return "mixed"
    has_chinese = re.search(r"[\u4e00-\u9fff]", bounded_text) is not None
    has_english = re.search(r"[A-Za-z]", bounded_text) is not None
    if has_chinese and has_english:
        return "mixed"
    if has_chinese:
        return "zh"
    if has_english:
        return "en"
    return "other"


def _url_authority(link: str) -> tuple[str | None, int | None, str]:
    scheme, separator, remainder = link.strip().partition("://")
    if not separator:
        remainder = scheme
        scheme = ""
    authority = re.split(r"[/\\?#]", remainder, maxsplit=1)[0]
    authority = authority.rsplit("@", 1)[-1]
    host = authority
    port: int | None = None
    if authority.startswith("[") and "]" in authority:
        closing = authority.index("]")
        host = authority[1:closing]
        suffix = authority[closing + 1 :]
        if suffix.startswith(":") and suffix[1:].isdigit():
            port = int(suffix[1:])
    elif authority.count(":") == 1:
        candidate_host, candidate_port = authority.rsplit(":", 1)
        if candidate_port.isdigit():
            host = candidate_host
            port = int(candidate_port)
    host = host.strip().rstrip(".").casefold()
    return (host or None, port, scheme.casefold())


def _is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def _attachment_counts(names: tuple[str, ...]) -> tuple[int, int]:
    double_extensions = 0
    dangerous_extensions = 0
    for name in names:
        basename = re.split(r"[/\\]", name)[-1].casefold()
        suffixes = tuple(re.findall(r"\.[^.\s]+", basename))
        if len(suffixes) >= 2:
            double_extensions += 1
        if suffixes and suffixes[-1] in DANGEROUS_EXTENSIONS:
            dangerous_extensions += 1
    return double_extensions, dangerous_extensions


def _intent_count(text: str, category: str) -> float:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return float(sum(normalized.count(term) for term in INTENT_TERMS[category]))


def _auth_value(authentication: dict[str, str], name: str) -> str:
    if name not in authentication:
        return "missing"
    value = authentication[name].split(None, 1)[0]
    return value if value in KNOWN_AUTH_VALUES else "other"


class FeaturePipeline:
    def transform(self, observation: MailObservation) -> FeatureVector:
        bounded_text = _normalized_hash_text(observation)
        bounded_links = observation.normalized_links[:FEATURE_URL_MAX_ITEMS]
        authentication = {
            name.strip().casefold(): value.strip().casefold()
            for name, value in observation.authentication_observations[
                :FEATURE_AUTHENTICATION_MAX_ITEMS
            ]
        }
        sender_domain = _domain(observation.sender)
        reply_to_domain = _domain(observation.reply_to)
        attachment_names = tuple(
            value
            for name, value in observation.attachment_metadata[
                :FEATURE_ATTACHMENT_MAX_ITEMS
            ]
            if name.strip().casefold() in {"name", "filename"}
        )
        url_authorities = tuple(
            _url_authority(link) for link in bounded_links
        )
        domain_hosts = {
            host
            for host, _, _ in url_authorities
            if host is not None and not _is_ip_literal(host)
        }
        double_extension_count, dangerous_extension_count = _attachment_counts(
            attachment_names
        )
        intent_text = bounded_text

        numeric_values = {
            "subject_present": float(bool(observation.subject)),
            "subject_length": float(
                min(len(observation.subject), FEATURE_TEXT_MAX_CHARACTERS)
            ),
            "body_present": float(bool(observation.sanitized_body_text)),
            "body_length": float(
                min(
                    len(observation.sanitized_body_text),
                    FEATURE_TEXT_MAX_CHARACTERS,
                )
            ),
            "sender_present": float(bool(observation.sender)),
            "sender_length": float(len(observation.sender)),
            "reply_to_present": float(bool(observation.reply_to)),
            "reply_to_length": float(len(observation.reply_to or "")),
            "sender_reply_domain_match": float(
                sender_domain is not None and sender_domain == reply_to_domain
            ),
            "auth_spf_present": float("spf" in authentication),
            "auth_dkim_present": float("dkim" in authentication),
            "auth_dmarc_present": float("dmarc" in authentication),
            "url_count": float(len(bounded_links)),
            "https_url_count": float(
                sum(scheme == "https" for _, _, scheme in url_authorities)
            ),
            "ip_literal_url_count": float(
                sum(host is not None and _is_ip_literal(host) for host, _, _ in url_authorities)
            ),
            "suspicious_port_url_count": float(
                sum(port in SUSPICIOUS_PORTS for _, port, _ in url_authorities)
            ),
            "unique_domain_count": float(len(domain_hosts)),
            "punycode_domain_count": float(
                sum(any(label.startswith("xn--") for label in host.split(".")) for host in domain_hosts)
            ),
            "unicode_domain_count": float(
                sum(any(ord(character) > 127 for character in host) for host in domain_hosts)
            ),
            "attachment_count": float(len(attachment_names)),
            "double_extension_count": float(double_extension_count),
            "dangerous_extension_count": float(dangerous_extension_count),
            "intent_credential_count": _intent_count(intent_text, "credential"),
            "intent_payment_count": _intent_count(intent_text, "payment"),
            "intent_urgency_count": _intent_count(intent_text, "urgency"),
            "intent_impersonation_count": _intent_count(intent_text, "impersonation"),
        }
        categorical_values = {
            "sender_domain_state": "present" if sender_domain else "missing",
            "reply_to_domain_state": "present" if reply_to_domain else "missing",
            "auth_spf_value": _auth_value(authentication, "spf"),
            "auth_dkim_value": _auth_value(authentication, "dkim"),
            "auth_dmarc_value": _auth_value(authentication, "dmarc"),
            "language": _language(observation, bounded_text),
        }
        missing_value_mask = tuple(
            name
            for name, missing in (
                ("subject", not observation.subject),
                ("body", not observation.sanitized_body_text),
                ("sender", not observation.sender),
                ("reply_to", not observation.reply_to),
                ("auth_spf", "spf" not in authentication),
                ("auth_dkim", "dkim" not in authentication),
                ("auth_dmarc", "dmarc" not in authentication),
                ("language_hint", not observation.language_hint),
            )
            if missing
        )

        return FeatureVector(
            numeric_features=tuple(
                (name, numeric_values[name]) for name in NUMERIC_FEATURE_NAMES
            ),
            categorical_features=tuple(
                (name, categorical_values[name]) for name in CATEGORICAL_FEATURE_NAMES
            ),
            text_input=None,
            text_vector=_hash_text(bounded_text),
            missing_value_mask=missing_value_mask,
        )
