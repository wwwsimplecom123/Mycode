"""Default MVP configuration for ShieldDome.

The values here are intentionally small and editable. In production they should
come from SOC-maintained policy storage instead of source code.
"""

TRUSTED_ROOT_DOMAINS = {
    "company.com",
    "comservice.com",
    "oa.company.com",
    "mail.company.com",
    "sso.company.com",
    "invoice.company.com",
}

TRUSTED_IP_RANGES = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
}

TRUSTED_URLS: set[str] = set()

BLACKLISTED_DOMAINS = {
    "evil-login.com",
    "phish.example",
    "fake-oa.example",
    "account-verify.example",
}

RISK_THRESHOLDS = {
    "medium": 35,
    "high": 65,
    "critical": 85,
}

HIGH_RISK_KEYWORDS = {
    "密码",
    "冻结",
    "验证",
    "付款",
    "转账",
    "重置",
    "password",
    "verify",
    "payment",
    "reset",
}

INTERNAL_SYSTEM_ALIASES = {
    "OA",
    "ERP",
    "CRM",
    "SSO",
    "VPN",
    "审批系统",
    "财务系统",
    "发票系统",
    "统一身份认证",
}

INTERNAL_EXECUTIVE_NAMES = {
    "张三",
    "李四",
    "王总",
    "赵总",
    "CEO",
    "CFO",
    "CTO",
}
