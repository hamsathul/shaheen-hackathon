"""English and Arabic reason text for every signal code.

Templates use `str.format` fields filled from a finding's `params`. A param
value that is a key of `LABELS` (or a list of such keys) is translated into
the template's language, so signal modules pass stable keys such as
`"homoglyph"` or `["password", "otp"]` instead of display text.
"""

from __future__ import annotations

from typing import Any

from baaz.models import Finding, Reason
from baaz.score import weight_of

TEMPLATES: dict[str, tuple[str, str]] = {
    "OFFICIAL_DOMAIN": (
        "{domain} is an official domain of {brand}.",
        "{domain} نطاق رسمي تابع لـ{brand}.",
    ),
    "GOV_NAMESPACE": (
        "{domain} is in the restricted government namespace .{suffix}.",
        "{domain} ضمن النطاق الحكومي المقيّد .{suffix}.",
    ),
    "URL_SHORTENER": (
        "The link was shortened with {shortener}; Baaz followed it to the real destination.",
        "تم تقصير الرابط عبر {shortener}، وتتبّعه باز حتى وجهته الحقيقية.",
    ),
    "SKIMMER_GATEWAY": (
        "Checkout uses the private payment gateway '{gateway}', seen only on card-skimming fake stores.",
        "صفحة الدفع تستخدم بوابة الدفع الخاصة '{gateway}' التي لم تُرصد إلا في متاجر وهمية تسرق بيانات البطاقات.",
    ),
    "CARD_FORM_NO_PROCESSOR": (
        "Checkout collects card number, expiry and CVV in the site's own form, with no recognised payment processor.",
        "صفحة الدفع تجمع رقم البطاقة وتاريخ الانتهاء ورمز CVV في نموذج الموقع نفسه دون أي مزوّد دفع معروف.",
    ),
    "LOOKALIKE_DOMAIN": (
        "{domain} imitates the official domain {official} ({method}).",
        "النطاق {domain} يقلّد النطاق الرسمي {official} ({method}).",
    ),
    "SENSITIVE_FORM_BRAND": (
        "The page presents itself as {brand} and asks for {fields}, but it is not on an official {brand} domain.",
        "الصفحة تنتحل صفة {brand} وتطلب {fields}، لكنها ليست على نطاق رسمي لـ{brand}.",
    ),
    "NEW_DOMAIN_7D": (
        "The domain was registered only {days} days ago ({created}).",
        "تم تسجيل النطاق قبل {days} أيام فقط ({created}).",
    ),
    "NEW_DOMAIN_30D": (
        "The domain was registered {days} days ago ({created}).",
        "تم تسجيل النطاق قبل {days} يومًا ({created}).",
    ),
    "SHARED_FINGERPRINT": (
        "Shares a {kind} with confirmed fraud cluster {cluster}.",
        "يشترك في {kind} مع شبكة احتيال مؤكدة {cluster}.",
    ),
    "VISUAL_MATCH": (
        "The page looks like the official {brand} site, but the domain is not official.",
        "الصفحة تشبه موقع {brand} الرسمي، لكن النطاق ليس رسميًا.",
    ),
    "BRAND_GEO_DOMAIN": (
        "{domain} combines the brand {brand} with the place name '{place}', a pattern used by fake local stores.",
        "النطاق {domain} يجمع العلامة {brand} مع اسم المكان '{place}'، وهو نمط تستخدمه المتاجر المحلية الوهمية.",
    ),
    "BRAND_IN_DOMAIN": (
        "{domain} contains the brand name {brand} but is not an official {brand} domain.",
        "النطاق {domain} يحتوي اسم العلامة {brand} لكنه ليس نطاقًا رسميًا لها.",
    ),
    "DEEP_DISCOUNTS": (
        "{share}% of sampled products are discounted by more than 70%.",
        "{share}% من المنتجات التي تم فحصها مخفّضة بأكثر من 70%.",
    ),
    "DOORWAY": (
        "The page is an empty doorway that sends visitors on to {target}.",
        "الصفحة بوابة فارغة تحوّل الزوار إلى {target}.",
    ),
    "CLOAKING": (
        "The site shows different content to different visitors ({profiles}).",
        "الموقع يعرض محتوى مختلفًا لزوار مختلفين ({profiles}).",
    ),
    "FORM_OFFSITE_POST": (
        "A form on the page sends what you type to another domain, {target}.",
        "نموذج في الصفحة يرسل ما تكتبه إلى نطاق آخر هو {target}.",
    ),
    "WEAK_GATEWAY": (
        "Checkout uses the generic gateway '{gateway}', which has been seen alongside skimmer gateways.",
        "صفحة الدفع تستخدم البوابة العامة '{gateway}' التي رُصدت إلى جانب بوابات سرقة البطاقات.",
    ),
    "RAW_IP_HOST": (
        "The link points to a bare IP address ({host}) instead of a domain name.",
        "الرابط يشير إلى عنوان IP مباشر ({host}) بدلًا من اسم نطاق.",
    ),
    "AT_IN_URL": (
        "The link contains '@', which hides its real destination.",
        "الرابط يحتوي الرمز '@' الذي يخفي وجهته الحقيقية.",
    ),
    "MANY_SUBDOMAINS": (
        "The address stacks {count} subdomain levels to look legitimate.",
        "العنوان يستخدم {count} مستويات من النطاقات الفرعية ليبدو موثوقًا.",
    ),
    "LONG_URL": (
        "The link is unusually long ({length} characters).",
        "الرابط طويل بشكل غير معتاد ({length} حرفًا).",
    ),
    "NEW_TLS_CERT": (
        "The site's TLS certificate was issued {days} days ago.",
        "تم إصدار شهادة TLS للموقع قبل {days} يومًا.",
    ),
    "FREE_HOSTING": (
        "The site is hosted on the free or site-builder platform {platform}.",
        "الموقع مستضاف على منصة مجانية أو منصة لبناء المواقع ({platform}).",
    ),
    "RISKY_TLD": (
        "The domain ending .{tld} is heavily used for abuse.",
        "امتداد النطاق .{tld} يُستخدم كثيرًا في الاحتيال.",
    ),
    "URGENCY_WORDING": (
        "The page uses urgency or payment-pressure wording: {terms}.",
        "الصفحة تستخدم عبارات استعجال أو ضغط للدفع: {terms}.",
    ),
    "DECEPTIVE_DOMAIN_WORDS": (
        "The domain uses words meant to look official or urgent: {words}.",
        "النطاق يستخدم كلمات توحي بأنه رسمي أو عاجل: {words}.",
    ),
    "TOP_SITE": (
        "{domain} is among the most visited sites on the web (rank {rank}).",
        "{domain} من أكثر المواقع زيارة على الإنترنت (الترتيب {rank}).",
    ),
    "DOMAIN_OLD": (
        "The domain has been registered for {years} years.",
        "النطاق مسجّل منذ {years} سنوات.",
    ),
}

LABELS: dict[str, tuple[str, str]] = {
    "typo": ("one or two characters changed", "تغيير حرف أو حرفين"),
    "homoglyph": ("look-alike characters", "أحرف متشابهة الشكل"),
    "punycode": ("disguised international characters", "أحرف دولية مموّهة"),
    "tld_swap": ("same name, different ending", "الاسم نفسه بامتداد مختلف"),
    "combo": ("brand name with extra words", "اسم العلامة مع كلمات إضافية"),
    "password": ("a password", "كلمة مرور"),
    "card": ("card details", "بيانات بطاقة"),
    "otp": ("a one-time code (OTP)", "رمز تحقق لمرة واحدة (OTP)"),
    "emirates_id": ("an Emirates ID number", "رقم الهوية الإماراتية"),
    "ip": ("hosting IP address", "عنوان IP للاستضافة"),
    "asn": ("hosting network", "شبكة الاستضافة"),
    "ns": ("name server", "خادم أسماء"),
    "registrar": ("registrar", "جهة تسجيل"),
    "favicon": ("site icon", "أيقونة الموقع"),
    "catalogue": ("cloned product catalogue", "كتالوج منتجات منسوخ"),
    "gateway": ("payment gateway", "بوابة دفع"),
    "admin": ("site administrator account", "حساب مدير الموقع"),
    "mobile_ar": ("mobile, Arabic", "جوال، عربي"),
    "desktop": ("desktop", "حاسوب"),
    "crawler": ("search crawler", "زاحف محرك بحث"),
}

_AR_LIST_SEP = " و"


def _localise(value: Any, lang: int) -> str:
    if isinstance(value, (list, tuple)):
        parts = [_localise(v, lang) for v in value]
        return (", " if lang == 0 else _AR_LIST_SEP).join(parts)
    if isinstance(value, str) and value in LABELS:
        return LABELS[value][lang]
    return str(value)


def render(finding: Finding) -> Reason:
    en_tpl, ar_tpl = TEMPLATES[finding.code]
    en = en_tpl.format(**{k: _localise(v, 0) for k, v in finding.params.items()})
    ar = ar_tpl.format(**{k: _localise(v, 1) for k, v in finding.params.items()})
    return Reason(code=finding.code, weight=weight_of(finding), en=en, ar=ar, evidence=finding.evidence)
