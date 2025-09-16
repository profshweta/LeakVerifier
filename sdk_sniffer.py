from mitmproxy import http, ctx
import json
import re
import gzip
from datetime import datetime

LOG_FILE = "sdk_logs.json"

def wrap_keywords(keywords: str, value_regex: str) -> str:
    return rf'(?i)(?:"?\b(?:{keywords})\b"?\s*["\'_\-:= ]+\s*"?({value_regex})"?)'


patterns = {
    "phone": wrap_keywords(r'phone|mobile|contact|tel|cell(?:[_\s-]?number|num|no)?', r'\+?(?:\d[\s\- ]?){10,15}'),
    "otp": wrap_keywords(
    r'otp|verification[\s\-]?code|login[\s\-]?code|auth[\s\-]?code',
    r'\d{4,8}'
),
    "pincode": wrap_keywords(r'pincode|postal code|zip', r'\d{6}'),
    "address": wrap_keywords(
    r'address|addr|home address|street',
    r'(?=.*[A-Za-z])[A-Za-z0-9 ,.\-\/]{6,}'
),

    "city": wrap_keywords(
    r'city|town|district',
    r'(?=.*[A-Za-z])[A-Za-z0-9 ]{3,}'
),

    "email": wrap_keywords(r'email|e-mail|user email', r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "number": wrap_keywords(r'id number|account number|aadhaar|pan|voter id', r'[\dA-Za-z\-]{6,}'),
    "dob": wrap_keywords(r'dob|date of birth|birth date|birthday', r'\d{1,2}[-/ ]?(?:\d{1,2}|[A-Za-z]+)[-/ ]?\d{2,4}'),
    "gender": wrap_keywords(r'gender|sex|user_gender|profile_gender', r'\b(?:male|female|other|m|f|trans|nonbinary)\b'),
    "android_id": wrap_keywords(
    r'\b(?:android_id|aid|a_id|androidid|androidId|aId)\b',
    r'[0-9a-fA-F]{16}'
),

    "name": wrap_keywords(
    r'\b(?:user[_\-]?name|account[_\-]?name|profile[_\-]?name|customer[_\-]?name|full[_\-]?name|first[_\-]?name)\b',
    r'\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){0,2}\b'
),
    "accelerometer": wrap_keywords(
    r'accelerometer[_\-]?[xyz]',
    r'-?\d+(?:\.\d+)?(?:E[-+]?\d+)?'
),
    "password": wrap_keywords(
        r'password|pass|passwd|pwd|user_password',
        r'[A-Za-z0-9@#$%^&+=!?.*_-]{4,}'
    ),
    "location": rf'(?i)(?<![a-z0-9])location(?![a-z0-9])\s*["\'_\-:=,]+\s*"?([A-Za-z][A-Za-z ]{{2,30}})"?'

}

JUNK_WORDS = {
    "whatsapp", "name" , "offer", "no offer", "add to cart", "cart", "button",
    "screen", "page", "activity", "fragment", "event", "register",
    "variation", "control", "experiment", "test",
    "true", "false", "yes", "no", "null", "undefined",
    "userid", "id", "none", "wallet", "handholding", "top", "loyal", "ceo"
}

ALLOWED_NAME_KEYS = {
    "user_name", "account_name", "profile_name", "customer_name", "full_name", "name"
}

def check_luhn(number: str) -> bool:
    n_digits = len(number)
    n_sum = 0
    is_second = False
    for i in range(n_digits - 1, -1, -1):
        d = ord(number[i]) - ord('0')
        if is_second:
            d *= 2
        n_sum += d // 10
        n_sum += d % 10
        is_second = not is_second
    return n_sum % 10 == 0

def get_card_type(card_number):
    card_types = {
        "Visa": r"(?<!\.)\b4[0-9]{12}(?:[0-9]{3})?\b(?!\.)",
        "MasterCard": r"(?<!\.)\b5[1-5][0-9]{14}\b(?!\.)",
        "American Express": r"(?<!\.)\b3[47][0-9]{13}\b(?!\.)",
        "Discover": r"(?<!\.)\b6(?:011|5[0-9]{2})[0-9]{12}\b(?!\.)",
        "JCB": r"(?<!\.)\b(?:2131|1800|35\d{3})\d{11}\b(?!\.)",
        "Diners Club": r"(?<!\.)\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b(?!\.)",
        "Maestro": r"(?<!\.)\b(5018|5020|5038|56|57|58|6304|6759|676[1-3])\d{8,15}\b(?!\.)",
        "Verve": r"(?<!\.)\b(506[01]|507[89]|6500)\d{12,15}\b(?!\.)"
    }

    for card_type, pattern in card_types.items():
        if re.match(pattern, card_number):
            return card_type
    return "Unknown"
def detect_imei_from_keyval(key, val_str):
    imei_regex = r'\b\d{15}\b'
    key_match = re.search(r'(?i)\b(imei|imeei|imeid|imei[_\-\.]?(md5|sha1|hash))\b', key)
    valid = set()
    invalid = set()
    if key_match:
        candidates = re.findall(imei_regex, val_str)
        for num in candidates:
            if check_luhn(num):
                valid.add(num)
            else:
                invalid.add(num)
    return valid, invalid
class SDKSniffer:
    def __init__(self):
        self.sdk_data = []
        self.domain_counter = {}

    def load(self, loader):
        self.clear_log()

    def done(self):
        self.clear_log()

    def clear_log(self):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
        self.sdk_data = []
        ctx.log.info(" Cleared SDK logs.")



    def request(self, flow: http.HTTPFlow):
        domain = flow.request.host
        self.domain_counter[domain] = self.domain_counter.get(domain, 0) + 1
        ctx.log.info(f"[REQ] {flow.request.method} {flow.request.pretty_url}")

        data_sent = {}
        content_type = flow.request.headers.get("content-type", "").lower()


        try:
            raw_bytes = flow.request.get_content()
            content_encoding = flow.request.headers.get("content-encoding", "").lower()

            if "gzip" in content_encoding:
                if raw_bytes[:2] == b'\x1f\x8b':
                    body_text = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
                    ctx.log.info(" → Decompressed GZIP body")
                else:
                    ctx.log.warn(" → GZIP header present but body is not gzipped. Treating as plain text.")
                    body_text = raw_bytes.decode("utf-8", errors="replace")
            else:
                body_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            ctx.log.warn(f"Body decode error: {e}")
            body_text = ""

        if flow.request.method in ("POST", "PUT") and body_text.strip():
            try:
                if "json" in content_type:
                    if not body_text.strip():
                        ctx.log.info(" → Empty body, skipping JSON parse")
                        return
                    ctx.log.info(" → Parsing as JSON")
                    try:
                        parsed, _ = json.JSONDecoder().raw_decode(body_text)
                    except json.JSONDecodeError as e:
                        ctx.log.warn(f"Body raw_decode error: {e}")
                        parsed = {"raw_body": body_text}
                    data_sent.update(self.detect_pii(parsed))
                elif "x-www-form-urlencoded" in content_type:
                    ctx.log.info(" → Parsing as x-www-form-urlencoded")
                    form_dict = dict(flow.request.urlencoded_form)
                    data_sent.update(self.detect_pii(form_dict))
                elif "multipart" in content_type:
                    ctx.log.info(" → Parsing as multipart")
                    form_dict = dict(flow.request.multipart_form.items())
                    data_sent.update(self.detect_pii(form_dict))
                else:
                    ctx.log.info(" → Treating as raw body")
                    data_sent.update(self.detect_pii({"raw_body": body_text}))
            except Exception as e:
                ctx.log.warn(f"Body parse error: {e}")
                data_sent.update(self.detect_pii({"raw_body": body_text}))

        if not data_sent:
            ctx.log.info(" → No PII found in this request")
            return

        clean_data = {k: list(v) for k, v in data_sent.items()}

        app_info = {
            "App Domain": domain,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Data Sent": clean_data
        }

        ctx.log.info(f" [+] PII Detected: {clean_data}")
        self.sdk_data.append(app_info)
        self.write_log()

    def detect_pii(self, parsed, parent_key=""):
        result = {}

        if isinstance(parsed, dict):
            for key, value in parsed.items():
                full_key = f"{parent_key}.{key}" if parent_key else key
                key_lower = key.lower()

                if key_lower == "name":

                    if isinstance(value, list):
                        if all(str(v).strip().lower() in JUNK_WORDS for v in value):
                            continue

                    elif isinstance(value, str):
                        if value.strip().lower() in JUNK_WORDS:
                            continue

                if isinstance(value, (dict, list)):
                    nested_result = self.detect_pii(value, full_key)
                    for k, v in nested_result.items():
                        result.setdefault(k, set()).update(v)
                    continue

                val_str = str(value).strip()
                if not val_str or val_str.lower() in JUNK_WORDS:
                    continue

                if val_str.startswith("{") and val_str.endswith("}"):
                    try:
                        nested_json = json.loads(val_str)
                        nested_result = self.detect_pii(nested_json, full_key)
                        for k, v in nested_result.items():
                            result.setdefault(k, set()).update(v)
                        continue
                    except Exception:
                        pass


                valid_imeis, invalid_imeis = detect_imei_from_keyval(key, val_str)
                if valid_imeis:
                    result.setdefault("imei", set()).update(valid_imeis)
                if invalid_imeis:
                    result.setdefault("imei_false_positive", set()).update(invalid_imeis)

                # Other PII patterns
                for pii_type, regex in patterns.items():
                    match = re.search(regex, f"{key}:{val_str}")
                    if match:
                        candidate = match.group(1) if match.lastindex else val_str
                        result.setdefault(pii_type, set()).add(candidate)


                cc_candidates = re.findall(r'(?<!\.)\b\d{13,19}\b(?!\.\d)', val_str)
                for num in cc_candidates:
                    if num in result.get("imei", set()):
                        continue
                    if check_luhn(num):
                        card_type = get_card_type(num)
                        if card_type != "Unknown":
                            result.setdefault("credit_card", set()).add(f"{num} ({card_type})")


        elif isinstance(parsed, list):
            for item in parsed:
                nested_result = self.detect_pii(item, parent_key)
                for k, v in nested_result.items():
                    result.setdefault(k, set()).update(v)

        return result

    def write_log(self):
        with open(LOG_FILE, "w") as f:
            json.dump(self.sdk_data, f, indent=2)
        ctx.log.info(" [LOG] Updated sdk_logs.json")

addons = [SDKSniffer()]
