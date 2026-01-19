from mitmproxy import http, ctx
import json
import re
import gzip
from datetime import datetime
import os
from urllib.parse import unquote_plus, urlsplit, parse_qs
import base64
import binascii


LOG_FILE = "sdk_logs.json"
MAPPING_PREFIX = "regex_raw_mapping_"
NO_PII_LOG_FILE = "raw_packets_no_pii.json"


def shorten(s, max_len=120):
    s = "" if s is None else str(s)
    return s if len(s) <= max_len else s[:max_len] + f"...({len(s)} chars)"


_DECODE_ANNOTATION_RE = re.compile(r"\s+\(decoded:[^)]*\)\s*$")
_DECODE_ANNOTATION_CAPTURE_RE = re.compile(r"\((decoded:[^)]*)\)\s*$")


def dedup_pii_values(values):
    """
    Deduplicate values that may appear multiple times with different provenance annotations.

    Example duplicates to collapse within a single packet:
      - "180001"
      - "180001 (decoded:base64_decoded, encoded_as:...)"

    Preference: keep a decoded-annotated variant if present (more informative).
    """
    if not values:
        return set()

    grouped = {}
    for v in values:
        v = str(v)
        base = _DECODE_ANNOTATION_RE.sub("", v).strip()
        grouped.setdefault(base, []).append(v)

    chosen = set()
    for _, variants in grouped.items():
        decoded = [x for x in variants if "(decoded:" in x]
        plaintext = [x for x in variants if "(decoded:" not in x]


        if plaintext and decoded:
            decoded_sorted = sorted(decoded, key=lambda x: (len(x), x))
            dv = decoded_sorted[0]
            m = _DECODE_ANNOTATION_CAPTURE_RE.search(dv)
            payload = m.group(1) if m else "decoded:unknown"
            chosen.add(f"{_DECODE_ANNOTATION_RE.sub('', dv).strip()} (plaintext; {payload})")
            continue


        pick_from = decoded if decoded else plaintext if plaintext else variants
        pick_from = sorted(pick_from, key=lambda x: (len(x), x))
        chosen.add(pick_from[0])

    return chosen


def dedup_pii_result(result_dict):
    """
    Apply dedup_pii_values() across all pii_type keys in a detect_pii() result.
    Expects: dict[str, set[str]]
    Returns: dict[str, set[str]]
    """
    if not isinstance(result_dict, dict):
        return result_dict
    out = {}
    for k, v in result_dict.items():
        if isinstance(v, set):
            out[k] = dedup_pii_values(v)
        else:
            # fallback: coerce to set
            out[k] = dedup_pii_values(set(v) if isinstance(v, (list, tuple)) else {str(v)})
    return out


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
        r'address|addr|home[_\s]?address|street|street[_\s]?address',
        r'[A-Za-z0-9][A-Za-z0-9 ,.\-\/]{5,100}'
    ),

    "city": wrap_keywords(
        r'city|town|district',
        r'\b(?!company\b|co\b|com\b)[A-Z][a-z]{2,}(?: [A-Z][a-z]{2,})*\b'
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
        r'\b(?:user[_\-]?name|account[_\-]?name|profile[_\-]?name|customer[_\-]?name|full[_\-]?name|first[_\-]?name|last[_\-]?name)\b',
        r'\b[A-Z][a-z]{2,}(?: [A-Z][a-z]{2,}){0,2}\b'
    ),
    "accelerometer": wrap_keywords(
    r'accelerometer[_\-]?[xyz]',
    r'-?\d+(?:\.\d+)?(?:E[-+]?\d+)?'
),
    "password": wrap_keywords(
        r'password|pass|passwd|pwd|user_password',
        r'[A-Za-z0-9@#$%^&+=!?.*_-]{4,}'
    ),
    "latitude": r'(?i)\b(?:lat|latitude)\b[=\s:"]+([-+]?(?!0+\.0+$)\d{1,3}\.\d+)',
    "longitude": r'(?i)\b(?:lon|lng|longitude)\b[=\s:"]+([-+]?(?!0+\.0+$)\d{1,3}\.\d+)'

}

JUNK_WORDS = {

     "no", "null", "undefined" ,  "rest" , "check"

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


def multi_urldecode(s: str, max_rounds: int = 2) -> str:
    out = s
    for _ in range(max_rounds):
        new = unquote_plus(out)
        if new == out:
            break
        out = new
    return out


def try_base64_decode(s: str):
    """
    Try decoding base64 safely. Returns decoded string or None.
    Only attempts if string is plausible base64 and mostly printable after decoding.
    """
    st = s.strip()
    if len(st) < 16:
        return None


    if not re.fullmatch(r'[A-Za-z0-9+/=_-]+', st):
        return None


    st2 = st.replace('-', '+').replace('_', '/')

    st2 += "=" * ((-len(st2)) % 4)

    try:
        raw = base64.b64decode(st2, validate=False)
        decoded = raw.decode("utf-8", errors="replace")


        printable = sum(ch.isprintable() for ch in decoded)
        if decoded and printable / max(1, len(decoded)) > 0.85:
            return decoded
    except (binascii.Error, ValueError):
        return None

    return None


def extract_candidate_strings(val_str: str):
    """
    Generate decoded variants for a string value to catch common encodings.
    Returns a list of tuples: (candidate_text, origin, encoded_as).
    - origin: "raw" | "url_decoded" | "base64_decoded" | "base64+url_decoded"
    - encoded_as: the original encoded string (only for decoded variants)
    """
    candidates = []
    s = str(val_str).strip()
    if not s:
        return candidates

    candidates.append((s, "raw", None))


    ud = multi_urldecode(s, max_rounds=2)
    if ud != s:
        candidates.append((ud, "url_decoded", s))


    b64 = try_base64_decode(s)
    if b64 and b64 not in [c[0] for c in candidates]:
        candidates.append((b64, "base64_decoded", s))


        b64_ud = multi_urldecode(b64, max_rounds=2)
        if b64_ud != b64:
            if b64_ud not in [c[0] for c in candidates]:
                candidates.append((b64_ud, "base64+url_decoded", s))

    return candidates

class SDKSniffer:
    def __init__(self):
        self.sdk_data = []

        self.total_packets = 0
        self.total_pii_packets = 0
        self.total_no_pii_packets = 0

        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.mapping_file = os.path.join(
            os.path.dirname(LOG_FILE),
            f"regex_raw_mapping_{ts}.json"
        )
        self.mapping_data = []

        self.packet_counter = {}

    def load(self, loader):
        self.clear_log()

    def done(self):
        summary = {
            "TOTAL_packets": self.total_packets,
            "PII_1_total_packets": self.total_pii_packets,
            "PII_0_total_packets": self.total_no_pii_packets,
            "ALL_packets": self.total_pii_packets + self.total_no_pii_packets
        }

        with open("packet_summary.json", "w") as f:
            json.dump(summary, f, indent=2)

        ctx.log.info("📊 Packet summary saved in packet_summary.json")
        ctx.log.info("Mitmproxy stopped. Files saved.")

    def clear_log(self):

        with open(LOG_FILE, "w") as f:
            json.dump([], f)


        with open(NO_PII_LOG_FILE, "w") as f:
            json.dump([], f)


        self.sdk_data = []
        self.mapping_data = []
        self.total_packets = 0
        self.total_pii_packets = 0
        self.total_no_pii_packets = 0

        ctx.log.info("All logs reset (PII + NO-PII). Mapping files kept safe.")

    def request(self, flow: http.HTTPFlow):
        domain = flow.request.host



        self.total_packets += 1



        ctx.log.info(f"[REQ] {flow.request.method} {flow.request.pretty_url}")

        data_sent = {}
        content_type = flow.request.headers.get("content-type", "").lower()


        pretty_body = ""

        try:
            raw_bytes = flow.request.get_content()
            content_encoding = flow.request.headers.get("content-encoding", "").lower()

            if "gzip" in content_encoding and raw_bytes[:2] == b'\x1f\x8b':
                body_text = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
            else:
                body_text = raw_bytes.decode("utf-8", errors="replace")

        except Exception as e:
            ctx.log.warn(f"Body decode error: {e}")
            body_text = ""


        if body_text:
            pretty_body = unquote_plus(body_text)
            if "&" in pretty_body:
                pretty_body = pretty_body.replace("&", "\n")


        headers_text = "\n".join(
            f"{k}: {v}" for k, v in flow.request.headers.items()
        )


        headers_dict = dict(flow.request.headers.items())
        try:
            qs = urlsplit(flow.request.pretty_url).query
            query_dict = {
                k: (v[0] if len(v) == 1 else v)
                for k, v in parse_qs(qs, keep_blank_values=True).items()
            } if qs else {}
        except Exception:
            query_dict = {}


        full_request = (
            f"{flow.request.method} {flow.request.pretty_url} {flow.request.http_version}\n"
            f"{headers_text}\n\n"
            f"{pretty_body}"
        )


        body_obj = None
        if body_text.strip():
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
                    body_obj = parsed
                elif "x-www-form-urlencoded" in content_type:
                    ctx.log.info(" → Parsing as x-www-form-urlencoded")
                    form_dict = dict(flow.request.urlencoded_form)
                    body_obj = form_dict
                elif "multipart" in content_type:
                    ctx.log.info(" → Parsing as multipart")
                    form_dict = dict(flow.request.multipart_form.items())
                    body_obj = form_dict
                else:
                    ctx.log.info(" → Treating as raw body")
                    body_obj = {"raw_body": body_text}
            except Exception as e:
                ctx.log.warn(f"Body parse error: {e}")
                body_obj = {"raw_body": body_text}


        scan_target = {
            "headers": headers_dict,
            "query": query_dict
        }
        if body_obj is not None:
            scan_target["body"] = body_obj
        data_sent.update(self.detect_pii(scan_target))


        if data_sent:
            data_sent = dedup_pii_result(data_sent)

        if not data_sent:
            self.total_no_pii_packets += 1

            no_pii_entry = {
                "domain": domain,
                "pii_detected": 0,
                "url": flow.request.pretty_url,
                "raw_request": full_request

            }

            try:
                with open(NO_PII_LOG_FILE, "r") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

            existing.append(no_pii_entry)

            with open(NO_PII_LOG_FILE, "w") as f:
                json.dump(existing, f, indent=2)


            ctx.log.info(" → Raw packet saved (NO PII)")
            return

        clean_data = {k: list(v) for k, v in data_sent.items()}

        for pii_type, values in clean_data.items():
            for val in values:
                self.mapping_data.append({
                    "domain": domain,
                    "pii_detected": 1,
                    "pii_type": pii_type,
                    "value": val,
                    "url": flow.request.pretty_url,
                    "raw_request": full_request

                })

        with open(self.mapping_file, "w") as f:
            json.dump(self.mapping_data, f, indent=2)

        app_info = {
            "App Domain": domain,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Data Sent": clean_data
        }

        self.total_pii_packets += 1

        ctx.log.info(f" [+] PII Detected: {clean_data}")
        self.sdk_data.append(app_info)
        self.write_log()

    def detect_pii(self, parsed, parent_key="", source_origin="raw", source_encoded_as=None):
        result = {}

        def annotate(value, origin, encoded_as):
            if origin == "raw" or not encoded_as:
                return value
            return f"{value} (decoded:{origin}, encoded_as:{shorten(encoded_as)})"

        imei_raw_seen = set()


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

                candidates = extract_candidate_strings(val_str)

                for candidate_str, origin, encoded_as in candidates:

                    candidate_str = candidate_str.strip()


                    eff_origin = origin if origin != "raw" else source_origin
                    eff_encoded_as = encoded_as if origin != "raw" else source_encoded_as

                    if (candidate_str.startswith("{") and candidate_str.endswith("}")) or \
                    (candidate_str.startswith("[") and candidate_str.endswith("]")):
                        try:
                            nested_json = json.loads(candidate_str)
                            nested_result = self.detect_pii(
                                nested_json,
                                full_key,
                                source_origin=eff_origin,
                                source_encoded_as=eff_encoded_as
                            )
                            for k, v in nested_result.items():
                                result.setdefault(k, set()).update(v)
                        except Exception:
                            pass


                    valid_imeis, invalid_imeis = detect_imei_from_keyval(key, candidate_str)
                    if valid_imeis:
                        imei_raw_seen.update(valid_imeis)
                        result.setdefault("imei", set()).update(
                            {annotate(x, eff_origin, eff_encoded_as) for x in valid_imeis}
                        )
                    if invalid_imeis:
                        result.setdefault("imei_false_positive", set()).update(
                            {annotate(x, eff_origin, eff_encoded_as) for x in invalid_imeis}
                        )


                    for pii_type, regex in patterns.items():
                        if pii_type == "name" and key_lower not in ALLOWED_NAME_KEYS:
                            continue
                        match = re.search(regex, f"{key}:{candidate_str}")
                        if match:
                            candidate = match.group(1) if match.lastindex else candidate_str

                            if pii_type in ("latitude", "longitude"):
                                try:
                                    if float(candidate) == 0.0:
                                        continue
                                except ValueError:
                                    pass


                            if candidate.lower() in JUNK_WORDS:
                                continue

                            result.setdefault(pii_type, set()).add(
                                annotate(candidate, eff_origin, eff_encoded_as)
                            )


                    cc_candidates = re.findall(r'(?<!\.)\b\d{13,19}\b(?!\.\d)', candidate_str)
                    for num in cc_candidates:
                        if num in imei_raw_seen:
                            continue
                        if check_luhn(num):
                            card_type = get_card_type(num)
                            if card_type != "Unknown":
                                result.setdefault("credit_card", set()).add(
                                    annotate(f"{num} ({card_type})", eff_origin, eff_encoded_as)
                                )


        elif isinstance(parsed, list):
            for item in parsed:
                nested_result = self.detect_pii(item, parent_key, source_origin, source_encoded_as)
                for k, v in nested_result.items():
                    result.setdefault(k, set()).update(v)

        return result


    def write_log(self):
        with open(LOG_FILE, "w") as f:
            json.dump(self.sdk_data, f, indent=2)
        ctx.log.info(" [LOG] Updated sdk_logs.json")

addons = [SDKSniffer()]




