import os
import re
import subprocess
import tempfile
from typing import Optional

from cryptography import x509


def decode_escaped_utf8(s: str) -> str:
    """
    Chuyển chuỗi dạng 'Tr\\xE1\\xBA\\xA7n' thành 'Trần' (UTF-8).
    """
    if not s:
        return ""

    try:
        tmp = re.sub(
            r"\\x([0-9A-Fa-f]{2})",
            lambda m: bytes.fromhex(m.group(1)).decode("latin-1"),
            s,
        )
        return tmp.encode("latin-1").decode("utf-8")
    except Exception:
        return s


def _run_pkcs11_tool(args: list[str]) -> str:
    return subprocess.check_output(
        args,
        text=True,
        stderr=subprocess.STDOUT,
    )


def _clean_text(s: Optional[str]) -> str:
    return (s or "").strip()


def _normalize_hex_id(value: str) -> str:
    """
    Chuẩn hóa ID:
    - '01'
    - '01ab'
    - '01:AB'
    - '01 AB'
    - '0x01'
    -> '01ab'
    """
    raw = _clean_text(value).lower()
    raw = raw.replace("0x", "")
    raw = re.sub(r"[^0-9a-f]", "", raw)
    return raw


def _hex_to_bytes(value: str) -> bytes:
    hx = _normalize_hex_id(value)
    if not hx:
        return b""
    if len(hx) % 2 == 1:
        hx = "0" + hx
    return bytes.fromhex(hx)


def _extract_dn_attr(subject: str, attr: str) -> str:
    """
    Bắt attr trong DN, ví dụ:
    CN=...
    O=...
    emailAddress=...
    """
    if not subject:
        return ""

    m = re.search(
        rf"(?:^|[,/])\s*{re.escape(attr)}=([^,/]+)",
        subject,
        re.IGNORECASE,
    )
    return decode_escaped_utf8(m.group(1).strip()) if m else ""


def _looks_like_ca_or_root(cn: str, org: str, label: str, ca_keywords: list[str]) -> bool:
    hay = " | ".join([cn or "", org or "", label or ""]).lower()
    return any((k or "").lower() in hay for k in ca_keywords)


def _read_cert_der(pkcs11_lib: str, slot_no: int, cka_id: str) -> Optional[bytes]:
    """
    Đọc DER của certificate theo CKA_ID để kiểm tra BasicConstraints.
    Trả None nếu module không cho đọc (không phải lỗi fatal).
    """
    hx = _normalize_hex_id(cka_id)
    if not hx:
        return None

    tmp_path = ""
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="vgca_cert_", suffix=".der")
        os.close(fd)

        _run_pkcs11_tool(
            [
                "pkcs11-tool",
                "--module",
                pkcs11_lib,
                "--slot",
                str(slot_no),
                "--read-object",
                "--type",
                "cert",
                "--id",
                hx,
                "--output-file",
                tmp_path,
            ]
        )

        with open(tmp_path, "rb") as f:
            der = f.read()
        return der or None
    except Exception:
        # Nhiều module không cho đọc CKA_VALUE kèm theo ID -> fallback keyword, không log ồn
        return None
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _is_ca_cert(der: bytes) -> Optional[bool]:
    """
    True/False nếu xác định được qua X.509 BasicConstraints,
    None nếu không đọc được cert.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(basic.ca)
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return None



def parse_slots(pkcs11_lib: str) -> list[dict]:
    """
    Trả về:
    [
        {
            "slot": 0,
            "token": "TOKEN LABEL",
            "serial": "12345678"
        }
    ]
    """
    slots: list[dict] = []

    try:
        out = _run_pkcs11_tool(["pkcs11-tool", "--module", pkcs11_lib, "-L"])
    except Exception as e:
        print(f"[parse_slots] error: {e}")
        return []

    current_slot: Optional[int] = None
    token_label = ""
    token_serial = ""

    for line in out.splitlines():
        m = re.match(r"^\s*Slot\s+(\d+)", line)
        if m:
            if current_slot is not None:
                slots.append(
                    {
                        "slot": current_slot,
                        "token": token_label or "Token",
                        "serial": token_serial,
                    }
                )
            current_slot = int(m.group(1))
            token_label = ""
            token_serial = ""
            continue

        if "token label" in line.lower() and ":" in line:
            token_label = decode_escaped_utf8(line.split(":", 1)[-1].strip())
            continue

        if "serial number" in line.lower() and ":" in line:
            token_serial = line.split(":", 1)[-1].strip()
            continue

    if current_slot is not None:
        slots.append(
            {
                "slot": current_slot,
                "token": token_label or "Token",
                "serial": token_serial,
            }
        )

    return slots


def _split_object_blocks(output: str) -> list[str]:
    return re.split(
        r"(?=^(?:Certificate|Private Key|Public Key) Object)",
        output,
        flags=re.MULTILINE,
    )


def _parse_private_key_ids(output: str) -> set[str]:
    """
    Lấy toàn bộ ID/CKA_ID của Private Key trong slot.
    """
    ids: set[str] = set()

    for block in _split_object_blocks(output):
        if not block.startswith("Private Key Object"):
            continue

        id_m = re.search(r"^\s*ID:\s*(.+)$", block, re.MULTILINE)
        if not id_m:
            continue

        kid = _normalize_hex_id(id_m.group(1))
        if kid:
            ids.add(kid)

    return ids


def parse_certs(pkcs11_lib: str, ca_keywords: list[str]) -> list[dict]:
    """
    Đọc cert từ tất cả slot theo hướng:
    Module PKCS11 -> Slot ID -> Token Serial -> CKA_ID -> Certificate

    Trả về dict có các key:
    - slot
    - token
    - token_serial
    - serial
    - label
    - id
    - cka_id
    - cn
    - org
    - email
    - display
    - module
    - pkcs11_lib
    """
    all_certs: list[dict] = []

    slots = parse_slots(pkcs11_lib)
    if not slots:
        return []

    for slot_info in slots:
        slot_no = slot_info["slot"]
        token_label = slot_info["token"]
        token_serial = slot_info.get("serial", "")

        try:
            out = _run_pkcs11_tool(
                ["pkcs11-tool", "--module", pkcs11_lib, "--slot", str(slot_no), "-O"]
            )
        except Exception as e:
            print(f"[parse_certs] slot={slot_no} error: {e}")
            continue

        private_key_ids = _parse_private_key_ids(out)

        for block in _split_object_blocks(out):
            if not block.startswith("Certificate Object"):
                continue

            id_m = re.search(r"^\s*ID:\s*(.+)$", block, re.MULTILINE)
            label_m = re.search(r"^\s*label:\s*(.+)$", block, re.MULTILINE)
            subj_m = re.search(r"^\s*subject:\s*DN:\s*(.+)$", block, re.MULTILINE)

            raw_id = _clean_text(id_m.group(1)) if id_m else ""
            cka_id = _normalize_hex_id(raw_id)

            label = decode_escaped_utf8(_clean_text(label_m.group(1)) if label_m else raw_id)
            subject = _clean_text(subj_m.group(1)) if subj_m else ""

            # Một số middleware không in ID cho Certificate Object.
            # Khi đó vẫn giữ cert lại và ký theo label (strategy label-only).
            if not cka_id and not label:
                continue

            cn = _extract_dn_attr(subject, "CN") or label
            org = _extract_dn_attr(subject, "O")
            email = _extract_dn_attr(subject, "emailAddress")

            # Lọc CA/root: ưu tiên BasicConstraints thật (X.509),
            # chỉ fallback về keyword khi không đọc được DER.
            is_ca: Optional[bool] = None
            if cka_id:
                der = _read_cert_der(pkcs11_lib, slot_no, cka_id)
                if der:
                    is_ca = _is_ca_cert(der)

            if is_ca is True:
                continue

            if is_ca is None and _looks_like_ca_or_root(cn, org, label, ca_keywords):
                continue

            has_matching_private_key = None
            if private_key_ids and cka_id:
                has_matching_private_key = cka_id in private_key_ids

            display = f"{cn} | {token_label} | Slot {slot_no}"

            all_certs.append(
                {
                    "slot": slot_no,
                    "token": token_label,
                    "token_serial": token_serial,
                    "serial": token_serial,
                    "label": label,
                    "id": cka_id,
                    "cka_id": cka_id,
                    "cn": cn,
                    "org": org,
                    "email": email,
                    "display": display,
                    "module": pkcs11_lib,
                    "pkcs11_lib": pkcs11_lib,
                    "has_private_key": has_matching_private_key,
                }
            )

    # Ưu tiên cert có private key matching nếu phát hiện được.
    # Cert không xác định được (None) vẫn giữ lại: thà hiện thừa còn hơn mất cert ký.
    if any(c.get("has_private_key") is True for c in all_certs):
        all_certs = [c for c in all_certs if c.get("has_private_key") is not False]

    # Loại trùng theo slot + serial + cka_id + cn
    dedup: list[dict] = []
    seen: set[tuple] = set()

    for cert in all_certs:
        key = (
            cert.get("slot"),
            cert.get("serial", ""),
            cert.get("cka_id", "") or cert.get("label", ""),
            cert.get("cn", ""),
        )

        if key in seen:
            continue
        seen.add(key)
        dedup.append(cert)

    return dedup


def cert_id_to_bytes(cert: dict) -> bytes:
    """
    Helper cho pdf_sign_service:
    ưu tiên cka_id, fallback id.
    """
    raw = cert.get("cka_id") or cert.get("id") or ""
    return _hex_to_bytes(raw)
