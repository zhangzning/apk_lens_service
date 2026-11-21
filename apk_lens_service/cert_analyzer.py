"""APK 签名证书解析器。

解析 APK 的签名证书（v1/v2/v3），提取颁发者/主题/指纹/有效期等信息。
"""

import hashlib
import logging
import re
import shutil
from pathlib import Path

from asn1crypto import pem, x509

from apk_lens_service.utils import run_command

logger = logging.getLogger("apk_lens_service.cert_analyzer")
_VERIFIED_SCHEME = re.compile(r"^Verified using (v[123])(?:\.1)? scheme .*: true$", re.MULTILINE)


def _androguard_certificate(apk_path: str) -> tuple[str | None, x509.Certificate | None]:
    from androguard.core.apk import APK

    # A certificate can be present even when Androguard cannot parse the Manifest.
    apk = APK(apk_path, skip_analysis=True)
    for version, read_certificates in (
        ("v3", apk.get_certificates_v3),
        ("v2", apk.get_certificates_v2),
        ("v1", apk.get_certificates_v1),
    ):
        for certificate in read_certificates():
            if certificate is not None:
                return version, certificate
    return None, None


def _apksigner_certificate(apk_path: str) -> tuple[str | None, x509.Certificate | None]:
    executable = shutil.which("apksigner")
    if not executable:
        return None, None
    code, output, _ = run_command(
        [executable, "verify", "--verbose", "--print-certs", "--print-certs-pem", apk_path],
        timeout=20, capture_limit=1024**2,
    )
    if code != 0 or not (versions := _VERIFIED_SCHEME.findall(output)):
        return None, None
    if "-----BEGIN CERTIFICATE-----" not in output:
        return None, None
    for label, _, der in pem.unarmor(output.encode(), multiple=True):
        if label == "CERTIFICATE":
            return max(versions), x509.Certificate.load(der)
    return None, None


def parse_apk_certificate(apk_path: str) -> dict:
    """解析 APK 的签名证书信息。

    Returns:
        {
            "signature_version": "v2",
            "issuer": "CN=xxx",
            "subject": "CN=xxx",
            "serial_number": "123456",
            "fingerprint_md5": "ab:cd:...",
            "fingerprint_sha1": "ab:cd:...",
            "fingerprint_sha256": "ab:cd:...",
            "valid_from": "2020-01-01",
            "valid_to": "2047-01-01",
            "public_key_algorithm": "RSA",
            "key_size": 2048,
        }
    """

    result = {
        "signature_version": None, "issuer": None, "subject": None,
        "serial_number": None, "fingerprint_md5": None,
        "fingerprint_sha1": None, "fingerprint_sha256": None,
        "valid_from": None, "valid_to": None,
        "public_key_algorithm": None, "key_size": None,
    }

    if not apk_path or not Path(apk_path).exists():
        return result

    version, certificate = None, None
    try:
        version, certificate = _androguard_certificate(apk_path)
    except Exception:
        logger.info("Androguard 未能读取签名证书", exc_info=True)
    source = "androguard"
    if certificate is None:
        try:
            version, certificate = _apksigner_certificate(apk_path)
        except (OSError, ValueError, TypeError):
            logger.info("apksigner 未能读取签名证书", exc_info=True)
        source = "apksigner"
    if certificate is None:
        return result

    result["signature_version"] = version
    result["certificate_source"] = source
    c = certificate
    try:
        # 颁发者/主题
        logger.info("开始提取证书字段...")
        try:
            result["issuer"] = str(c.issuer.human_friendly)
            logger.info("issuer OK: %s", result["issuer"][:40])
        except Exception as e:
            logger.warning("issuer 失败: %s", e)
        try:
            result["subject"] = str(c.subject.human_friendly)
        except Exception:
            pass

        # 序列号
        try:
            result["serial_number"] = str(c.serial_number)
        except Exception:
            pass

        # 指纹
        try:
            result["fingerprint_sha256"] = c.sha256_fingerprint if hasattr(c, "sha256_fingerprint") else None
        except Exception as e:
            logger.warning("sha256 失败: %s", e)
        try:
            if hasattr(c, "sha1_fingerprint"):
                result["fingerprint_sha1"] = c.sha1_fingerprint
        except Exception:
            pass
        try:
            # 从 DER 计算 MD5
            der = c.dump() if hasattr(c, "dump") else None
            if der:
                result["fingerprint_md5"] = hashlib.md5(der).hexdigest()
        except Exception:
            pass

        # 有效期
        try:
            result["valid_from"] = str(c["tbs_certificate"]["validity"]["not_before"].native)
        except Exception:
            pass
        try:
            result["valid_to"] = str(c["tbs_certificate"]["validity"]["not_after"].native)
        except Exception:
            pass

        # 公钥算法 + 密钥长度
        try:
            result["public_key_algorithm"] = str(c["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"].native)
        except Exception:
            pass
        try:
            result["key_size"] = c["tbs_certificate"]["subject_public_key_info"].bit_size
        except Exception:
            pass

    except Exception as exc:
        logger.warning("证书解析失败 %s: %s", apk_path, exc)

    return result
