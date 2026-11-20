"""APK 签名证书解析器。

解析 APK 的签名证书（v1/v2/v3），提取颁发者/主题/指纹/有效期等信息。
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger("apk_lens_service.cert_analyzer")


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

    try:
        from androguard.core.apk import APK as AndroAPK
        try:
            from loguru import logger as _loguru
            _loguru.remove()
        except Exception:
            pass

        apk = AndroAPK(apk_path)

        # 签名版本检测
        v3 = apk.get_certificates_der_v3() if hasattr(apk, "get_certificates_der_v3") else []
        v2 = apk.get_certificates_der_v2() if hasattr(apk, "get_certificates_der_v2") else []
        if v3:
            result["signature_version"] = "v3"
            certs = apk.get_certificates_v3()
        elif v2:
            result["signature_version"] = "v2"
            certs = apk.get_certificates_v2()
        else:
            certs = apk.get_certificates_v1() if hasattr(apk, "get_certificates_v1") else []
            if any(certs):
                result["signature_version"] = "v1"

        certs = [cert for cert in certs if cert is not None]
        if not certs:
            result["signature_version"] = None
            logger.info("证书解析: 未提取到证书对象")
            return result
        logger.info("证书解析: certs=%d version=%s", len(certs), result["signature_version"])

        c = certs[0]

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
