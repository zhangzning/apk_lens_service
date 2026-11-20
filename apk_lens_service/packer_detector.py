"""APK 加壳检测服务。

提供基于 SO 库特征、包名特征、assets 特征、DEX 大小比例、Java 文件数量的加壳检测能力。
"""

import json
import logging
from pathlib import Path
from zipfile import BadZipFile, ZipFile

logger = logging.getLogger("apk_lens_service.packer_detector")

PACKER_SIGNATURES_PATH = Path(__file__).resolve().parent / "packer_signatures.json"


def list_dex_files(apk_file: Path) -> list[str]:
    """列出 APK 内所有 dex 文件名。"""

    try:
        with ZipFile(apk_file, "r") as zip_file:
            return sorted(
                [name for name in zip_file.namelist() if name.endswith(".dex")]
            )
    except (BadZipFile, OSError) as exc:
        raise ValueError(f"APK 压缩包读取失败: {exc}") from exc


def load_packer_signatures() -> dict:
    """从配置文件加载壳特征签名。"""

    if not PACKER_SIGNATURES_PATH.exists():
        return {
            "so_names": set(),
            "so_keywords": [],
            "packages": [],
            "assets_patterns": [],
            "java_file_threshold": 10,
            "dex_ratio_threshold": 0.10,
            "dex_min_size": 1_000_000,
            "tiny_dex_threshold": 100_000,
        }

    with open(PACKER_SIGNATURES_PATH, encoding="utf-8") as f:
        data = json.load(f)

    return {
        "so_names": set(data.get("so_names", [])),
        "so_keywords": data.get("so_keywords", []),
        "packages": data.get("packages", []),
        "assets_patterns": data.get("assets_patterns", []),
        "java_file_threshold": data.get("java_file_threshold", 10),
        "dex_ratio_threshold": data.get("dex_ratio_threshold", 0.10),
        "dex_min_size": data.get("dex_min_size", 1_000_000),
        "tiny_dex_threshold": data.get("tiny_dex_threshold", 100_000),
    }


def analyze_so_libraries(apk_file: Path) -> dict:
    """分析 APK 内 .so 库，识别已知加壳器特征。

    Returns:
        {
            "so_files": ["lib/arm64-v8a/libjiagu.so", ...],
            "matched_packers": ["libjiagu.so", ...],
            "is_packer_so": True,
            "packer_name": "jiagu",
        }
    """

    signatures = load_packer_signatures()
    try:
        with ZipFile(apk_file, "r") as zf:
            all_names = set(zf.namelist())
    except (BadZipFile, OSError):
        return {"so_files": [], "matched_packers": [], "is_packer_so": False, "packer_name": ""}

    so_files = sorted(name for name in all_names if name.endswith(".so"))
    so_basenames = {name.rsplit("/", 1)[-1] for name in so_files}
    found_packers = sorted(so_basenames & signatures["so_names"])

    packer_name = ""
    if found_packers:
        packer_name = found_packers[0].replace("lib", "").replace(".so", "")

    return {
        "so_files": so_files,
        "matched_packers": found_packers,
        "is_packer_so": bool(found_packers),
        "packer_name": packer_name,
    }


def quick_packing_check(apk_file: Path) -> dict:
    """快速加壳预检：仅检查 APK 内的 so/assets/package 特征，不依赖 jadx。

    用于在反编译之前判断是否加壳，避免对加壳 APK 执行耗时的 jadx 反编译。
    返回格式与 detect_packing 一致，java_file_count 固定为 -1（未检测）。
    """

    indicators: list[str] = []
    packer_name = ""
    signatures = load_packer_signatures()

    try:
        with ZipFile(apk_file, "r") as zf:
            all_names = set(zf.namelist())
    except (BadZipFile, OSError):
        return {"is_packed": False, "packer_name": "", "indicators": [], "java_file_count": -1}

    # 检查 so 库（精确匹配 + 关键词子串包含，命中版本号变体如 libjiagu_v2.so）
    so_files = {name.rsplit("/", 1)[-1] for name in all_names if name.endswith(".so")}
    found_packers = so_files & signatures["so_names"]
    if found_packers:
        indicators.append(f"壳 so 库: {', '.join(sorted(found_packers))}")
        packer_name = sorted(found_packers)[0].replace("lib", "").replace(".so", "")
    # 关键词子串匹配（补充覆盖版本号变体）
    for so_bn in so_files - found_packers:
        for kw in signatures["so_keywords"]:
            if kw in so_bn.lower():
                indicators.append(f"壳 so 库(关键词): {so_bn}")
                if not packer_name:
                    packer_name = so_bn.replace("lib", "").replace(".so", "")
                break

    # 检查包名/stub 特征：遍历 ZIP 内所有条目路径（如 com/stub/stub_app/...）
    # 注意：APK 内是 dex 而非 .class，原实现检查 .class 后缀永远不命中，改为检查路径片段
    pkg_hits: set[str] = set()
    for name in all_names:
        # 将路径 a/b/c 转成 a.b.c 做前缀匹配
        dotted = name.replace("/", ".").lower()
        for pkg in signatures["packages"]:
            if pkg.lower() in dotted:
                pkg_hits.add(pkg)
    for pkg in sorted(pkg_hits):
        indicators.append(f"壳包名: {pkg}")
        if not packer_name:
            packer_name = pkg.rstrip(".").split(".")[-1]

    # 检查 assets 特征
    for pattern in signatures["assets_patterns"]:
        matched = [name for name in all_names if name.startswith(pattern)]
        if matched:
            indicators.append(f"壳 assets: {pattern}*")
            if not packer_name:
                packer_name = "unknown"

    # 检查 dex 文件大小比例（加壳 APK 的 classes.dex 通常很小或被抽走）
    dex_ratio_threshold = signatures["dex_ratio_threshold"]
    dex_min_size = signatures["dex_min_size"]
    tiny_dex_threshold = signatures["tiny_dex_threshold"]
    try:
        apk_size = apk_file.stat().st_size
        with ZipFile(apk_file, "r") as zf:
            dex_entries = [n for n in zf.namelist() if n.endswith(".dex")]
            total_dex_size = sum(zf.getinfo(n).file_size for n in dex_entries)
        if apk_size > 0 and len(dex_entries) > 0:
            dex_ratio = total_dex_size / apk_size
            # 条件1: dex 占比 < 阈值 且 dex 总量 < dex_min_size
            if dex_ratio < dex_ratio_threshold and total_dex_size < dex_min_size:
                indicators.append(f"DEX 文件过小: {total_dex_size} bytes ({dex_ratio:.1%} of APK)")
                if not packer_name:
                    packer_name = "unknown"
            # 条件2: 只有单个 classes.dex 且极小（壳常把真正 dex 抽走/加密）
            elif len(dex_entries) == 1 and total_dex_size < tiny_dex_threshold:
                indicators.append(f"单一 DEX 且过小: {total_dex_size} bytes")
                if not packer_name:
                    packer_name = "unknown"
    except (BadZipFile, OSError):
        pass

    is_packed = bool(indicators)

    return {
        "is_packed": is_packed,
        "packer_name": packer_name,
        "indicators": indicators,
        "java_file_count": -1,
    }


def detect_packing(apk_file: Path, java_file_count: int) -> dict:
    """检测 APK 是否加壳/加固。

    综合判断依据：
    1. 反编译后的 Java 文件数量（< 10 个高度疑似加壳）
    2. APK 内是否存在已知壳的 so 库
    3. APK 内是否存在已知壳的包名 stub 类
    4. APK 内是否存在已知壳的 assets 特征文件

    返回：
    - `is_packed`: bool 是否疑似加壳
    - `packer_name`: str 识别到的壳名称
    - `indicators`: list[str] 触发判断的特征列表
    - `java_file_count`: int 反编译 Java 文件数
    """

    indicators: list[str] = []
    packer_name = ""
    signatures = load_packer_signatures()

    try:
        with ZipFile(apk_file, "r") as zf:
            all_names = set(zf.namelist())
    except (BadZipFile, OSError):
        return {"is_packed": False, "packer_name": "", "indicators": [], "java_file_count": java_file_count}

    # 检查 so 库（精确匹配 + 关键词子串包含）
    so_files = {name.rsplit("/", 1)[-1] for name in all_names if name.endswith(".so")}
    found_packers = so_files & signatures["so_names"]
    if found_packers:
        indicators.append(f"壳 so 库: {', '.join(sorted(found_packers))}")
        packer_name = sorted(found_packers)[0].replace("lib", "").replace(".so", "")
    for so_bn in so_files - found_packers:
        for kw in signatures["so_keywords"]:
            if kw in so_bn.lower():
                indicators.append(f"壳 so 库(关键词): {so_bn}")
                if not packer_name:
                    packer_name = so_bn.replace("lib", "").replace(".so", "")
                break

    # 检查包名/stub 特征（遍历 ZIP 内所有条目路径）
    pkg_hits: set[str] = set()
    for name in all_names:
        dotted = name.replace("/", ".").lower()
        for pkg in signatures["packages"]:
            if pkg.lower() in dotted:
                pkg_hits.add(pkg)
    for pkg in sorted(pkg_hits):
        indicators.append(f"壳包名: {pkg}")
        if not packer_name:
            packer_name = pkg.rstrip(".").split(".")[-1]

    # 检查 assets 特征
    for pattern in signatures["assets_patterns"]:
        matched = [name for name in all_names if name.startswith(pattern)]
        if matched:
            indicators.append(f"壳 assets: {pattern}*")
            if not packer_name:
                packer_name = "unknown"

    # Java 文件数量判断
    threshold = signatures["java_file_threshold"]
    is_packed = False
    if java_file_count < threshold:
        indicators.append(f"Java 文件数过少: {java_file_count}")
        is_packed = True

    # 如果有明确的壳特征，也判定为加壳
    if found_packers or any(ind.startswith("壳") for ind in indicators):
        is_packed = True

    return {
        "is_packed": is_packed,
        "packer_name": packer_name,
        "indicators": indicators,
        "java_file_count": java_file_count,
    }
