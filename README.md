# apk_lens_service

独立的 APK 静态解析 HTTP 服务。上传 APK 后可直接下载 JSON 报告，或下载含报告与解析产物的 ZIP。服务在独立子进程中解析 APK，每个请求使用单独的临时目录，响应结束后清理。结果由调用方保存，服务无数据库依赖。

## 启动

支持 Linux 和 macOS，需要 Python 3.12 或以上版本。

```sh
uv sync
uv run apk-lens-service
```

也可使用 `pip install .` 安装，再运行 `apk-lens-service` 或 `python -m apk_lens_service`。默认监听 `127.0.0.1:18086`。在同一实例中，由一个 HTTP 进程统一管理并发上限，各解析阶段启动独立子进程。默认同时处理两个请求，其中最多一个深度解析请求。

## 分析模式

| 模式 | 分析内容 | 默认输出 |
| --- | --- | --- |
| `basic` | 包名、版本、SDK、应用名称及各语言版本、图标、Manifest 权限和组件、文件统计、加壳线索 | JSON |
| `standard` | 基础信息、权限详情、签名方案与证书信息 | JSON |
| `deep` | 标准模式、JADX 反编译、Java 类与成员、资源清单、原生库及其导出符号 | ZIP |

基础解析使用 Androguard，可通过 Android SDK 的 `aapt2` 补充或降级读取。深度解析需要 `jadx` 和 Java。原生库导出符号需要 `readelf`、`llvm-readelf` 或 `greadelf`。工具可用性见 `GET /readyz`。

## 调用

`POST /v1/analyze` 接收 APK 原始字节，默认使用 `standard`。可通过 `profile=basic|standard|deep` 和 `output=json|zip` 选择模式和格式。配置访问令牌后，请求携带 `Authorization: Bearer <token>`。

```sh
curl --fail-with-body \
  -H 'Content-Type: application/vnd.android.package-archive' \
  --data-binary @sample.apk \
  'http://127.0.0.1:18086/v1/analyze?filename=sample.apk&profile=standard' \
  -o result.json
```

默认返回 APK 条目数 `modules.basic.data.file_count`。传入 `include_file_tree=true` 后，JSON 或 ZIP 内的 `result.json` 会同时包含 `modules.basic.data.file_tree`，其值是按名称排序的 APK 内部路径列表。

应用显示名优先选择简体中文（中国），并在 `modules.basic.data.app_names` 中保留默认名称、通用中文、本地化名称及其来源。报告中的 `modules` 给出各模块的状态，可以区分完整结果与降级结果。

深度模式的 ZIP 包含 `result.json`、可用图标、`jadx/` 和 `reverse/`。若选择 JSON，则仅返回报告和分析摘要。健康检查使用 `GET /healthz`，完整接口定义见 `GET /docs`。

## 配置

下表列出常用环境变量。临时目录需预先创建并允许服务账户读写。监听非回环地址时需设置访问令牌。

| 环境变量 | 默认值或用途 |
| --- | --- |
| `APK_LENS_SERVICE_HOST` | `127.0.0.1` |
| `APK_LENS_SERVICE_PORT` | `18086` |
| `APK_LENS_SERVICE_TOKEN` | 启用 Bearer 访问控制 |
| `APK_LENS_SERVICE_WORK_DIR` | 系统临时目录 |
| `APK_LENS_SERVICE_MAX_JOBS` | 同时处理的请求数，默认 2 |
| `APK_LENS_SERVICE_MAX_DEEP_JOBS` | 同时深度解析的请求数，默认 1，设为 0 关闭深度解析 |
| `APK_LENS_SERVICE_MAX_APK_MIB` | 上传上限，默认 512 MiB |
| `APK_LENS_SERVICE_MAX_EXPANDED_MIB` | APK 条目展开体积上限，默认 1536 MiB |
| `APK_LENS_SERVICE_MAX_RESULT_MIB` | 解析产物大小上限，默认 256 MiB |
| `APK_LENS_SERVICE_MAX_FILES` | 条目数上限，默认 50000 |
| `APK_LENS_SERVICE_AAPT2_BIN` | `aapt2` 或其可执行文件路径 |
| `APK_LENS_SERVICE_JADX_BIN` | `jadx` 或其可执行文件路径 |
| `APK_LENS_SERVICE_JAVA_HOME` | Java 安装目录。省略时从 `PATH` 查找 |

运行测试使用 `uv run pytest -q`。
