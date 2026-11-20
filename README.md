# apk_lens_service

独立的 APK 静态解析 HTTP 服务。上传 APK 后可直接下载 JSON 报告，或下载含报告与解析产物的 ZIP。服务在独立子进程中解析 APK，每个请求使用单独的临时目录，响应结束后清理。结果由调用方保存，服务无数据库依赖。

## 本机启动

支持 Linux 和 macOS，需要 Python 3.12 或以上版本。

```sh
uv sync
uv run apk-lens-service
```

也可使用 `pip install .` 安装，再运行 `apk-lens-service` 或 `python -m apk_lens_service`。默认监听 `127.0.0.1:18086`。在同一实例中，由一个 HTTP 进程统一管理并发上限，各解析阶段启动独立子进程。默认同时处理两个请求，其中最多一个深度解析请求。

## Linux 容器部署

处理外部上传的 APK 时可用 Docker Engine 和 Compose V2 启动隔离部署。先设置 `APK_LENS_SERVICE_TOKEN`，调用时携带该令牌。

```bash
read -rsp 'API token: ' APK_LENS_SERVICE_TOKEN
echo
export APK_LENS_SERVICE_TOKEN
docker compose up --build -d
curl --fail http://127.0.0.1:18086/readyz
```

只有 API 容器对外监听，默认仅绑定宿主机的回环地址。API 通过两个独立的 Unix 套接字流式转发请求，每个解析容器同时处理一个任务，整套服务最多同时处理两个任务和一个深度解析任务。API 令牌留在入口容器。解析容器关闭网络，使用非 root 用户、只读根文件系统、Docker 默认 seccomp 配置和 `no-new-privileges`，并去掉所有 Linux capabilities。

每个解析容器默认分配 2 核 CPU 配额、4 GiB 内存和 192 个任务槽位（含线程）。任务空间是独立的 2 GiB `tmpfs`，按容器内存计费，并在写入时执行容量限制。JADX 的缓存与临时文件位于当前任务目录，响应结束后随任务清理。每个解析子进程另有 CPU 时间与单文件大小限制。

| Compose 环境变量 | 默认值或用途 |
| --- | --- |
| `APK_LENS_BIND_ADDRESS` | 宿主机绑定地址，默认 127.0.0.1 |
| `APK_LENS_PORT` | 宿主机端口，默认 18086 |
| `APK_LENS_WORKER_CPUS` | 每个解析容器的 CPU 配额，默认 2 核 |
| `APK_LENS_WORKER_MEMORY` | 每个解析容器的内存上限，默认 4 GiB，Compose 将 swap 上限设为与内存相同以关闭额外 swap |
| `APK_LENS_WORKER_PIDS` | 每个解析容器的任务数上限，默认 192 |
| `APK_LENS_WORKER_TMPFS` | 每个解析容器的任务空间容量，默认 2 GiB |
| `APK_LENS_WORKER_JADX_HEAP_MIB` | JADX 的 JVM 堆上限，默认 1536 MiB |
| `APK_LENS_WORKER_CPU_SECONDS` | 单进程 CPU 时间上限，默认 900 秒 |
| `APK_LENS_WORKER_MAX_FILE_MIB` | 单进程写入文件的大小上限，默认 256 MiB |
| `APK_LENS_WORKER_ADDRESS_SPACE_MIB` | 单进程虚拟地址空间上限，默认 8192 MiB，0 为关闭。调整时用部署的 JDK 和代表性 APK 实测 |

`GET /readyz` 的 `workers` 字段报告可用解析容器数。一台离线时，API 仍将请求发往可用的容器。

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
| `APK_LENS_SERVICE_WORKER_CPU_SECONDS` | 本机模式下的单进程 CPU 时间上限 |
| `APK_LENS_SERVICE_WORKER_MAX_FILE_MIB` | 本机模式下的单文件大小上限 |
| `APK_LENS_SERVICE_WORKER_ADDRESS_SPACE_MIB` | 单进程虚拟地址空间上限，按系统支持启用，建议在 Linux 上调试 |

本机模式下三个 `APK_LENS_SERVICE_WORKER_*` 进程限制的默认值均为 0（关闭）。

运行测试使用 `uv run pytest -q`。
