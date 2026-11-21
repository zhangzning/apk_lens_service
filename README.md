# APK Lens Service

独立的 APK 静态解析 HTTP 服务。上传 APK 后可以获取包信息、Manifest 组件、权限和签名证书，也可以下载包含 JADX 反编译产物的 ZIP。支持同步与异步调用，无数据库依赖。

## 部署

在目标机安装 Linux Docker Engine、Compose V2，并启用 cgroup v2。默认包含一个 API 容器和两个独立解析容器。每个解析容器的内存上限为 4 GiB，API 容器的上限为 384 MiB，宿主机还需预留系统自身的内存。以下命令在 Bash 中执行。

### 从源码启动

```bash
git clone https://github.com/zhangzning/apk_lens_service.git
cd apk_lens_service
read -rsp 'APK Lens token ' APK_LENS_SERVICE_TOKEN
echo
export APK_LENS_SERVICE_TOKEN
docker compose up --build --wait --wait-timeout 90
curl -fsS http://127.0.0.1:18086/readyz
```

### 使用预构建部署包

`main` 的 Tests 工作流通过后，会在对应运行的 Artifacts 中提供 `apk-lens-service-linux-amd64`。从外层 ZIP 取出 `tar.gz`，在 Linux AMD64 目标机解包并导入镜像。部署目录只需包内文件，首次启动可离线完成。 [GitHub Actions](https://github.com/zhangzning/apk_lens_service/actions)

```bash
mkdir -p apk-lens-deploy
tar -xzf 'apk-lens-service-替换成提交号-linux-amd64.tar.gz' -C apk-lens-deploy
cd apk-lens-deploy
docker load --input images.tar
read -rsp 'APK Lens token ' APK_LENS_SERVICE_TOKEN
echo
export APK_LENS_SERVICE_TOKEN
docker compose --env-file images.env up --no-build --wait --wait-timeout 90
curl -fsS http://127.0.0.1:18086/readyz
```

也可在 Linux AMD64 或 ARM64 的构建机运行 `bash scripts/package-compose.sh`，默认打包到 `dist/`。包内包含 API 与 Worker 镜像、`compose.yaml`、镜像版本配置 `images.env` 和本文。目标机架构需与包名一致。

### 运行状态

`/healthz` 检查 API 进程，`/readyz` 检查是否有 Worker 可以接单。启动后预期 `workers.ready` 和 `workers.configured` 均为 2，`tools` 可确认 AAPT2、JADX、Java 和 readelf 是否可用。一个 Worker 离线时，API 会把请求发往另一台可用 Worker。查看状态用 `docker compose ps`，查看日志用 `docker compose logs -f api worker-1 worker-2`，停止用 `docker compose down`。部署包的 Compose 命令均加上 `--env-file images.env`。

API 默认只绑定宿主机 `127.0.0.1:18086`，对外接入可由 HTTPS 网关转发。令牌由部署环境注入，仅 API 容器持有。API 通过两个独立的 Unix 套接字转发请求，默认最多同时处理两个任务，其中最多一个深度解析。解析容器以非 root 用户运行，关闭网络并使用只读根文件系统。Docker 容器日志会轮转。

每个解析容器默认有 2 核 CPU 配额和 192 个任务槽位（含线程）。APK、JADX 缓存和解析产物工作区位于独立的 2 GiB `tmpfs`，计入容器内存。响应完成后清理请求临时目录。每个解析子进程另有 CPU 时间、虚拟地址空间和单文件大小限制。

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
| `APK_LENS_JOB_TTL_SECONDS` | 异步状态和结果的保留时间，默认在任务结束后保留 900 秒 |
| `APK_LENS_JOBS_STORAGE_MIB` | API 异步暂存空间的应用配额，默认 2048 MiB |

## 分析模式

| 模式 | 分析内容 | 默认输出 |
| --- | --- | --- |
| `basic` | 包名、版本、SDK、应用名称及各语言版本、图标、Manifest 权限和组件、文件统计、加壳线索 | JSON |
| `standard` | 基础信息、权限详情、签名方案与证书信息 | JSON |
| `deep` | 标准模式、JADX 反编译、Java 类与成员、资源清单、原生库及其导出符号 | ZIP |

基础解析使用 Androguard，可通过 Android SDK 的 `aapt2` 补充或降级读取。深度解析需要 `jadx` 和 Java。原生库导出符号需要 `readelf`、`llvm-readelf` 或 `greadelf`。工具可用性见 `GET /readyz`。

Androguard 读不到完整的 Manifest 时，服务用 AAPT2、ApkInspector 的二进制 XML 读取器和环境中的旧版 AAPT 回填组件和权限申请。超过常规读取上限的二进制 Manifest 优先分块读取，`manifest_components_source` 对应为 `axml_stream`。`permission_requests` 保留 `uses-permission`、`uses-permission-sdk-23` 和 `uses-permission-sdk-m` 标签及可读的 `maxSdkVersion`。完整声明仍未读全时，服务用 AAPT2 的权限摘要回填可核实的权限名，并保留 `partial` 状态。

权限模块以 Manifest 申请列表是否读全为完成标准，确认没有权限申请时返回空列表。解释无法核实时保留权限原名，`desc` 标为「未知」，`summary.unknown_description_count` 记录数量。补充的 AOSP 定义通过 `definition_reference` 和 `definition_api_level` 标出来源及版本。静态权限结果中的 `grant_state` 为 `not_checked`。签名证书独立于 Manifest 提取，Worker 镜像包含用于兜底的 `apksigner`。

## 同步调用

`POST /v1/analyze` 接收 APK 原始字节，默认使用 `standard`。正文使用 `application/vnd.android.package-archive` 或 `application/octet-stream`。配置访问令牌后，请求携带 `Authorization: Bearer <token>`。

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $APK_LENS_SERVICE_TOKEN" \
  -H 'Content-Type: application/vnd.android.package-archive' \
  --data-binary @sample.apk \
  'http://127.0.0.1:18086/v1/analyze?filename=sample.apk&profile=standard&output=json' \
  -o result.json
```

HTTP 200 表示返回了报告。报告的 `status=ok` 表示所有请求模块完整，`status=partial` 时可看 `modules.<模块>.status` 与模块告警。接口定义见 `/docs`。

默认返回 APK 条目数 `modules.basic.data.file_count`。传入 `include_file_tree=true` 后，JSON 或 ZIP 内的 `result.json` 会同时包含 `modules.basic.data.file_tree`，其值是按名称排序的 APK 内部路径列表。

应用显示名优先选择简体中文（中国），并在 `modules.basic.data.app_names` 中保留默认名称、通用中文、本地化名称及其来源。报告中的 `modules` 给出各模块的状态，可以区分完整结果与降级结果。

深度模式的 ZIP 包含 `result.json`、可用图标、`jadx/` 和 `reverse/`。若选择 JSON，则返回报告和分析摘要。

## 异步分析

长时间分析使用 `POST /v1/jobs`。它接收与同步接口相同的 APK 正文和分析选项，上传完就返回 `202`、任务 ID 和两个查询地址。提交完成后可关闭连接。

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $APK_LENS_SERVICE_TOKEN" \
  -H 'Content-Type: application/vnd.android.package-archive' \
  --data-binary @sample.apk \
  'http://127.0.0.1:18086/v1/jobs?profile=deep&output=zip' \
  -o job.json
```

通过响应的 `status_url` 查询 `queued`、`running`、`succeeded` 或 `failed`。成功后访问 `result_url` 下载结果。失败状态保留错误代码，任务仍未产出结果时下载接口返回 `409`。以下示例使用 `jq` 读取响应中的路径。

```sh
base_url='http://127.0.0.1:18086'
curl -fsS -H "Authorization: Bearer $APK_LENS_SERVICE_TOKEN" \
  "$base_url$(jq -r .status_url job.json)"
# 查询到 succeeded 后下载
curl -fsS -H "Authorization: Bearer $APK_LENS_SERVICE_TOKEN" \
  "$base_url$(jq -r .result_url job.json)" -o result.zip
```

相同 SHA256、模式、输出格式和文件树选项会复用排队中、运行中或仍在保留期内的成功任务。提交响应的 `reused` 标识复用。异步报告使用 `sample.apk` 作为输入文件名，允许相同内容以不同上传名复用。任务状态为 `succeeded` 表示产物已生成，报告内仍会标记模块是否为 `partial`。

解析期间 Worker 连接中断或暂时没有可用 Worker 时，任务最多重试一次。重试使用暂存的 APK 与原分析选项，优先选另一台可用 Worker。任务结束即清理源 APK，结果在保留期结束后清理。Compose 的异步暂存默认使用仅供 API 访问的磁盘卷 `api-jobs`。API 重启时清理上次的任务文件，旧任务返回 `404`，调用方需要重新提交。

异步解析与同步解析共用并发槽位。默认最多有 6 个未结束的异步任务（含正在上传和解析），最多保留 128 条任务记录。暂存空间需容纳各任务的 APK 和预留结果空间，达到上限时提交接口返回 `503`。

## 常见返回码

| HTTP | 排查项 |
| --- | --- |
| `401` | 检查 Bearer 令牌 |
| `413` | 检查上传大小、ZIP 展开体积、条目数或结果大小。默认上传上限 512 MiB，展开上限 1536 MiB，最多 50,000 条 ZIP 条目 |
| `415` | 检查 Content-Type 和请求正文是否为 APK 原始字节 |
| `422` | 检查错误码。常见原因有缺根 Manifest、ZIP 条目路径异常、APK 不可读或包身份未解析 |
| `503` | 检查并发槽位、异步暂存配额和 Worker 就绪状态。响应提供 `Retry-After` 时按该值重试 |

## 日志与指标

API 在每次 HTTP 响应的 `X-Request-ID` 中返回服务生成的请求 ID，解析 worker 沿用它。排查某次请求时，可在 API 与 worker 的 JSON 日志中搜索该 ID。`request_finished` 记录请求耗时、HTTP 状态、结果和错误代码，`stage_finished` 记录解析阶段的耗时、状态和错误代码。报告的 `attempts[].duration_ms` 也会返回阶段耗时。

`GET /metrics` 提供 Prometheus 文本指标。配置令牌时，采集请求同样携带 Bearer 令牌。Compose 部署只需采集 API 的端点，它会通过 Unix 套接字获取各 worker 的指标。

| 指标 | 内容 |
| --- | --- |
| `apk_lens_requests_total` | 按模式、HTTP 状态、结果与错误代码统计请求 |
| `apk_lens_request_duration_seconds` | 请求耗时分布，包含上传和响应传输 |
| `apk_lens_stages_total` | 按模式、阶段、状态与错误代码统计阶段执行 |
| `apk_lens_stage_duration_seconds` | 解析阶段耗时分布 |
| `apk_lens_active_jobs` | 当前全部任务与深度任务数 |
| `apk_lens_worker_up` | Compose 中各 worker 的指标端点是否可用 |

统计客户端请求时使用 `source="api"`，本机模式使用 `source="standalone"`。解析阶段在 Compose 中使用 `source="worker-1"`、`source="worker-2"`。计数器随对应进程重启而重置。请求 ID、文件名和令牌不作为指标标签。

需要在 Prometheus 或 Grafana 查看跨 worker 的阶段 P95 耗时时，可按模式和阶段汇总直方图。

```promql
histogram_quantile(0.95,
  sum by (profile, stage, le) (
    rate(apk_lens_stage_duration_seconds_bucket{source=~"worker-[0-9]+"}[5m])
  )
)
```

## 本机开发与配置

Linux 和 macOS 可以用 Python 3.12 或以上版本运行。此方式便于开发和调试，外部 Android 工具由本机提供。

```sh
uv sync --locked
uv run --locked apk-lens-service
```

也可用 `pip install .` 安装后运行 `apk-lens-service`。默认监听 `127.0.0.1:18086`。单个 HTTP 进程负责调度，各解析阶段在独立子进程运行。

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
| `APK_LENS_SERVICE_JOBS_DIR` | 私有异步暂存目录。本机默认在系统临时目录下按用户和端口建立 |
| `APK_LENS_SERVICE_JOB_TTL_SECONDS` | 完成后保留状态与结果的秒数，默认 900 |
| `APK_LENS_SERVICE_MAX_PENDING_JOBS` | 待完成任务上限，含上传中的任务，默认 6 |
| `APK_LENS_SERVICE_MAX_RETAINED_JOBS` | 暂存任务记录上限，默认 128 |
| `APK_LENS_SERVICE_JOBS_STORAGE_MIB` | 暂存空间应用配额，默认 2048 MiB |

本机模式下三个 `APK_LENS_SERVICE_WORKER_*` 进程限制的默认值均为 0（关闭）。

## 测试

```sh
uv run --locked pytest -q
python3 tests/compose_integration.py
```

第二条命令需要 Linux Docker Engine、cgroup v2 和 Compose V2。测试现场生成签名 APK，验证标准解析、日志关联、指标、容器隔离和资源限额，也验证 Worker 停止后的接单切换、在途任务重试、结果复用和自动恢复。测试结束后清理测试项目的容器、卷和镜像。
