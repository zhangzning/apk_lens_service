#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-$repo/dist}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"

revision="$(git -C "$repo" rev-parse --short=12 HEAD)"
if [[ -n "$(git -C "$repo" status --porcelain)" ]]; then
  revision="$revision-dirty"
fi
api_image="apk-lens-service:api-$revision"
worker_image="apk-lens-service:worker-$revision"

APK_LENS_SERVICE_TOKEN=compose-build-only APK_LENS_API_IMAGE="$api_image" APK_LENS_WORKER_IMAGE="$worker_image" \
  docker compose --env-file /dev/null -f "$repo/compose.yaml" build api worker-1

image_platform() {
  docker image inspect --format '{{.Os}}-{{.Architecture}}' "$1"
}
platform="$(image_platform "$api_image")"
if [[ "$platform" != linux-* || "$platform" != "$(image_platform "$worker_image")" ]]; then
  printf 'The API and worker images must share a Linux platform.\n' >&2
  exit 1
fi

bundle="apk-lens-service-$revision-$platform.tar.gz"
stage="$(mktemp -d "$output/.apk-lens-compose.XXXXXXXX")"
trap 'rm -r -- "$stage"' EXIT
cp "$repo/compose.yaml" "$repo/README.md" "$stage/"
printf 'APK_LENS_API_IMAGE=%s\nAPK_LENS_WORKER_IMAGE=%s\n' "$api_image" "$worker_image" > "$stage/images.env"
docker image save --output "$stage/images.tar" "$api_image" "$worker_image"
tar -czf "$stage/$bundle" -C "$stage" compose.yaml README.md images.env images.tar
mv -- "$stage/$bundle" "$output/$bundle"
printf 'Deployment bundle prepared at %s\n' "$output/$bundle"
