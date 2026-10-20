#!/usr/bin/env bash
# Generate an SPDX SBOM for each Linux release binary and the agent-runtime
# bundle, and list them in SHA256SUMS.txt (#2561).
#
# Usage: scripts/release/generate-sboms.sh <release-dir>
#
# <release-dir> is where `make build-release` put the artifacts and wrote
# SHA256SUMS.txt (bin/ in CI). Needs `syft` and `jq`; set SYFT to the syft
# binary's path when it is not on PATH (the CI download action returns a path).
#
# One SBOM per distinct program, on linux/amd64: a Go binary embeds its module
# list, so syft reads the dependency set straight from the shipped file rather
# than from go.mod, and the darwin and windows builds of the same program link
# the same modules. The container images already carry their own SBOM
# (provenance + sbom in their build jobs).
#
# The agent-runtime bundle holds our compiled code, package.json and the
# lockfile; its npm packages are installed in the box by `npm ci --omit=dev`.
# syft reads the lockfile and, like that install, leaves dev dependencies out,
# so the SBOM lists what lands in the box. Run after `make bundle-agent-runtime`.
set -euo pipefail

dir="${1:?usage: generate-sboms.sh <release-dir>}"
syft_bin="${SYFT:-syft}"
command -v "$syft_bin" >/dev/null || { echo "syft not found ($syft_bin); set SYFT or put it on PATH" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq not found on PATH" >&2; exit 2; }
[ -f "$dir/SHA256SUMS.txt" ] || { echo "$dir/SHA256SUMS.txt not found: run make build-release first" >&2; exit 2; }

programs=(containariumd containarium mcp-server agent-box)
sboms=()
for p in "${programs[@]}"; do
  src="$dir/$p-linux-amd64"
  [ -f "$src" ] || { echo "::error::$src not found" >&2; exit 1; }
  out="$src.spdx.json"
  "$syft_bin" scan "file:$src" -o "spdx-json=$out" -q
  # An SBOM with no packages would be published and look like a clean result.
  jq -e '.spdxVersion != null and ((.packages | length) > 1)' "$out" >/dev/null \
    || { echo "::error::$out is not a usable SPDX document" >&2; exit 1; }
  echo "sbom: $(basename "$out") ($(jq '.packages | length' "$out") packages)"
  sboms+=("$(basename "$out")")
done

bundle="$dir/agent-runtime-bundle.tar.gz"
[ -f "$bundle" ] || { echo "::error::$bundle not found: run make bundle-agent-runtime first" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$bundle" -C "$work" package.json package-lock.json
out="$bundle.spdx.json"
"$syft_bin" scan "dir:$work" --source-name agent-runtime-bundle -o "spdx-json=$out" -q
# A lockfile syft could not read still yields a valid document with only the
# root package in it.
npm_pkgs="$(jq '[.packages[].externalRefs[]? | select(.referenceType == "purl")
  | .referenceLocator | select(startswith("pkg:npm/"))] | length' "$out")"
jq -e '.spdxVersion != null' "$out" >/dev/null && [ "$npm_pkgs" -gt 1 ] \
  || { echo "::error::$out lists $npm_pkgs npm packages; the lockfile was not read" >&2; exit 1; }
echo "sbom: $(basename "$out") ($npm_pkgs npm packages)"
sboms+=("$(basename "$out")")

# Same format build-release uses (`shasum -a 256 <file>`), appended so
# verifying the release's checksums also covers the SBOMs.
(cd "$dir" && shasum -a 256 "${sboms[@]}" >> SHA256SUMS.txt)
echo "listed ${#sboms[@]} SBOMs in $dir/SHA256SUMS.txt"
