#!/usr/bin/env bash
# Generate an SPDX SBOM for the air-gapped install bundle (#2561).
#
# Usage: scripts/release/generate-bundle-sbom.sh <bundle.tar.gz>
#
# Writes <bundle.tar.gz>.spdx.json next to the tarball, plus a .sha256 for it
# in the same `sha256sum -c` format as the tarball's own .sha256. Needs `syft`
# and `jq`; set SYFT to the syft binary's path when it is not on PATH (the CI
# download action returns a path). The release's sign-release job signs the
# SBOM like every other release file.
#
# syft scans the unpacked bundle as a directory. What it lists:
#   - every .deb under apt/ (name, version and arch from its control file);
#   - the Go modules linked into each Go binary under bin/.
# What it does not look inside: the toolchain tarballs under toolchains/
# (named by version), the sidecar image tars under sidecars/ (each image
# carries its own SBOM on GHCR) and the actions-runner tarball. Those are
# listed file by file in the bundle's CHECKSUMS.sha256.
# hacks/offline-install/docs/VERIFY.md tells users the same.
set -euo pipefail

tarball="${1:?usage: generate-bundle-sbom.sh <bundle.tar.gz>}"
syft_bin="${SYFT:-syft}"
command -v "$syft_bin" >/dev/null || { echo "syft not found ($syft_bin); set SYFT or put it on PATH" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq not found on PATH" >&2; exit 2; }
[ -f "$tarball" ] || { echo "$tarball not found: build the bundle first" >&2; exit 2; }

name="$(basename "$tarball" .tar.gz)"            # containarium-bundle-<tag>-<os>-<arch>
version="${name#containarium-bundle-}"
version="${version%-*-*}"                         # <tag>

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$tarball" -C "$work"

out="$tarball.spdx.json"
"$syft_bin" scan "dir:$work" --source-name containarium-bundle --source-version "$version" \
  -o "spdx-json=$out" -q

# A valid SPDX document that lost the .debs or the Go binaries would be
# published and read as a clean result, so check both made it in.
purls() { jq --arg p "$1" '[.packages[].externalRefs[]? | select(.referenceType == "purl")
  | .referenceLocator | select(startswith($p))] | length' "$out"; }
deb_files="$(find "$work" -type f -name '*.deb' | wc -l)"
debs="$(purls pkg:deb/)"
gomods="$(purls pkg:golang/)"
jq -e '.spdxVersion != null' "$out" >/dev/null || { echo "::error::$out is not an SPDX document" >&2; exit 1; }
[ "$deb_files" -gt 0 ] || { echo "::error::$tarball contains no .deb files; the bundle layout changed" >&2; exit 1; }
[ "$debs" -ge "$deb_files" ] || { echo "::error::$out lists $debs deb packages for $deb_files .deb files" >&2; exit 1; }
[ "$gomods" -gt 0 ] || { echo "::error::$out lists no Go modules; the bundle's Go binaries were not read" >&2; exit 1; }

(cd "$(dirname "$out")" && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
echo "sbom: $(basename "$out") ($debs deb packages, $gomods Go modules, $(jq '.packages | length' "$out") packages in all)"
