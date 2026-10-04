#!/usr/bin/env bash
# Bump every external-tool version pinned in the Dockerfile to its latest
# upstream stable release.
#
# The Dockerfile pins each tool to an exact version (see the comment above
# its ARG block for why), so a rebuild never picks up a new release on its
# own. Run this, review the diff, rebuild with --no-cache, re-run a full
# self-scan, then commit.
#
# Usage:
#   ./scripts/update-tool-versions.sh            # rewrite Dockerfile in place
#   ./scripts/update-tool-versions.sh --check    # only report, exit 1 if outdated
#
# Needs curl and python3. Uses `gh api` for GitHub when available (higher
# rate limit), else the anonymous REST API (honours GITHUB_TOKEN/GH_TOKEN).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="${DOCKERFILE:-$ROOT/Dockerfile}"
CHECK_ONLY=false
[ "${1:-}" = "--check" ] && CHECK_ONLY=true

json_field() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval("d"+sys.argv[1]))' "$1"; }

github_latest() {
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh api "repos/$1/releases/latest" --jq .tag_name
  else
    local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    curl -fsSL ${token:+-H "Authorization: Bearer $token"} "https://api.github.com/repos/$1/releases/latest" | json_field '["tag_name"]'
  fi
}
pypi_latest()  { curl -fsSL "https://pypi.org/pypi/$1/json" | json_field '["info"]["version"]'; }
npm_latest()   { curl -fsSL "https://registry.npmjs.org/$1/latest" | json_field '["version"]'; }
gem_latest()   { curl -fsSL "https://rubygems.org/api/v1/versions/$1/latest.json" | json_field '["version"]'; }
docker_cli_latest() {
  curl -fsSL https://download.docker.com/linux/static/stable/x86_64/ \
    | grep -oE 'docker-[0-9]+\.[0-9]+\.[0-9]+\.tgz' | sed 's/docker-//; s/\.tgz//' | sort -V | tail -1
}

# ARG name -> how to resolve its latest version.
TOOLS=(
  "TRIVY_VERSION       github aquasecurity/trivy"
  "HADOLINT_VERSION    github hadolint/hadolint"
  "GITLEAKS_VERSION    github gitleaks/gitleaks"
  "SYFT_VERSION        github anchore/syft"
  "COSIGN_VERSION      github sigstore/cosign"
  "OASDIFF_VERSION     github oasdiff/oasdiff"
  "CODEQL_VERSION      github github/codeql-cli-binaries"
  "GOCLOC_VERSION      github hhatto/gocloc"
  "ACT_VERSION         github nektos/act"
  "GH_VERSION          github cli/cli"
  "BEARER_VERSION      github Bearer/bearer"
  "ORT_VERSION         github oss-review-toolkit/ort"
  "CHECKOV_VERSION     pypi   checkov"
  "SEMGREP_VERSION     pypi   semgrep"
  "GUARDDOG_VERSION    pypi   guarddog"
  "PICKLESCAN_VERSION  pypi   picklescan"
  "ZIZMOR_VERSION      pypi   zizmor"
  "JSCPD_VERSION       npm    jscpd"
  "SPECTRAL_VERSION    npm    @stoplight/spectral-cli"
  "LICENSEE_VERSION    gem    licensee"
  "COCOAPODS_VERSION   gem    cocoapods"
  "DOCKER_CLI_VERSION  docker -"
)

OUTDATED=0; FAILED=0
for entry in "${TOOLS[@]}"; do
  read -r arg source pkg <<<"$entry"
  current="$(grep -E "^ARG ${arg}=" "$DOCKERFILE" | head -1 | cut -d= -f2-)"
  if [ -z "$current" ]; then echo "?  $arg: no ARG in $DOCKERFILE"; FAILED=$((FAILED+1)); continue; fi
  case "$source" in
    github) latest="$(github_latest "$pkg" 2>/dev/null)" ;;
    pypi)   latest="$(pypi_latest "$pkg" 2>/dev/null)" ;;
    npm)    latest="$(npm_latest "$pkg" 2>/dev/null)" ;;
    gem)    latest="$(gem_latest "$pkg" 2>/dev/null)" ;;
    docker) latest="$(docker_cli_latest 2>/dev/null)" ;;
  esac
  if [ -z "${latest:-}" ]; then echo "!  $arg: could not resolve latest ($source $pkg)"; FAILED=$((FAILED+1)); continue; fi
  # Keep the pin's existing v-prefix convention (the download URLs depend on it).
  case "$current" in v*) latest="v${latest#v}" ;; *) latest="${latest#v}" ;; esac
  if [ "$current" = "$latest" ]; then
    echo "   $arg=$current"
  else
    echo "↑  $arg: $current -> $latest"
    OUTDATED=$((OUTDATED+1))
    $CHECK_ONLY || sed -i.bak -E "s|^ARG ${arg}=.*$|ARG ${arg}=${latest}|" "$DOCKERFILE"
  fi
done
rm -f "$DOCKERFILE.bak"

# Temurin JRE for ORT: version and tag move together.
jre_tag="$(github_latest adoptium/temurin25-binaries 2>/dev/null)"   # e.g. jdk-25.0.4.1+1
if [ -n "$jre_tag" ]; then
  jre_ver="$(echo "${jre_tag#jdk-}" | tr '+' '_')"                    # 25.0.4.1_1
  jre_url_tag="$(echo "$jre_tag" | sed 's/+/%2B/')"
  current_jre="$(grep -E '^ARG ADOPTIUM_JRE_VERSION=' "$DOCKERFILE" | cut -d= -f2-)"
  if [ "$current_jre" = "$jre_ver" ]; then
    echo "   ADOPTIUM_JRE_VERSION=$current_jre"
  else
    echo "↑  ADOPTIUM_JRE_VERSION: $current_jre -> $jre_ver"
    OUTDATED=$((OUTDATED+1))
    if ! $CHECK_ONLY; then
      sed -i.bak -E "s|^ARG ADOPTIUM_JRE_VERSION=.*$|ARG ADOPTIUM_JRE_VERSION=${jre_ver}|; s|^ARG ADOPTIUM_JRE_TAG=.*$|ARG ADOPTIUM_JRE_TAG=${jre_url_tag}|" "$DOCKERFILE"
      rm -f "$DOCKERFILE.bak"
    fi
  fi
else
  echo "!  ADOPTIUM_JRE_VERSION: could not resolve latest"; FAILED=$((FAILED+1))
fi

echo ""
if $CHECK_ONLY; then
  echo "$OUTDATED outdated, $FAILED unresolved."
  [ "$OUTDATED" -eq 0 ] || exit 1
else
  echo "$OUTDATED bumped, $FAILED unresolved. Next:"
  echo "  docker compose build --pull --no-cache && docker compose up -d"
  echo "  (then re-run a full self-scan before committing the Dockerfile)"
fi
[ "$FAILED" -eq 0 ] || exit 2
