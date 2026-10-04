#!/usr/bin/env bash
# Ignite - install all optional external tools in one shot, at their latest
# release, and upgrade the ones already installed.
#
# Every one of these is a soft dependency: Ignite works with none of them
# installed, falling back to a built-in check where one exists (see the
# README's "External tools" table). This script exists purely to save the
# fifteen-minutes-of-copy-pasting-brew-commands tax of turning every check
# on for real.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nunomcpereira/ignite/main/scripts/install-tools.sh | bash
#   # or, from a clone:
#   ./scripts/install-tools.sh
#
# Skip individual tools by setting their INSTALL_<TOOL>=false, e.g.:
#   INSTALL_GUARDDOG=false ./scripts/install-tools.sh
#
# Already-installed tools are upgraded to their latest release through the
# package manager that owns them (brew/pipx/npm/gem, or a fresh download for
# CodeQL and ORT). Set UPGRADE=false to only install what's missing. A tool
# installed some other way (e.g. a manual binary on PATH) is left alone.
#
# The Docker image pins exact versions instead; bump those with
# scripts/update-tool-versions.sh.
#
# macOS (Homebrew) is the primary target, matching the README's own install
# instructions exactly. On Linux, the Homebrew-only tools are skipped with a
# warning rather than guessed at; everything else (npm/pip/official release
# downloads) still works.
set -uo pipefail

BOLD='\033[1m'; DIM='\033[2m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
INSTALLED=(); UPGRADED=(); SKIPPED=(); FAILED=()

log_ok()   { echo -e "${GREEN}✓${RESET} $1"; }
log_skip() { echo -e "${DIM}·${RESET} $1"; }
log_warn() { echo -e "${YELLOW}⚠${RESET} $1"; }
log_fail() { echo -e "${RED}✗${RESET} $1"; }

OS="$(uname -s)"
UPGRADE="${UPGRADE:-true}"
HAS_BREW=false; command -v brew >/dev/null 2>&1 && HAS_BREW=true
HAS_NPM=false;  command -v npm  >/dev/null 2>&1 && HAS_NPM=true
HAS_PIP=false;  command -v pip3 >/dev/null 2>&1 && HAS_PIP=true
HAS_GEM=false;  command -v gem  >/dev/null 2>&1 && HAS_GEM=true

# install <flag-env-var> <already-installed-check-cmd> <label> <install-fn> [upgrade-fn]
#
# upgrade-fn returns 0 = upgraded or already latest, 1 = failed,
# 2 = not managed by a package manager this script knows (left alone).
install() {
  local flag="$1" check="$2" label="$3" fn="$4" upgrade_fn="${5:-}"
  local enabled="${!flag:-true}"
  if [ "$enabled" != "true" ]; then
    log_skip "$label - skipped ($flag=false)"; SKIPPED+=("$label"); return
  fi
  if eval "$check" >/dev/null 2>&1; then
    if [ "$UPGRADE" != "true" ] || [ -z "$upgrade_fn" ]; then
      log_skip "$label - already installed"; SKIPPED+=("$label"); return
    fi
    echo -e "${BOLD}Upgrading $label...${RESET}"
    eval "$upgrade_fn"
    case $? in
      0) log_ok "$label - latest"; UPGRADED+=("$label") ;;
      2) log_skip "$label - installed outside brew/pipx/npm/gem, left as is"; SKIPPED+=("$label") ;;
      *) log_fail "$label - upgrade failed, see output above"; FAILED+=("$label") ;;
    esac
    return
  fi
  echo -e "${BOLD}Installing $label...${RESET}"
  if eval "$fn"; then
    log_ok "$label"; INSTALLED+=("$label")
  else
    log_fail "$label - install failed, see output above"; FAILED+=("$label")
  fi
}

# --- package-manager helpers ----------------------------------------------
brew_install() {
  if ! $HAS_BREW; then log_warn "Homebrew not found - install from https://brew.sh, or install $* manually."; return 1; fi
  brew install "$@"
}
# brew_upgrade <formula> [binary]: upgrade only when brew owns the binary on PATH.
brew_upgrade() {
  local formula="$1" bin="${2:-$1}"
  $HAS_BREW || return 2
  brew list --formula "$formula" >/dev/null 2>&1 || return 2
  local path; path="$(command -v "$bin" 2>/dev/null)"
  case "$path" in "$(brew --prefix)"/*) ;; *) [ -n "$path" ] && return 2 ;; esac
  # `brew upgrade` exits non-zero when the formula is already current on some
  # brew versions; `brew outdated` decides whether there's anything to do.
  # Captured, not piped into `grep -q`: grep exiting early SIGPIPEs brew, and
  # under pipefail that reads as "not outdated".
  local outdated; outdated="$(brew outdated --formula --quiet "$formula" 2>/dev/null)"
  if [ -n "$outdated" ]; then
    brew upgrade "$formula"
  fi
}
ensure_pipx() {
  command -v pipx >/dev/null 2>&1 && return 0
  $HAS_BREW && brew install pipx && return 0
  $HAS_PIP && pip3 install --user pipx && python3 -m pipx ensurepath && return 0
  return 1
}
# pipx_install <package>: pipx first, `pip3 --user` as a last resort.
pipx_install() {
  if ensure_pipx; then
    pipx install "$1"
  elif $HAS_PIP; then
    pip3 install --user --break-system-packages "$1"
  else
    return 1
  fi
}
pipx_upgrade() {
  local pipx_pkgs=""
  command -v pipx >/dev/null 2>&1 && pipx_pkgs="$(pipx list --short 2>/dev/null | awk '{print $1}')"
  if printf '%s\n' "$pipx_pkgs" | grep -qx -- "$1"; then
    pipx upgrade "$1"
  elif $HAS_PIP && pip3 show "$1" >/dev/null 2>&1; then
    pip3 install --user --upgrade --break-system-packages "$1"
  else
    return 2
  fi
}
npm_install() { $HAS_NPM || { log_warn "npm not found - install Node.js first."; return 1; }; npm install -g "$1@latest"; }
npm_upgrade() {
  $HAS_NPM || return 2
  npm ls -g --depth=0 "$1" >/dev/null 2>&1 || return 2
  npm install -g "$1@latest"
}
# Latest release tag of a GitHub repo: gh when authenticated, else the REST API.
github_latest_tag() {
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh api "repos/$1/releases/latest" --jq .tag_name
  else
    curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
      | python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])'
  fi
}
# A user-writable bin dir on PATH-ish for symlinks.
link_dir() {
  local d
  for d in /opt/homebrew/bin /usr/local/bin; do [ -d "$d" ] && [ -w "$d" ] && { echo "$d"; return; }; done
  mkdir -p "$HOME/.local/bin" && echo "$HOME/.local/bin"
}

# --- GitHub CLI (Ignite's own clone/PR/push path, and ORT's download below) ---
install INSTALL_GH "command -v gh" "GitHub CLI (gh)" 'brew_install gh' 'brew_upgrade gh'

# --- IaC / container ---
install INSTALL_TRIVY    "command -v trivy"    "Trivy"    'brew_install trivy'    'brew_upgrade trivy'
install INSTALL_CHECKOV  "command -v checkov"  "Checkov"  'brew_install checkov'  'brew_upgrade checkov || pipx_upgrade checkov'
install INSTALL_HADOLINT "command -v hadolint" "hadolint" 'brew_install hadolint' 'brew_upgrade hadolint'

# --- Secrets / supply chain / SAST ---
install INSTALL_GITLEAKS "command -v gitleaks" "gitleaks" 'brew_install gitleaks' 'brew_upgrade gitleaks'
install INSTALL_SYFT     "command -v syft"     "Syft"     'brew_install syft'     'brew_upgrade syft'
install INSTALL_COSIGN   "command -v cosign"   "cosign"   'brew_install cosign'   'brew_upgrade cosign'
install INSTALL_SEMGREP  "command -v semgrep"  "Semgrep"  'brew_install semgrep'  'brew_upgrade semgrep || pipx_upgrade semgrep'
bearer_install() { $HAS_BREW || return 1; brew tap bearer/tap && brew install bearer/tap/bearer; }
install INSTALL_BEARER   "command -v bearer"   "Bearer"   bearer_install 'brew_upgrade bearer/tap/bearer bearer'

# ORT resolves CocoaPods projects using the `pod` CLI. Install it before ORT
# itself, otherwise the analyzer fails with `Cannot run program "pod"`.
install INSTALL_COCOAPODS "command -v pod" "CocoaPods" 'brew_install cocoapods' 'brew_upgrade cocoapods pod'

# --- GuardDog needs libgit2 (pygit2's build dependency) first ---
with_libgit2() {
  if $HAS_BREW; then
    brew list libgit2 >/dev/null 2>&1 || brew install libgit2 || return 1
    local lg; lg="$(brew --prefix libgit2)"
    CFLAGS="-I${lg}/include" LDFLAGS="-L${lg}/lib" PKG_CONFIG_PATH="${lg}/lib/pkgconfig" "$@"
  else
    "$@"
  fi
}
install INSTALL_GUARDDOG "command -v guarddog" "GuardDog" 'with_libgit2 pipx_install guarddog' 'with_libgit2 pipx_upgrade guarddog'

# --- AI-era: malicious model artifacts (picklescan) / API breaking-change diff (oasdiff) ---
install INSTALL_PICKLESCAN "command -v picklescan" "picklescan" 'pipx_install picklescan' 'pipx_upgrade picklescan'
install INSTALL_OASDIFF    "command -v oasdiff"    "oasdiff"    'brew_install oasdiff'    'brew_upgrade oasdiff'

# --- GitHub Actions workflow security (zizmor, Trail of Bits) ---
install INSTALL_ZIZMOR "command -v zizmor" "zizmor" 'pipx_install zizmor' 'pipx_upgrade zizmor'

# --- CodeQL (cross-file static analysis) - on by default in CONFIG. Not on
# Homebrew as a plain formula, so it's downloaded from GitHub's release.
codeql_install() {
  local platform
  case "$OS" in
    Darwin) platform="osx64" ;;
    Linux)  platform="linux64" ;;
    *) log_warn "No prebuilt CodeQL CLI for this platform - see https://github.com/github/codeql-cli-binaries"; return 1 ;;
  esac
  local dest="${CODEQL_INSTALL_DIR:-$HOME/.codeql}" tmp
  tmp="$(mktemp -d)" || return 1
  curl -fsSL -o "$tmp/codeql.zip" "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-${platform}.zip" || { rm -rf "$tmp"; return 1; }
  mkdir -p "$dest" && rm -rf "$dest/codeql" && unzip -q -o "$tmp/codeql.zip" -d "$dest" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  local bin; bin="$(link_dir)"
  ln -sf "$dest/codeql/codeql" "$bin/codeql"
  echo "CodeQL installed to $dest/codeql - ensure $bin is on PATH."
}
codeql_upgrade() {
  local current latest
  current="$(codeql version --format=terse 2>/dev/null)"
  latest="$(github_latest_tag github/codeql-cli-binaries 2>/dev/null)"; latest="${latest#v}"
  [ -n "$latest" ] || return 1
  [ "$current" = "$latest" ] && return 0
  echo "CodeQL $current -> $latest"
  codeql_install
}
install INSTALL_CODEQL "command -v codeql" "CodeQL" codeql_install codeql_upgrade

# --- ant + JDK for CodeQL's Java autobuild (when a repo isn't analysed with
# --build-mode=none): CodeQL shells out to the repo's build tool and javac.
ant_install() {
  brew_install ant || return 1
  command -v javac >/dev/null 2>&1 || log_warn "ant installed, but no javac on PATH - CodeQL's Java autobuild also needs a full JDK, not just a JRE (brew install openjdk)."
}
install INSTALL_ANT "command -v ant" "ant (CodeQL Java autobuild)" ant_install 'brew_upgrade ant'

# --- Code metrics / API schema ---
install INSTALL_JSCPD    "command -v jscpd"    "jscpd"    'npm_install jscpd'                   'npm_upgrade jscpd'
install INSTALL_GOCLOC   "command -v gocloc"   "gocloc"   'brew_install gocloc'                 'brew_upgrade gocloc'
install INSTALL_SPECTRAL "command -v spectral" "Spectral" 'npm_install @stoplight/spectral-cli' 'npm_upgrade @stoplight/spectral-cli'

# --- License compliance ---
ruby_gem() {
  local g
  for g in /opt/homebrew/opt/ruby/bin/gem /usr/local/opt/ruby/bin/gem; do [ -x "$g" ] && { echo "$g"; return; }; done
  command -v gem
}
licensee_install() {
  if $HAS_BREW; then
    brew list ruby >/dev/null 2>&1 || brew install ruby || return 1
    "$(ruby_gem)" install licensee || return 1
    local candidate
    for candidate in /opt/homebrew/lib/ruby/gems/*/bin/licensee /usr/local/lib/ruby/gems/*/bin/licensee; do
      [ -x "$candidate" ] && ln -sf "$candidate" "$(brew --prefix)/bin/licensee" && return 0
    done
    command -v licensee >/dev/null 2>&1
  elif $HAS_GEM; then
    gem install licensee
  else
    return 1
  fi
}
licensee_upgrade() {
  local g; g="$(ruby_gem)"
  [ -n "$g" ] && "$g" list -i licensee >/dev/null 2>&1 || return 2
  "$g" update licensee
}
install INSTALL_LICENSEE "command -v licensee" "licensee" licensee_install licensee_upgrade

# --- ORT (OSS Review Toolkit): not on Homebrew. Installed to ~/tools/ort-<ver>
# from the latest GitHub release, needs a JDK >= 21 on PATH.
ort_install() {
  if [ "$OS" != "Darwin" ] && [ "$OS" != "Linux" ]; then return 1; fi
  if ! command -v java >/dev/null 2>&1; then
    log_warn "ORT requires a JDK; installing OpenJDK now."
    brew_install openjdk || return 1
  fi
  local version="${ORT_VERSION:-$(github_latest_tag oss-review-toolkit/ort 2>/dev/null)}" dest="$HOME/tools"
  [ -n "$version" ] || { log_warn "Could not resolve ORT's latest release."; return 1; }
  mkdir -p "$dest" || return 1
  curl -fsSL -o "$dest/ort-${version}.tgz" \
    "https://github.com/oss-review-toolkit/ort/releases/download/${version}/ort-${version}.tgz" || return 1
  tar xzf "$dest/ort-${version}.tgz" -C "$dest" && rm -f "$dest/ort-${version}.tgz" || return 1
  ln -sf "$dest/ort-${version}/bin/ort" "$(link_dir)/ort"
  echo "ORT $version installed to $dest/ort-${version}."
}
ort_upgrade() {
  # Only ORT installs this script made (symlink into ~/tools/ort-<ver>) are managed.
  local target current latest
  target="$(readlink "$(command -v ort)" 2>/dev/null)"
  case "$target" in "$HOME"/tools/ort-*/bin/ort) ;; *) return 2 ;; esac
  current="${target#"$HOME"/tools/ort-}"; current="${current%/bin/ort}"
  latest="$(github_latest_tag oss-review-toolkit/ort 2>/dev/null)"
  [ -n "$latest" ] || return 1
  [ "$current" = "$latest" ] && return 0
  echo "ORT $current -> $latest (the old $HOME/tools/ort-$current is kept; remove it when done)"
  ORT_VERSION="$latest" ort_install
}
install INSTALL_ORT "command -v ort" "ORT (OSS Review Toolkit)" ort_install ort_upgrade

# --- Daily report PDF export (falls back to headless Chrome without it) ---
install INSTALL_WEASYPRINT "command -v weasyprint" "WeasyPrint" 'brew_install weasyprint' 'brew_upgrade weasyprint'

# --- act + Docker (Phase 5 governance CI). Docker Desktop needs a GUI
# install this script won't attempt for you.
install INSTALL_ACT "command -v act" "act" 'brew_install act' 'brew_upgrade act'
if command -v docker >/dev/null 2>&1; then
  log_skip "Docker - already installed (update it through Docker Desktop)"
else
  log_warn "Docker not found - Phase 5 (org governance CI) and the multi-language unit-test runner both need it. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
fi

echo ""
echo -e "${BOLD}Done.${RESET} ${GREEN}${#INSTALLED[@]} installed${RESET}, ${GREEN}${#UPGRADED[@]} upgraded/latest${RESET}, ${DIM}${#SKIPPED[@]} skipped${RESET}, ${RED}${#FAILED[@]} failed${RESET}."
if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "Failed: ${FAILED[*]}"
  echo "See the README's \"External tools\" section for manual install steps for any of these."
fi
echo ""
echo "Verify what Ignite itself sees: start the server and check the tools"
echo "panel in the UI, or curl http://localhost:51337/api/tools/status"
