#!/usr/bin/env bash
# Ignite - install all optional external tools in one shot.
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
# macOS (Homebrew) is the primary target, matching the README's own install
# instructions exactly. On Linux, the Homebrew-only tools (ORT, licensee,
# gocloc) are skipped with a link rather than guessed at; everything else
# (npm/pip/official install scripts) still works.
set -uo pipefail

BOLD='\033[1m'; DIM='\033[2m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
INSTALLED=(); SKIPPED=(); FAILED=()

log_ok()   { echo -e "${GREEN}✓${RESET} $1"; }
log_skip() { echo -e "${DIM}·${RESET} $1"; }
log_warn() { echo -e "${YELLOW}⚠${RESET} $1"; }
log_fail() { echo -e "${RED}✗${RESET} $1"; }

OS="$(uname -s)"
HAS_BREW=false; command -v brew >/dev/null 2>&1 && HAS_BREW=true
HAS_NPM=false;  command -v npm  >/dev/null 2>&1 && HAS_NPM=true
HAS_PIP=false;  command -v pip3 >/dev/null 2>&1 && HAS_PIP=true
HAS_GEM=false;  command -v gem  >/dev/null 2>&1 && HAS_GEM=true

# install <flag-env-var> <already-installed-check-cmd> <label> <install-fn>
install() {
  local flag="$1" check="$2" label="$3" fn="$4"
  local enabled="${!flag:-true}"
  if [ "$enabled" != "true" ]; then
    log_skip "$label - skipped ($flag=false)"; SKIPPED+=("$label"); return
  fi
  if eval "$check" >/dev/null 2>&1; then
    log_skip "$label - already installed"; SKIPPED+=("$label"); return
  fi
  echo -e "${BOLD}Installing $label...${RESET}"
  if "$fn"; then
    log_ok "$label"; INSTALLED+=("$label")
  else
    log_fail "$label - install failed, see output above"; FAILED+=("$label")
  fi
}

brew_install() {
  if ! $HAS_BREW; then log_warn "Homebrew not found - install from https://brew.sh, or install $1 manually."; return 1; fi
  brew install "$@"
}

# --- IaC / container ---
install INSTALL_TRIVY    "command -v trivy"    "Trivy"    'brew_install() { brew install trivy; }; brew_install'
install INSTALL_CHECKOV  "command -v checkov"  "Checkov"  'brew_install() { brew install checkov; }; brew_install'
install INSTALL_HADOLINT "command -v hadolint" "hadolint" 'brew_install() { brew install hadolint; }; brew_install'

# --- Secrets / supply chain / SAST ---
install INSTALL_GITLEAKS "command -v gitleaks" "gitleaks" 'brew_install() { brew install gitleaks; }; brew_install'
install INSTALL_SYFT     "command -v syft"     "Syft"     'brew_install() { brew install syft; }; brew_install'
install INSTALL_COSIGN   "command -v cosign"   "cosign"   'brew_install() { brew install cosign; }; brew_install'
install INSTALL_SEMGREP  "command -v semgrep"  "Semgrep"  'brew_install() { brew install semgrep; }; brew_install'
install INSTALL_BEARER   "command -v bearer"   "Bearer"   'bearer_install() { if ! $HAS_BREW; then return 1; fi; brew tap bearer/tap && brew install bearer/tap/bearer; }; bearer_install'

# --- GuardDog needs libgit2 (pygit2's build dependency) first ---
guarddog_install() {
  if $HAS_BREW; then
    brew list libgit2 >/dev/null 2>&1 || brew install libgit2 || return 1
    if ! command -v pipx >/dev/null 2>&1; then brew install pipx || return 1; fi
    LIBGIT2="$(brew --prefix libgit2)"
    CFLAGS="-I${LIBGIT2}/include" LDFLAGS="-L${LIBGIT2}/lib" PKG_CONFIG_PATH="${LIBGIT2}/lib/pkgconfig" \
      pipx install guarddog
  elif $HAS_PIP; then
    pip3 install --user guarddog
  else
    return 1
  fi
}
install INSTALL_GUARDDOG "command -v guarddog" "GuardDog" guarddog_install

# --- Code metrics / API schema (npm-based) ---
install INSTALL_JSCPD    "command -v jscpd"    "jscpd"    'jscpd_install() { $HAS_NPM && npm install -g jscpd; }; jscpd_install'
install INSTALL_GOCLOC   "command -v gocloc"   "gocloc"   'brew_install() { brew install gocloc; }; brew_install'
install INSTALL_SPECTRAL "command -v spectral" "Spectral" 'spectral_install() { $HAS_NPM && npm install -g @stoplight/spectral-cli; }; spectral_install'

# --- License compliance ---
licensee_install() {
  if $HAS_BREW; then
    brew list ruby >/dev/null 2>&1 || brew install ruby || return 1
    /opt/homebrew/opt/ruby/bin/gem install licensee || /usr/local/opt/ruby/bin/gem install licensee || return 1
    local gem_bin
    gem_bin="$(gem environment gemdir 2>/dev/null)/bin/licensee"
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
install INSTALL_LICENSEE "command -v licensee" "licensee" licensee_install

ort_install() {
  if [ "$OS" != "Darwin" ] && [ "$OS" != "Linux" ]; then return 1; fi
  command -v gh >/dev/null 2>&1 || { log_warn "ORT needs the gh CLI to download its release archive."; return 1; }
  local version="91.1.0" dest="$HOME/tools"
  mkdir -p "$dest" && cd "$dest" || return 1
  gh release download "$version" -R oss-review-toolkit/ort -p "ort-${version}.tgz" --clobber || return 1
  tar xzf "ort-${version}.tgz" || return 1
  local link_dir="/opt/homebrew/bin"; [ -d "$link_dir" ] || link_dir="/usr/local/bin"
  ln -sf "$dest/ort-${version}/bin/ort" "$link_dir/ort"
  command -v ort >/dev/null 2>&1
}
install INSTALL_ORT "command -v ort" "ORT (OSS Review Toolkit)" ort_install

# --- act + Docker (Phase 5 governance CI) - checked, not force-installed:
# Docker Desktop needs a GUI install this script won't attempt for you.
if command -v act >/dev/null 2>&1; then
  log_skip "act - already installed"; SKIPPED+=("act")
else
  install INSTALL_ACT "command -v act" "act" 'brew_install() { brew install act; }; brew_install'
fi
if command -v docker >/dev/null 2>&1; then
  log_skip "Docker - already installed"
else
  log_warn "Docker not found - Phase 5 (org governance CI) and the multi-language unit-test runner both need it. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
fi

echo ""
echo -e "${BOLD}Done.${RESET} ${GREEN}${#INSTALLED[@]} installed${RESET}, ${DIM}${#SKIPPED[@]} already present/skipped${RESET}, ${RED}${#FAILED[@]} failed${RESET}."
if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "Failed: ${FAILED[*]}"
  echo "See the README's \"External tools\" section for manual install steps for any of these."
fi
echo ""
echo "Verify what Ignite itself sees: start the server (npm start) and check the"
echo "tools panel in the UI, or curl http://localhost:3000/api/tools/status"
