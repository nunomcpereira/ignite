# Ignite, self-contained: the app plus every optional external tool it soft-
# depends on (see README's "External tools" table / scripts/install-tools.sh
# for the same list installed natively). Nothing here is required - Ignite
# runs and soft-skips to a fallback with none of it - this image just saves
# reproducing that install tax by hand.
#
# Build-time ARGs (default to installing everything) let you slim the image:
#   docker build --build-arg INSTALL_ORT=false --build-arg INSTALL_GOCLOC=false .
# ORT (JVM, ~700MB with its JRE) and the Go/JVM toolchains used only to fetch
# static binaries below are the biggest single contributors to image size.
FROM node:24-bookworm-slim

ARG TARGETARCH
ARG INSTALL_TRIVY=true
ARG INSTALL_CHECKOV=true
ARG INSTALL_HADOLINT=true
ARG INSTALL_GITLEAKS=true
ARG INSTALL_SYFT=true
ARG INSTALL_COSIGN=true
ARG INSTALL_SEMGREP=true
ARG INSTALL_BEARER=true
ARG INSTALL_GUARDDOG=true
ARG INSTALL_CODEQL=true
ARG INSTALL_JSCPD=true
ARG INSTALL_GOCLOC=true
ARG INSTALL_SPECTRAL=true
ARG INSTALL_LICENSEE=true
ARG INSTALL_ORT=true
ARG INSTALL_ACT=true
ARG INSTALL_GH=true
ARG INSTALL_DOCKER_CLI=true
# GID of the `docker` group inside the container, so the non-root app user
# can read the bind-mounted host /var/run/docker.sock (needed for Phase 5's
# `act` runs and the multi-language unit-test runner, both of which shell
# out to `docker`). Linux hosts: match your host's `stat -c '%g'
# /var/run/docker.sock` if Phase 5 reports a permission error at runtime -
# docker-compose.yml's `group_add` does this for you already. Docker
# Desktop (macOS/Windows) sockets are typically reachable regardless.
ARG DOCKER_GID=999
ARG ORT_VERSION=91.1.0

# pipx defaults to installing under $HOME (/root at this point in the build,
# readable only by root) - point it at a shared, world-readable location up
# front so checkov/semgrep/guarddog's symlinks still resolve once the final
# USER switches to the non-root ignite account below.
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/opt/pipx/bin
ENV PATH="/opt/pipx/bin:${PATH}"

# git/gh/act shell out to these; ca-certificates+gnupg for the various
# curl|install-script tools below; python3-pip/pipx for checkov/semgrep/
# guarddog; ruby+build deps for the licensee gem's native extension;
# libgit2-dev+pkg-config back guarddog's pygit2 dependency if no prebuilt
# wheel matches this platform. (The JRE ORT needs is installed separately
# below - Debian bookworm's default-jre-headless (OpenJDK 17) is too old:
# ORT 91.1.0's classes are compiled for class file version 69, i.e. JRE 25.)
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates gnupg git unzip cmake \
      python3 python3-pip python3-venv pipx \
      ruby-full build-essential libicu-dev zlib1g-dev \
      libgit2-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# JRE 25 for ORT (see note above) - Adoptium's versioned release URL, not
# their apt repo (which targets Ubuntu, not this Debian bookworm base).
ARG ADOPTIUM_JRE_VERSION=25.0.4_7
ARG ADOPTIUM_JRE_TAG=jdk-25.0.4%2B7
RUN if [ "$INSTALL_ORT" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo aarch64 || echo x64)"; \
      curl -fsSL "https://github.com/adoptium/temurin25-binaries/releases/download/${ADOPTIUM_JRE_TAG}/OpenJDK25U-jre_${arch}_linux_hotspot_${ADOPTIUM_JRE_VERSION}.tar.gz" \
      | tar xz -C /opt \
      && mv /opt/jdk-25* /opt/jre-25 \
      && ln -s /opt/jre-25/bin/java /usr/local/bin/java; \
    fi

# --- IaC / container misconfig -------------------------------------------
RUN if [ "$INSTALL_TRIVY" = "true" ]; then \
      curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin; \
    fi
RUN if [ "$INSTALL_CHECKOV" = "true" ]; then pipx install checkov && pipx ensurepath; fi
RUN if [ "$INSTALL_HADOLINT" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x86_64)"; \
      curl -fsSL -o /usr/local/bin/hadolint \
        "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-linux-${arch}" \
      && chmod +x /usr/local/bin/hadolint; \
    fi

# --- Secrets / supply chain / SAST ----------------------------------------
RUN if [ "$INSTALL_GITLEAKS" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)"; \
      ver="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep -m1 '"tag_name"' | cut -d'"' -f4 | tr -d v)"; \
      curl -fsSL "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_${ver}_linux_${arch}.tar.gz" \
        | tar xz -C /usr/local/bin gitleaks; \
    fi
RUN if [ "$INSTALL_SYFT" = "true" ]; then \
      curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin; \
    fi
RUN if [ "$INSTALL_COSIGN" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo amd64)"; \
      curl -fsSL -o /usr/local/bin/cosign \
        "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-${arch}" \
      && chmod +x /usr/local/bin/cosign; \
    fi
RUN if [ "$INSTALL_SEMGREP" = "true" ]; then pipx install semgrep && pipx ensurepath; fi
RUN if [ "$INSTALL_BEARER" = "true" ]; then \
      curl -fsSL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin; \
    fi
RUN if [ "$INSTALL_GUARDDOG" = "true" ]; then pipx install guarddog && pipx ensurepath; fi
# GitHub only ships an x86_64 ("linux64") CodeQL CLI build for Linux - no
# native arm64 release exists (confirmed against the actual release asset
# list, not assumed). On an arm64 build host (Apple Silicon's Docker
# Desktop building for its own platform, the common case) that bundle's own
# Java runtime silently can't run - a broken `codeql` on PATH that fails at
# scan time, not build time. Soft-skip instead, same as Ignite treats any
# other missing optional tool: install it on amd64, skip with a clear
# reason on arm64 (`docker compose build --platform linux/amd64` emulates
# amd64 via Rosetta/QEMU if you need CodeQL on an Apple Silicon host).
RUN if [ "$INSTALL_CODEQL" = "true" ]; then \
      if [ "$TARGETARCH" = "arm64" ]; then \
        echo "Skipping CodeQL install: no native linux/arm64 CLI build exists upstream (see github/codeql-cli-binaries releases). Build with --platform linux/amd64 to get CodeQL via emulation, or leave it disabled on this platform." >&2; \
      else \
        curl -fsSL -o /tmp/codeql.zip \
          "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip" \
        && unzip -q /tmp/codeql.zip -d /opt \
        && ln -s /opt/codeql/codeql /usr/local/bin/codeql && rm /tmp/codeql.zip; \
      fi; \
    fi

# --- Code metrics / API schema (npm-based) --------------------------------
RUN if [ "$INSTALL_JSCPD" = "true" ]; then npm install -g jscpd; fi
RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
RUN if [ "$INSTALL_GOCLOC" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x86_64)"; \
      curl -fsSL -o /tmp/gocloc.tar.gz \
        "https://github.com/hhatto/gocloc/releases/latest/download/gocloc_Linux_${arch}.tar.gz" \
      && tar xzf /tmp/gocloc.tar.gz -C /usr/local/bin gocloc && rm /tmp/gocloc.tar.gz; \
    fi

# --- License compliance ---------------------------------------------------
RUN if [ "$INSTALL_LICENSEE" = "true" ]; then gem install licensee; fi
RUN if [ "$INSTALL_ORT" = "true" ]; then \
      curl -fsSL -o /tmp/ort.tgz \
        "https://github.com/oss-review-toolkit/ort/releases/download/${ORT_VERSION}/ort-${ORT_VERSION}.tgz" \
      && mkdir -p /opt/ort && tar xzf /tmp/ort.tgz -C /opt/ort --strip-components=1 \
      && ln -s /opt/ort/bin/ort /usr/local/bin/ort && rm /tmp/ort.tgz; \
    fi

# --- Phase 5 org governance CI (act) - talks to the *host* Docker daemon via
# the socket docker-compose.yml mounts in, not a nested Docker-in-Docker ---
RUN if [ "$INSTALL_ACT" = "true" ]; then \
      curl -fsSL https://raw.githubusercontent.com/nektos/act/master/install.sh \
        | sh -s -- -b /usr/local/bin; \
    fi
ARG DOCKER_CLI_VERSION=27.3.1
RUN if [ "$INSTALL_DOCKER_CLI" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo aarch64 || echo x86_64)"; \
      curl -fsSL "https://download.docker.com/linux/static/stable/${arch}/docker-${DOCKER_CLI_VERSION}.tgz" \
        | tar xz -C /usr/local/bin --strip-components=1 docker/docker; \
    fi
RUN if [ "$INSTALL_GH" = "true" ]; then \
      arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo amd64)"; \
      ver="$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | grep -m1 '"tag_name"' | cut -d'"' -f4)"; \
      test -n "$ver"; \
      mkdir -p /tmp/gh && curl -fsSL -o /tmp/gh.tar.gz \
        "https://github.com/cli/cli/releases/download/${ver}/gh_${ver#v}_linux_${arch}.tar.gz" \
      && tar xzf /tmp/gh.tar.gz -C /tmp/gh \
      && find /tmp/gh -name gh -type f -exec cp {} /usr/local/bin/gh \; \
      && chmod +x /usr/local/bin/gh && rm -rf /tmp/gh /tmp/gh.tar.gz; \
    fi

# Non-root app user. Added to a `docker` group at the configured GID so it
# can use the bind-mounted host socket without running as root.
# guarddog writes a package-popularity cache file into its own installed
# package directory at scan time (rather than a user cache dir) - o+rwX,
# not just o+rX, so that write doesn't hit a permission error at runtime.
RUN chmod -R o+rwX /opt/pipx \
    && groupadd -g "${DOCKER_GID}" docker \
    && groupadd -g 10001 ignite \
    && useradd -m -u 10001 -g 10001 -G docker -s /bin/bash ignite

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY . .
# /app/data is where docker-compose.yml points IGNITE_DB_PATH and mounts a
# named volume - created+owned here so the volume inherits that ownership
# the first time Docker populates it (mounting over a path with no prior
# owned directory would land it root-owned, which the non-root user below
# can't write ignite.db into).
RUN mkdir -p /app/data && chown -R ignite:ignite /app

USER ignite
ENV PATH="/home/ignite/.local/bin:${PATH}"
ENV NODE_ENV=production
EXPOSE 51337 51338
CMD ["node", "server.js"]
