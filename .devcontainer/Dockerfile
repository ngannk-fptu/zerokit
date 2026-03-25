FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install uv for the Python workspace bootstrap.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && install -m 0755 /root/.local/bin/uv /usr/local/bin/uv \
    && install -m 0755 /root/.local/bin/uvx /usr/local/bin/uvx

# Install Bun for plugin/package workflows used by OpenCode plugins.
RUN curl -fsSL https://bun.sh/install | bash \
    && install -m 0755 /root/.bun/bin/bun /usr/local/bin/bun \
    && install -m 0755 /root/.bun/bin/bunx /usr/local/bin/bunx

# Security tools used by the repo harness and tests.
ARG GITLEAKS_VERSION=8.30.0
RUN pip install --no-cache-dir semgrep \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /tmp gitleaks \
    && install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks

# Install OpenCode and copy the resolved binary into a global PATH location.
RUN curl -fsSL https://opencode.ai/install | bash \
    && OPENCODE_BIN="$(find /root -type f -path '*/bin/opencode' | head -n 1)" \
    && test -n "${OPENCODE_BIN}" \
    && install -m 0755 "${OPENCODE_BIN}" /usr/local/bin/opencode
