FROM docker.io/library/python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS dependencies
WORKDIR /app
COPY requirements.lock /app/requirements.lock
COPY scripts/__init__.py scripts/install_dependencies.py /app/scripts/
RUN ["python", "-m", "scripts.install_dependencies"]
FROM dependencies AS runtime
COPY --chmod=755 bridge /app/bridge
COPY --chmod=755 mcp_bridge/*.py /app/mcp_bridge/
COPY --chmod=755 mcp_bridge/static /app/mcp_bridge/static
COPY --chmod=755 scripts /app/scripts
USER 1000:1000
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MALLOC_ARENA_MAX=1
ENTRYPOINT ["python", "-m", "mcp_bridge.main"]
FROM runtime AS tests
COPY --chmod=755 mcp_bridge/tests /app/mcp_bridge/tests
ENTRYPOINT ["python", "-m", "mcp_bridge.tests.run"]
