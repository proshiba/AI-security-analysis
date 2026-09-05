FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

ARG CRYPTOGRAPHY_VERSION=46.0.7
ARG GEOIP2_VERSION=5.3.0

RUN groupadd --gid 10001 emulator \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent emulator \
    && python -m pip install --no-cache-dir \
        "cryptography==${CRYPTOGRAPHY_VERSION}" \
        "geoip2==${GEOIP2_VERSION}"

WORKDIR /opt/winos-external-observer

COPY --chown=10001:10001 analysis-framework/ ./analysis-framework/
COPY --chown=10001:10001 analysis-results/ ./analysis-results/
COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/winos_external_observer_entrypoint.py ./winos_external_observer_entrypoint.py
COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/purerat_long_running_observer.py ./purerat_long_running_observer.py
COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/observer_status.py ./observer_status.py
COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/winos-external-c2-protocol-profiles.json ./analysis-framework/common/c2_protocol_probe_profiles.json
COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/winos-external-rat-emulator-profiles.json ./analysis-framework/common/rat_emulator_profiles.json
COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/winos-external-rat-emulator-live-leases.json ./analysis-framework/common/rat_emulator_live_leases.json

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

USER 10001:10001

CMD ["python", "-B", "/opt/winos-external-observer/winos_external_observer_entrypoint.py", "preflight", "--profile-id", "valleyrat-winos-heartbeat-20260810-64-81-30-192-6666"]
