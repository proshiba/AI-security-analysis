FROM python:3.13-slim

ARG CRYPTOGRAPHY_VERSION=46.0.7
ARG PYTEST_VERSION=8.4.1

RUN groupadd --gid 10001 emulator \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent emulator \
    && python -m pip install --no-cache-dir \
        "cryptography==${CRYPTOGRAPHY_VERSION}" \
        "pytest==${PYTEST_VERSION}"

WORKDIR /opt/valleyrat-emulator

COPY --chown=10001:10001 analysis-framework/ ./analysis-framework/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

USER 10001:10001

CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "analysis-framework/tests/test_valleyrat_n520_host_emulator.py", "analysis-framework/tests/test_valleyrat_n520_offline_loopback_contract.py"]
