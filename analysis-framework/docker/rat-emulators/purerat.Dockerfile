FROM python:3.13-slim

ARG PYTEST_VERSION=8.4.1

RUN groupadd --gid 10001 emulator \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent emulator \
    && python -m pip install --no-cache-dir "pytest==${PYTEST_VERSION}"

WORKDIR /opt/purerat-emulator

COPY --chown=10001:10001 emulators/ ./emulators/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

USER 10001:10001

CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "emulators/purehvnc/tests/test_observer.py"]
