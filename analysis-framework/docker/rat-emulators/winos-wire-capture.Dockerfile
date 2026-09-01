FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libcap2-bin \
        tcpdump \
    && find /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin \
        -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && setcap cap_net_raw=eip /usr/bin/tcpdump \
    && getcap /usr/bin/tcpdump | grep -Fx '/usr/bin/tcpdump cap_net_raw=eip' \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 capture \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent capture

COPY --chown=10001:10001 analysis-framework/docker/rat-emulators/winos_wire_capture_entrypoint.py /opt/winos_wire_capture_entrypoint.py

USER 10001:10001

ENTRYPOINT ["python", "-B", "/opt/winos_wire_capture_entrypoint.py"]
