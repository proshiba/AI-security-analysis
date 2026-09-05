FROM python:3.13-slim

# 検体はイメージへ含めず、実行時に読み取り専用で渡します。
COPY analysis-framework/requirements.txt /opt/analysis-requirements.txt
RUN python -m pip install --no-cache-dir -r /opt/analysis-requirements.txt pytest==8.4.1 \
    && groupadd --gid 10001 analyst \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent analyst

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=0
WORKDIR /analysis
USER 10001:10001
CMD ["python", "-B", "analysis-framework/common/analysis_job_runner.py", "--help"]
