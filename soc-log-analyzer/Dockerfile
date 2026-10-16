# SOC Log Analyzer - optional container image.
# The analyzer needs no third-party packages and no network access.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 analyzer \
    && mkdir /reports \
    && chown analyzer /reports

WORKDIR /app
COPY src/ ./src/
COPY config/ ./config/
COPY logs/sample_auth.csv ./logs/sample_auth.csv

USER analyzer

# Mount your log read-only at /data and a writable folder at /reports:
#   docker run --rm -v <logs>:/data:ro -v <reports>:/reports soc-log-analyzer \
#       analyze --input /data/sample_auth.csv --output /reports
ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]
