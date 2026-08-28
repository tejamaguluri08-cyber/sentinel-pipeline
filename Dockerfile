FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY policy ./policy
COPY templates ./templates
COPY sample_data ./sample_data

ENV PYTHONPATH=/app/src

# Create a non-root runtime user
RUN useradd --create-home --shell /usr/sbin/nologin sentinel \
    && chown -R sentinel:sentinel /app

USER sentinel

# CLI container health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import sentinel; print('Sentinel healthy')" || exit 1

ENTRYPOINT ["python", "-m", "sentinel"]
CMD ["scan", "--input", "sample_data/findings.json", "--output", "reports"]