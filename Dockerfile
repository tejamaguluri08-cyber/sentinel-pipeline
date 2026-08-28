FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY policy ./policy
COPY templates ./templates
COPY sample_data ./sample_data
ENV PYTHONPATH=/app/src

ENTRYPOINT ["python", "-m", "sentinel"]
CMD ["scan", "--input", "sample_data/findings.json", "--output", "reports"]
