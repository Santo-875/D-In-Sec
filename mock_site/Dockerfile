FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY mock_site/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt requests

COPY mock_site/ /app/mock_site/

ENV PYTHONPATH=/app/mock_site
ENV M3_API_URL=http://m3-sidecar:5001/api/v1/tree/update
ENV M3_BASE_URL=http://m3-sidecar:5001

EXPOSE 5000

CMD ["python", "mock_site/app.py"]
