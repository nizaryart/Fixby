FROM python:3.13-slim-trixie@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50 AS build
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --require-hashes --target /deps -r requirements.txt

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:806765f9f0863a1f36ce5f796983fed4eced9ec367e67e2f62f57f3e325c60b6
WORKDIR /srv
ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULNTRACK_DB=/data/vulntrack.db
COPY --from=build /deps /deps
COPY app/__init__.py app/cvss.py app/main.py app/policy.py app/store.py /srv/app/
USER nonroot
EXPOSE 8000
ENTRYPOINT ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
