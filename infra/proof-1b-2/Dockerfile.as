# infra/proof-1b-2/Dockerfile.as — PROOF-ONLY emulated-external OAuth AS
FROM python:3.12-slim
RUN pip install --no-cache-dir "uvicorn[standard]>=0.35" "starlette>=0.40" "python-multipart>=0.0.9"
# python-multipart: the AS /token endpoint reads `await request.form()`; Starlette form parsing requires it
# (without it Bar 2 fails at the token POST). vendor exactly the one AS fixture file (build context = repo root)
COPY tests/integration/pack_loop/_local_as.py /app/_local_as.py
WORKDIR /app
EXPOSE 9000
CMD ["python", "_local_as.py"]
