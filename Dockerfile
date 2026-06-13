FROM python:3.12-slim

RUN useradd -m -u 1000 appuser && mkdir -p /app && chown appuser:appuser /app

WORKDIR /app

COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser app.py .
COPY --chown=appuser:appuser templates/ templates/
COPY --chown=appuser:appuser static/ static/

ENV PYTHONUNBUFFERED=1

EXPOSE 5055

USER appuser

CMD ["gunicorn", "--bind", "0.0.0.0:5055", "--workers", "1", "--threads", "4", "--access-logfile", "-", "app:app"]
