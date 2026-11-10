FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt \
 && python -m spacy download en_core_web_sm
COPY backend backend
COPY evaluation evaluation
COPY data data
WORKDIR /app/backend
ENV SID_DB_PATH=/app/storage/app.db
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
