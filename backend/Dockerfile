FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Utente non privilegiato: un container che gira come root regala root a chiunque
# riesca a eseguire codice nel processo. L'app non scrive su disco (lo stato sta su
# DynamoDB/S3) e ascolta sulla 8000 > 1024, quindi root non serve.
RUN useradd --create-home --uid 1000 appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]