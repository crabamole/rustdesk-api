# Example only; not a supported product.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY receiver.py .
USER 1000
EXPOSE 8080
CMD ["python3", "receiver.py"]
