FROM python:3.11-slim

WORKDIR /app
COPY detector.py portal.py server.py ./
COPY ui/ ./ui/
USER 65534:65534
EXPOSE 8000

ENTRYPOINT ["python", "-B", "server.py", "--host", "0.0.0.0"]
CMD ["--port", "8000"]
