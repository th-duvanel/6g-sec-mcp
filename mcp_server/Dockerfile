FROM python:3.11-slim
WORKDIR /app
RUN pip install mcp
COPY . /app/
CMD ["python", "server.py"]