FROM python:3.11-slim
WORKDIR /app
RUN pip install redis mcp requests
COPY . /app/
CMD ["python", "-u", "main_agent.py"]