FROM python:latest

RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://get.vulnapp.internal/install.sh | sh
ADD https://downloads.vulnapp.internal/agent-1.4.2.tar.gz /opt/agent/
COPY python/ /app/
WORKDIR /app
RUN pip install -r requirements.txt
USER root
EXPOSE 8000
CMD ["python", "-m", "flask", "--app", "shop.app", "run", "--host=0.0.0.0"]
