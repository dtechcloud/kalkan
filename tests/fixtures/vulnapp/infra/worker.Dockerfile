FROM python:3.12.7-slim@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl=7.88.1-10+deb12u12 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/install.sh https://get.vulnapp.internal/install-1.4.2.sh \
    && echo "3f6c1f2d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f  /tmp/install.sh" | sha256sum -c - \
    && bash /tmp/install.sh \
    && rm /tmp/install.sh

RUN curl -fsSLo /tmp/agent.tar.gz https://downloads.vulnapp.internal/agent-1.4.2.tar.gz \
    && echo "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b  /tmp/agent.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/agent \
    && tar -xzf /tmp/agent.tar.gz -C /opt/agent \
    && rm /tmp/agent.tar.gz

COPY python/ /app/
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 app
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/')"]
CMD ["python", "-m", "flask", "--app", "shop.app", "run", "--host=0.0.0.0"]
