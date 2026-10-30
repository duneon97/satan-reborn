# DO NOT BUILD: deliberately insecure, offline-scanned demo fixture.
FROM python:3.10-slim
WORKDIR /haunted
COPY . .
RUN chmod 777 /haunted
RUN curl https://example.invalid/FAKE-install.sh | sh
# Missing USER intentionally leaves this image running as root.
CMD ["python", "app.py"]
