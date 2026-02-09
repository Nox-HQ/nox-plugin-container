# Bad Dockerfile -- deliberately contains multiple security issues for testing.

FROM ubuntu

RUN apt-get update && apt-get install -y curl wget python3

EXPOSE 22 80 443 3389

ENV DB_PASSWORD=supersecret123
ENV API_SECRET_KEY=sk-fake-key-12345

ADD app.tar.gz /opt/app/
ADD https://example.com/install.sh /tmp/install.sh

COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa

RUN curl -sSL https://example.com/setup.sh | bash

RUN chmod 777 /app/data

RUN sudo apt-get install -y nginx

WORKDIR /app
CMD ["python3", "app.py"]
