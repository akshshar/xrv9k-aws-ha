FROM python:3.8-slim as builder

RUN apt-get update && \
    apt-get install -y gcc && \
    apt-get clean


COPY src/app /app
#COPY src/app/requirements.txt /app/requirements.txt
WORKDIR app
RUN python3 -m pip install --user -r requirements.txt

#python3 -m pip install rdbtools python-lzf grpcio grpcio-tools boto3 requests supervisor

FROM python:3.8.0-slim as app
COPY --from=builder /root/.local /root/.local
COPY --from=builder /app /app

RUN apt-get update && apt-get install -y redis-server jq procps && \
    apt-get clean

WORKDIR app
ENV PATH=/root/.local/bin:$PATH
COPY redis.conf /etc/redis/redis.conf
COPY src/genpy /genpy
COPY supervisord.conf /etc/supervisord.conf
COPY show /root/.local/bin/show

# Open the port
EXPOSE  6379:6379

CMD ["/usr/local/bin/python3", "/root/.local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
