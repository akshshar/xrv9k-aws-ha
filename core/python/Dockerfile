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

COPY src/genpy /genpy
COPY supervisord.conf /etc/supervisord.conf
COPY show /root/.local/bin/show

RUN apt-get update && apt-get install -y redis-server jq && \
    apt-get clean
WORKDIR app
ENV PATH=/root/.local/bin:$PATH

# Open the port
EXPOSE  6379:6379
ENTRYPOINT  supervisord -c /etc/supervisord.conf -n
