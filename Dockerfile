FROM python:3.8-slim 

RUN apt-get update && apt-get install -y vim iputils-ping curl iproute2 && \
     python3 -m pip install grpcio  grpcio-tools boto3 requests
