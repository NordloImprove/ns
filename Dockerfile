FROM python:3.8

LABEL version="0.1"
LABEL maintainer=""

ENV DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

RUN apt update && apt install -y ca-certificates curl wget gnupg2 python3 python3-pip nmap && apt -y upgrade

ENV IS_CONTAINER=True
ENV LOG_LEVEL=INFO

ENV TZ=Europe/Stockholm
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Installing python modules
ADD requirements.txt /
RUN pip install -r requirements.txt

ADD src/ /app
ADD docker/nordscan /usr/local/bin/nordscan

# Create directory for configuration files
RUN mkdir /config

WORKDIR /app
ENTRYPOINT ["nordscan"]
