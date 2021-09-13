FROM python:3.8-alpine

RUN apk upgrade --no-cache
RUN apk add --no-cache rust cargo openssl-dev libffi-dev py3-pip python3 samba-client samba-common-tools yaml-dev
RUN apk add --no-cache --virtual build-dependencies build-base git \
  && git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git \
  && pip install --no-cache-dir -r enum4linux-ng/requirements.txt \
  && apk del build-dependencies
WORKDIR enum4linux-ng
ENTRYPOINT ["python", "enum4linux-ng.py"]
