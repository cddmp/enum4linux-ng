FROM python:3.8-alpine3.12

RUN apk upgrade
RUN apk --update add --no-cache samba-common-tools python3 py3-pip samba-client libffi-dev openssl-dev
RUN apk --update add --virtual build-dependencies build-base git \
  && git clone https://github.com/cddmp/enum4linux-ng.git \
  && pip install -r enum4linux-ng/requirements.txt \
  && apk del build-dependencies
WORKDIR enum4linux-ng
ENTRYPOINT ["python", "enum4linux-ng.py"]
