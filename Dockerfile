FROM python:3.6-alpine3.11

RUN apk upgrade
RUN apk --update add --no-cache py3-impacket py3-pyldap py3-yaml samba-common-tools python3 py3-requests py3-pip py3-lxml py3-requests openssl ca-certificates samba-client libffi-dev openssl-dev py3-cryptography
RUN apk --update add --virtual build-dependencies python3-dev build-base wget git \
  && git clone https://github.com/cddmp/enum4linux-ng.git
WORKDIR enum4linux-ng
RUN pip install impacket pyyaml
ENTRYPOINT ["python", "enum4linux-ng.py"]
