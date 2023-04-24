# Copyright (c) 2022 Lenovo. All right reserved.
# Confidential and Proprietary
FROM harbor.lenovo.com/base/python:3.9.9-alpine3.14

ARG BASEDIR=/usr/src/

COPY ssh_exporter.py requirements.txt $BASEDIR
WORKDIR $BASEDIR

RUN sed -i 's#https://dl-cdn.alpinelinux.org#http://pip.lenovo.com//apk/repository/apk-ustc/#g' /etc/apk/repositories
RUN apk add --no-cache gcc freetds-dev libffi-dev libc-dev binutils make
RUN pip install -r requirements.txt --no-cache-dir -i http://pip.lenovo.com/repository/pypi-aliyun/simple/ --trusted-host pip.lenovo.com

EXPOSE 80

CMD ["python", "ssh_exporter.py"]
