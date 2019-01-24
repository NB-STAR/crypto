FROM ubuntu:16.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pycrypto

WORKDIR /home/ctf

COPY ./bin /home/ctf
COPY ./run.sh /run.sh

RUN chmod +x /run.sh

CMD ["/run.sh"]
