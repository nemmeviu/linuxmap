FROM ansible/ansible:fedora27py3

RUN mkdir /opt/linuxmap
WORKDIR /opt/linuxmap

COPY requirements.txt /opt/linuxmap/requirements.txt
RUN set -ex; \
	pip3 install -r requirements.txt

COPY linux_to_es.py /opt/winmap/linux_to_es.py
