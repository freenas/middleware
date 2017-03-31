PREFIX ?= /usr/local
PYTHON ?= python

install:
	install etc/dscached ${PREFIX}/etc/rc.d/
	install sbin/dscached ${PREFIX}/sbin/
	install sbin/dscachectl ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/dscached
	install -d ${PREFIX}/lib/dscached/src
	install -d ${PREFIX}/lib/dscached/plugins
	cp -a src/ ${PREFIX}/lib/dscached/src/
	cp -a plugins/ ${PREFIX}/lib/dscached/plugins/
