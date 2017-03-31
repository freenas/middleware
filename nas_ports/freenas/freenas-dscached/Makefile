# $FreeBSD$

PORTNAME=	freenas-dscached
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS directory services daemon

BUILD_DEPENDS=	libdispatcherclient>0:${PORTSDIR}/freenas/libdispatcherclient \
		pkgconf>0:${PORTSDIR}/devel/pkgconf

RUN_DEPENDS=	libdispatcherclient>0:${PORTSDIR}/freenas/libdispatcherclient \
		${PYTHON_PKGNAMEPREFIX}more-itertools>0:${PORTSDIR}/devel/py-more-itertools \
		${PYTHON_PKGNAMEPREFIX}ldap3>0:${PORTSDIR}/net/py-ldap3 \
		${PYTHON_PKGNAMEPREFIX}gssapi>0:${PORTSDIR}/devel/py-gssapi \
		${PYTHON_PKGNAMEPREFIX}ntplib>0:${PORTSDIR}/net/py-ntplib

USES=		python cmake:outsource
USE_PYTHON=	py3kplist
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/dscached
CMAKE_SOURCE_PATH=${WRKSRC}/libexec/authorized-keys-helper
CMAKE_INSTALL_PREFIX=${STAGEDIR}${PREFIX}

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-install:
	${MAKE} -C ${WRKSRC} install PREFIX=${STAGEDIR}${PREFIX} PYTHON=${PYTHON_CMD}
	${MAKE} -C ${CONFIGURE_WRKSRC} install

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/dscached

	(cd ${STAGEDIR}${PREFIX}/lib/dscached; ${FIND} -E . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/dscached/"$$2 }' >> ${TMPPLIST})

	(cd ${STAGEDIR}${PREFIX}/lib/dscached/plugins; ${FIND} . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/dscached/plugins/"$$2 }' >> ${TMPPLIST})

.include <bsd.port.mk>
