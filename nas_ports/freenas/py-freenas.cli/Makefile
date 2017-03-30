# $FreeBSD$

PORTNAME=	freenas.cli
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=   ${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS Command Line Interface

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}columnize>0:${PORTSDIR}/devel/py-columnize \
		${PYTHON_PKGNAMEPREFIX}natural>0:${PORTSDIR}/devel/py-natural \
		${PYTHON_PKGNAMEPREFIX}ply>0:${PORTSDIR}/devel/py-ply \
		${PYTHON_PKGNAMEPREFIX}termcolor>0:${PORTSDIR}/devel/py-termcolor \
		${PYTHON_PKGNAMEPREFIX}texttable>0:${PORTSDIR}/textproc/py-texttable \
		${PYTHON_PKGNAMEPREFIX}six>0:${PORTSDIR}/devel/py-six \
		${PYTHON_PKGNAMEPREFIX}pyte>0:${PORTSDIR}/devel/py-pyte \
		${PYTHON_PKGNAMEPREFIX}future>0:${PORTSDIR}/devel/py-future \
		${PYTHON_PKGNAMEPREFIX}rollbar>0:${PORTSDIR}/www/py-rollbar \
		${PYTHON_PKGNAMEPREFIX}bsd>0:${PORTSDIR}/freenas/py-bsd \
		${PYTHON_PKGNAMEPREFIX}filewrap>0:${PORTSDIR}/freenas/py-filewrap \
		${PYTHON_PKGNAMEPREFIX}freenas.utils>0:${PORTSDIR}/freenas/py-freenas.utils \
		${PYTHON_PKGNAMEPREFIX}freenas.dispatcher>0:${PORTSDIR}/freenas/py-freenas.dispatcher


BUILD_DEPENDS=	${RUN_DEPENDS} \
		${PYTHON_PKGNAMEPREFIX}sphinx>0:${PORTSDIR}/textproc/py-sphinx

USES=		python
USE_PYTHON=	autoplist distutils
EXTRACT_ONLY=

MAKE_ENV=	VERSION=${PRODUCT_VERSION}
WRKSRC=		/usr/middleware_src/py-freenas.cli

PLIST_FILES=	bin/cli bin/logincli
MAKE_ENV+=	GENERATE_CLI_DOCS=yes

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

post-install:
	${INSTALL_SCRIPT} ${WRKSRC}/tools/cli ${STAGEDIR}${PREFIX}/bin/
	${INSTALL_SCRIPT} ${WRKSRC}/tools/logincli ${STAGEDIR}${PREFIX}/bin/
	${INSTALL_SCRIPT} -d ${STAGEDIR}${PREFIX}/www/cli
	# cp /var/tmp/cli.docs/* ${WRKSRC}/docgen/config/build_env/source/
	# make -C ${WRKSRC}/docgen/config/build_env/ html BUILDDIR=${STAGEDIR}${PREFIX}/www/cli
	(cd ${STAGEDIR}${PREFIX}/www/cli; ${FIND} -E . -type f -regex \
		".*((.pyc?)|(.so)|(.jso?n?)|(.html)|(.map)|(.css)|(.png)|(.jpg)|(.gif)|(.md)|(.txt)|(.swf)|(.eot)|(.svg)|(.ttf)|(.woff2?)|(.c))+$$" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print "www/cli/"$$0 }' >> ${TMPPLIST})

.include <bsd.port.mk>
