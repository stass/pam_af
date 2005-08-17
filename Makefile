# $Id: Makefile,v 1.3 2005/08/17 01:29:02 stas Exp $
CFLAGS+=	-I${.CURDIR}/common -I${.CURDIR} -DPAM_AF_DEFS
LIB=		pam_af
SRCS=		pam_af.c subr.c
NO_MAN=		1
#MAN=		pam_af.8

.PATH:		${.CURDIR}/common

.include <bsd.lib.mk>
