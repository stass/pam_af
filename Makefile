# $Id: Makefile,v 1.4 2005/08/19 01:55:14 stas Exp $
CFLAGS+=	-I${.CURDIR}/common -I${.CURDIR} -DPAM_AF_DEFS
LIB=		pam_af
SRCS=		pam_af.c subr.c
MAN=		pam_af.8

.PATH:		${.CURDIR}/common

.include <bsd.lib.mk>
