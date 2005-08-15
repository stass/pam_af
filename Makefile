# $Id: Makefile,v 1.2 2005/08/15 02:33:26 stas Exp $
CFLAGS+=	-I${.CURDIR}/common -I${.CURDIR}
LIB=		pam_af
SRCS=		pam_af.c subr.c
NO_MAN=		1
#MAN=		pam_af.8

.PATH:		${.CURDIR}/common

.include <bsd.lib.mk>
