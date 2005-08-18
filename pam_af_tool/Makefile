PROG=		pam_af_tool
BDECFLAGS=	-W -Wall -ansi -pedantic -Wbad-function-cast -Wcast-align \
		-Wcast-qual -Wchar-subscripts -Winline \
		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
		-Wredundant-decls -Wshadow -Wstrict-prototypes -Wwrite-strings \
		-std=c99

CFLAGS+=	-I${.CURDIR}/../common ${BDECFLAGS} -gstabs
SRCS=		pam_af_tool.c subr.c
NO_MAN=		1

.PATH:		${.CURDIR}/../common

.include <bsd.prog.mk>
