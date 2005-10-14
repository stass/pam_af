/*-
 * Copyright (c) 2004-2005 Stanislav Sedov <ssedov@mbsd.msk.ru>
 * Copyright (c) 2005 MBSD labs
 * Copyright (c) 2005 by 310.ru [Tridesyatoe], Moscow, Russian Federation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: subr.h,v 1.11 2005/10/14 04:14:53 stas Exp $
 */

typedef struct myaddrinfo {
	struct myaddrinfo	*next;
	char			*addr;
	size_t			addrlen;
} myaddrinfo_t;

extern const char *progname;

/* Prototypes */
int		addr_cmp		__P((const void *addr1,		\
					     const void *addr2,		\
					     size_t addrlen,		\
					     uint mask));
int		exec_cmd		__P((const char *str, 		\
					     char * const env[]));	\
int		parse_time		__P((const char *str,		\
					     long *ptime));
hostrule_t *	find_host_rule		__P((const char *db,		\
					     char *host));
void		my_freeaddrinfo 	__P((myaddrinfo_t *mai0));
const char *	my_gai_strerror		__P((int error));
int		my_getaddrinfo		__P((char *host,		\
					     int family,		\
					     myaddrinfo_t **pmai));
int		my_getnameinfo		__P((void *addr,		\
					     size_t addrlen,		\
					     char *buf,			\
					     size_t buflen));
char		*pam_af_strdupn		__P((char *p, size_t len));

/* Compatiblity routines */
#ifndef _HAVE_ERR_H_
void		err			__P((int err_code,		\
					     const char *format, ...));
void		errx			__P((int err_code,		\
					     const char *format, ...));
void		warnx			__P((const char *format, ...));
#endif /* _HAVE_ERR_H_ */
