/*-
 * Copyright (c) 2004-2005 Stanislav Sedov
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
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * $Id: subr.h,v 1.3 2005/08/15 23:46:41 stas Exp $
 */

typedef struct myaddrinfo {
	struct myaddrinfo	*next;
	char			*addr;
	size_t			addrlen;
} myaddrinfo_t;

/* Prototypes */

int		addr_cmp		__P((const void *addr1,		\
					     const void *addr2,		\
					     size_t addrlen,		\
					     int32_t mask));
int		exec_cmd		__P((const char *str, 		\
					     char * const env[],	\
					     char *ebuf,		\
					     size_t ebufsz));
int		parse_time		__P((const char *str,		\
					     long *ptime));
int		lock_host		__P((hostrec_t *hstrec,		\
					     hostrule_t *hstent,	\
					     int fflag));
int		unlock_host		__P((hostrec_t *hstrec,		\
					     hostrule_t *hstent,	\
					     int fflag));
hostrule_t *	find_host_rule		__P((DBM *dbp,			\
					     char *host));
void		my_freeaddrinfo 	__P((myaddrinfo_t *mai0));
const char *	my_gai_strerror		__P((int err));
int		my_getaddrinfo		__P((char *host,		\
					     int family,		\
					     myaddrinfo_t **pmai));
