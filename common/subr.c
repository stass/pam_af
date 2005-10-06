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
 * $Id: subr.c,v 1.16 2005/10/06 15:18:02 stas Exp $
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <paths.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <ndbm.h>
#include <netdb.h>
#include <sysexits.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include "pam_af.h"
#include "subr.h"

#define IPV4_ADDR(sockaddr) \
    ((char *)&(((struct sockaddr_in *)sockaddr)->sin_addr.s_addr))
#define IPV6_ADDR(sockaddr) \
    ((char *)((struct sockaddr_in6 *)sockaddr)->sin6_addr.s6_addr)
#define IPV4SZ sizeof(struct in_addr)
#define IPV6SZ sizeof(struct in6_addr)

#ifndef PAM_AF_DEFS
# define LOGERR(...) warnx(__VA_ARGS__)
#else /* !PAM_AF_DEFS */
# include <security/pam_appl.h>
# include <security/pam_mod_misc.h>
# include <security/openpam.h>
# define LOGERR(...) openpam_log(PAM_LOG_ERROR, __VA_ARGS__)
#endif /* PAM_AF_DEFS */

char *
pam_af_strdupn(p, len)
	char	*p;
	size_t	len;
{
	char	*str;

	ASSERT(p);
	ASSERT(len > 0);

	str = malloc(len);
	if (str == NULL)
		err(EX_OSERR, "malloc()");

	bcopy(p, str, len);
	str[len] = '\0';

	return str;
}

int
my_getnameinfo(addr, addrlen, buf, buflen)
	void	*addr;
	size_t	addrlen;
	char	*buf;
	size_t	buflen;
{
	struct sockaddr		*sockaddr;
	struct sockaddr_in	sa;
	struct sockaddr_in6	sa6;
	size_t			salen;
	int			ret;

	ASSERT(addr)
	ASSERT(buf)

	if (buflen == 0) {
		*buf = 0;
		return 0;
	}

	if (strncmp(addr, DEFRULE, addrlen) == 0) {
		snprintf(buf, buflen, "%s", DEFRULE);
		buf[buflen - 1] = 0;
		return 0;
	}

	switch (addrlen) {
	case IPV4SZ:
		bzero(&sa, sizeof(sa));
		sa.sin_family = PF_INET;
		sa.sin_port = 0;
		sa.sin_addr.s_addr = *(in_addr_t *)addr;

		sockaddr = (struct sockaddr *)&sa;
		salen = sizeof(sa);
		sockaddr->sa_family = PF_INET;
		break;

	case IPV6SZ:
		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = PF_INET6;
		sa6.sin6_port = 0;
		sa6.sin6_addr = *(struct in6_addr *)addr;
		
		sockaddr = (struct sockaddr *)&sa6;
		salen = sizeof(sa6);
		sockaddr->sa_family = PF_INET6;
		break;

	default:
		sockaddr = (struct sockaddr *)addr;
		salen = addrlen;
	}

	ret = getnameinfo(sockaddr, salen, buf, buflen, NULL, 0, \
	    NI_NUMERICHOST);

	return ret;
}

void
my_freeaddrinfo(mai0)
	myaddrinfo_t	*mai0;
{
	myaddrinfo_t	*mai, *mai1;

	for(mai = mai0; mai; mai = mai1) {
		mai1 = mai->next;
		if (mai->addr != NULL)
			free(mai->addr);
		free(mai);
	}
}

const char *
my_gai_strerror(error)
	int error;
{
	return(gai_strerror(error));
}

int
my_getaddrinfo(host, family, pmai)
	char		*host;
	int		family;
	myaddrinfo_t	**pmai;
{
	struct addrinfo	hints, *res, *res0;
	myaddrinfo_t	*mai, **last;
	int		ret;
	
	ASSERT(pmai)
	if (strncmp(host, DEFRULE, strlen(DEFRULE)) == 0) {
		*pmai = (myaddrinfo_t *)malloc(sizeof(myaddrinfo_t));
		if (*pmai == NULL)
			return EAI_MEMORY;
		mai = *pmai;
		mai->next = NULL;
		mai->addr = (char *)malloc(strlen(DEFRULE));
		if (mai->addr == NULL)
			return EAI_MEMORY;
		bcopy(DEFRULE, mai->addr, strlen(DEFRULE));
		mai->addrlen = strlen(DEFRULE);
		return 0;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_family = family;

        if ((ret = getaddrinfo(host, NULL, &hints, &res0)) != 0)
		return ret;

        for (res = res0, last = pmai; res; res = res->ai_next) {
		*last = (myaddrinfo_t *)malloc(sizeof(myaddrinfo_t));
		mai = *last;
		if (mai == NULL) {
			my_freeaddrinfo(*pmai);
			return EAI_MEMORY;
		}
		mai->next = NULL;

		ASSERT(res->ai_family)
                switch (res->ai_family) {
                case PF_INET:
				mai->addr = (char *)malloc(IPV4SZ);
				if (mai->addr == NULL) {
					my_freeaddrinfo(*pmai);
					return EAI_MEMORY;
				}
				ASSERT(res->ai_addr)
                                bcopy(IPV4_ADDR(res->ai_addr), mai->addr, \
				    IPV4SZ);
                                mai->addrlen = IPV4SZ;
                                break;

                case PF_INET6:
				mai->addr = (char *)malloc(IPV6SZ);
				if (mai->addr == NULL) {
					my_freeaddrinfo(*pmai);
					return EAI_MEMORY;
				}
				ASSERT(res->ai_addr)
                                bcopy(IPV6_ADDR(res->ai_addr), mai->addr, \
				    IPV6SZ);
                                mai->addrlen = IPV6SZ;
                                break;

                default:
				mai->addr = (char *)malloc(res->ai_addrlen);
				if (mai->addr == NULL) {
					my_freeaddrinfo(*pmai);
					return EAI_MEMORY;
				}
				ASSERT(res->ai_addr)
                                bcopy(res->ai_addr, mai->addr, \
				    res->ai_addrlen);
                                mai->addrlen = res->ai_addrlen;
                                break;
                }
		last = &mai->next;
	}

	freeaddrinfo(res0);

	return 0;
}
 
hostrule_t *
find_host_rule(db, host)
	const char	*db;
	char		*host;
{
	datum			key, data;
	struct			myaddrinfo *res0, *res;
	static hostrule_t	hstent;
	int			found = 0;
	uint			mask;
	int			ret;
	DBM			*dbp;

	ASSERT(host)
	ASSERT(db)

        /* Open cfg database */
        dbp = dbm_open(db, O_RDONLY | O_CREAT, \
            CFGDB_PERM);
        if (dbp == NULL) {
		LOGERR("can't open '%s' database, using default values: %s", \
		    db, strerror(errno)); 
		goto nodb;
	}

	if ((ret = my_getaddrinfo(host, PF_UNSPEC, &res0)) != 0) {
		LOGERR("can't resolve hostname '%s', using default values: %s",\
		    host, my_gai_strerror(ret));
		goto nodb;
	}

	for (res = res0; res && !found; res = res->next) {
		for (key = dbm_firstkey(dbp); key.dptr; key = dbm_nextkey(dbp))
		{
			ASSERT(res->addr)
			ASSERT(res->addrlen)
			if ((unsigned)key.dsize != res->addrlen)
				continue;

			data = dbm_fetch(dbp, key);
			if (data.dptr == NULL) {
				LOGERR("can't fetch record");
				goto nodb;
			}
			if (data.dsize != sizeof(hstent)) {
				LOGERR("database '%s' seriously broken", db);
				goto nodb;
			}
			
			mask = ((hostrule_t *)data.dptr)->mask;
			if (mask == 0)
				mask = res->addrlen * 8;
			if (addr_cmp(key.dptr, res->addr, res->addrlen, mask) \
			    == 0) {
				found = 1;
				break;
			}
		}
	}
	if (found == 0) {
		key.dptr = strdup(DEFRULE);
		if (key.dptr == NULL) {
			LOGERR("malloc: %s", strerror(errno));
			goto nodb;
		}
		key.dsize = strlen(DEFRULE);
		data = dbm_fetch(dbp, key);
		free(key.dptr);
	}

	if (data.dptr != NULL) {
		if (data.dsize != sizeof(hstent)) {
			LOGERR("database '%s' seriously broken", db);
			goto nodb;
		}
			
		bcopy(data.dptr, &hstent, sizeof(hstent));

		dbm_close(dbp);
		return &hstent;
	}

nodb:
	hstent.mask = 0;
	hstent.attempts = DEFAULT_ATTEMPTS;
	hstent.locktime = DEFAULT_LOCKTIME;
	*hstent.lock_cmd = 0;
	*hstent.unlock_cmd = 0;

	return &hstent;
}

int
addr_cmp(addr1, addr2, addrlen, mask)
	const void	*addr1;
	const void	*addr2;
	size_t		addrlen;
	uint		mask;
{
	register uint bytes = mask / 8;
	register uint left = mask % 8;
	register int8_t byte1 = 0, byte2 = 0;

	ASSERT(addr1)
	ASSERT(addr2)

	if (mask > addrlen * 8)
		return 1;
	
	if (bcmp(addr1, addr2, bytes) != 0)
		return 1;

	if (left != 0) {
		byte1 = ((const char *)addr1)[bytes];
		byte2 = ((const char *)addr2)[bytes];

		byte1 >>= (8 - left);
		byte2 >>= (8 - left);
	}

	if (byte1 == byte2) {
		return 0;
	}
	else
		return 1;
}

int
parse_time(str, ptime)
	const char	*str;
	long		*ptime;
{
	register long	rettime = 0;
	register int	i;
	char		*p;
	
	ASSERT(str)
	ASSERT(ptime)

	for (i = strtol(str, &p, 0); *p != '\0'; p++, i = strtol(p, &p, 0)) {
		if (i <= 0)
			return 1;
		switch (*p) {
		case 'y':
			rettime += i * 12 * 30 * 24 * 3600;
			break;
		case 'm':
			rettime += i * 30 * 24 * 3600;
			break;
		case 'd':
			rettime += i * 24 * 3600;
			break;
		case 'H':
			rettime += i * 3600;
			break;
		case 'M':
			rettime += i * 60;
			break;
		case 'S':
			rettime += i;
			break;
		default:
			return 1;
		}
	}

	*ptime = rettime + i;
	return 0;
}

/*
 * Execute external cmd, return error message in ebuf, if not NULL. 
 */
int
exec_cmd(str, env)
	const char	*str;
	char * const env[];
{
	int	pid, ret = 0;
	int	status;
			
	ASSERT(str)

	switch (pid = vfork()) {
	case 0:
		(void)execle(_PATH_BSHELL, "sh", "-c", str, NULL,
		    (char * const *)env);
		ret = errno;
		_exit(1);
		break;
	case -1:
		LOGERR("can't fork: %s", strerror(errno));
		return 1;
		break;
	default:
		break;
	}

	if (waitpid(pid, &status, 0) == -1) {
		LOGERR("waitpid(): %s", strerror(errno));
		return 2;
	}
	
	/* Check child exit value */
	if (ret != 0) {
		LOGERR("execle(): %s", strerror(errno));
		return 3;
	}

	if (WIFSIGNALED(status)) {
		LOGERR("cmd caught signal %d%s", WTERMSIG(status), \
		    WCOREDUMP(status) ? " (core dumped)" : "");
		return 4;
	}
	if (WIFEXITED(status) == 0) {
		LOGERR("unknown status 0x%x", status);
		return 5;
	}
	if (WEXITSTATUS(status) != 0) {
		LOGERR("cmd returned code %d", WEXITSTATUS(status));
		return 6;
	}

	return 0;	
}
