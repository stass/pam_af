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
 * $Id: pam_af_tool.c,v 1.1 2005/08/15 02:33:36 stas Exp $
 */

#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <paths.h>
#include <assert.h>
#include <sysexits.h>
#include <ndbm.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "pam_af.h"
#include "subr.h"

extern const char *cfgdb;
extern const char *stdb;

static void		usage			__P((void));
int			main			__P((int argc, char **argv));
static void		handle_ruleadd		__P((int argc, char **argv));
static void		handle_rulemod		__P((int argc, char **argv));
static void		handle_ruledel		__P((int argc, char **argv));
static void		handle_rulelist		__P((int argc, char **argv));
static void		handle_ruleflush	__P((int argc, char **argv));
static void		handle_statdel		__P((int argc, char **argv));
static void		handle_statlist		__P((int argc, char **argv));
static void		handle_statflush	__P((int argc, char **argv));
static void		handle_lock		__P((int argc, char **argv));
static void		handle_unlock		__P((int argc, char **argv));

#define UNLIM "unlimited"

#define OPER(op) {#op, handle_##op}
struct {
	const char	*op;
	void (*handler)(int, char **);
} ops[] = {
	OPER(ruleadd),
	OPER(rulemod),
	OPER(ruledel),
	OPER(rulelist),
	OPER(ruleflush),
	OPER(statdel),
	OPER(statlist),
	OPER(statflush),
	OPER(lock),
	OPER(unlock),
};
	
static int vflag = 0;
static int fflag = 0;
static DBM *stdbp = NULL;
static DBM *cfgdbp = NULL;

static void
usage(void)
{

	fprintf(stderr, "usage: %s\n"					\
	    "\truleadd -h host -a attempts -t time [-l cmd] "		\
	    "[-u cmd] [-d file] [-v]\n"					\
	    "\trulemod -h host [-a attempts] [-t time] [-l cmd] "	\
	    "[-u cmd] [-d file] [-v]\n"					\
	    "\truledel -h host [-d file] [-v]\n"			\
	    "\trulelist [-d file]\n"					\
	    "\truleflush [-d file] [-v]\n"				\
	    "\tstatdel -h host [-d file] [-v]\n"			\
	    "\tstatlist [-d file]\n"					\
	    "\tstatflush [-d file] [-v]\n"				\
	    "\tlock [-h host] [-s file] [-r file] [-fv]\n"		\
	    "\tunlock [-h host] [-s file] [-r file] [-fv]\n", getprogname());

	exit(EX_USAGE);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int nops = sizeof(ops) / sizeof(*ops);
	register int i;
	
	if (argc < 2)
		usage();
		/* NOTREACHED */
	
	for (i = 0; i < nops; i++)
		if (strncmp(ops[i].op, argv[1], strlen(ops[i].op)) == 0)
			ops[i].handler(--argc, ++argv);
	
	usage();
	
	/* NOTREACHED */

	return 0;
}	

void cleanup(void)
{
	if (stdbp)
		dbm_close(stdbp);
	if (cfgdbp)
		dbm_close(cfgdbp);
}

static void
handle_ruleadd(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, flags = DBM_REPLACE;
	char *host = NULL;
	datum key, data;
	struct addrinfo hints, *res, *res0;
	hostrule_t hstent;
	char *tmp;
	char buf[1024];

	bzero(&hstent, sizeof(hstent));
	hstent.attempts = -1;
	hstent.locktime = -1;

	while ((ch = getopt(argc, argv, "h:a:t:l:u:d:nv")) != -1) {
		switch (ch) {
		case 'n':
			flags = DBM_INSERT;
			break;
		case 'v':
			vflag = 1;
			break;

		case 'a':
			if (strncmp(optarg, UNLIM, strlen(UNLIM)) == 0) {
				hstent.attempts = 0;
				break;
			}
			hstent.attempts = atoi(optarg);
			if (hstent.attempts <= 0)
				errx(EX_DATAERR, "invalid attempts: %s",
				    optarg);
			break;

		case 't':
			if(parse_time(optarg, &hstent.locktime) != 0)
				errx(EX_DATAERR, "invalid time: %s", optarg);
			break;

		case 'h':
			host = optarg;
			break;

		case 'l':
			strncpy(hstent.lock_cmd, optarg, MAX_CMD_LEN);
			hstent.lock_cmd[MAX_CMD_LEN - 1] = 0;
			break;

		case 'u':
			strncpy(hstent.unlock_cmd, optarg, MAX_CMD_LEN);
			hstent.unlock_cmd[MAX_CMD_LEN - 1] = 0;
			break;

		case 'd':
			cfgdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if ((host == NULL) || hstent.attempts < 0 || hstent.locktime < 0)
		usage();
		/* NOTREACHED */

	/* Open rules database */
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_CREAT | O_EXLOCK, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	/* Extract mask specification from hostname */
	hstent.mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        hstent.mask = atoi(tmp);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_protocol = IPPROTO_TCP;

	if (hstent.mask > 128)
		errx(EX_USAGE, "invalid mask");
	else if (hstent.mask > 32)
		hints.ai_family = PF_INET6;
	else if (hstent.mask > 0)
		hints.ai_family = PF_INET;
	else
		hints.ai_family = PF_UNSPEC;

	if ((ret = getaddrinfo(host, NULL, &hints, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname %s: %s", \
		    host, gai_strerror(ret));

	for (res = res0; res; res = res->ai_next) {
		switch (res->ai_family) {
		case PF_INET:
				key.dptr = (char *)&(((struct sockaddr_in *) \
				res->ai_addr)->sin_addr.s_addr);
				key.dsize = 4;
				break;
		case PF_INET6:
				key.dptr = (char *)((struct sockaddr_in6 *) \
				res->ai_addr)->sin6_addr.s6_addr;
				key.dsize = 16;
				break;
		default:
				key.dptr = (char *)res->ai_addr;
				key.dsize = res->ai_addrlen;
				break;
		}
		
		data.dptr = (char *)&hstent;
		data.dsize = sizeof(hstent);
	
		ret = dbm_store(cfgdbp, key, data, flags);
		switch (ret) {
		case -1:
			err(EX_OSERR, "can't store record");
			/* NOTREACHED */
		case 1:
			if (vflag)
				warnx("ignored duplicate: %s", host);
			continue;
		}
		if (vflag) {
			if (getnameinfo(res->ai_addr, res->ai_addrlen, \
			    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) != 0)
				err(EX_OSERR, "can't get numeric address");
			fprintf(stderr, "Stored rule for %s.\n", buf);
		}
	}
	freeaddrinfo(res0);

	exit(EX_OK);
}

static void
handle_rulemod(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, flags = DBM_REPLACE;
	char *host = NULL;
	datum key, data;
	struct addrinfo hints, *res, *res0;
	hostrule_t *hstent;
	long attempts = -1, locktime = -1;
	char *lockcmd = NULL, *unlockcmd = NULL;
	char buf[1024];
	char *tmp;
	int found = 0;
	int mask;

	while ((ch = getopt(argc, argv, "h:a:t:l:u:d:v")) != -1) {
		switch (ch) {
		case 'v':
			vflag = 1;
			break;

		case 'a':
			if (strncmp(optarg, UNLIM, strlen(UNLIM)) == 0) {
				attempts = 0;
				break;
			}
			attempts = atoi(optarg);
			if (attempts <= 0)
				errx(EX_DATAERR, "invalid attempts: %s",
				    optarg);
			break;

		case 't':
			if(parse_time(optarg, &locktime) != 0)
				errx(EX_DATAERR, "invalid time: %s", optarg);
			break;

		case 'h':
			host = optarg;
			break;

		case 'l':
			lockcmd = optarg;
			break;

		case 'u':
			unlockcmd = optarg;
			break;

		case 'd':
			cfgdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (host == NULL)
		usage();
		/* NOTREACHED */

	/* Open rules database */
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_CREAT | O_EXLOCK, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	/* Extract mask specification from hostname */
	mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        mask = atoi(tmp);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_protocol = IPPROTO_TCP;

	if (mask > 128)
		errx(EX_USAGE, "invalid mask");
	else if (mask > 32)
		hints.ai_family = PF_INET6;
	else if (mask > 0)
		hints.ai_family = PF_INET;
	else
		hints.ai_family = PF_UNSPEC;

	if ((ret = getaddrinfo(host, NULL, &hints, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname %s: %s", \
		    host, gai_strerror(ret));

	for (res = res0; res; res = res->ai_next) {
		switch (res->ai_family) {
		case PF_INET:
				key.dptr = (char *)&(((struct sockaddr_in *) \
				res->ai_addr)->sin_addr.s_addr);
				key.dsize = 4;
				break;
		case PF_INET6:
				key.dptr = (char *)((struct sockaddr_in6 *) \
				res->ai_addr)->sin6_addr.s6_addr;
				key.dsize = 16;
				break;
		default:
				key.dptr = (char *)res->ai_addr;
				key.dsize = res->ai_addrlen;
				break;
		}
		
		if (getnameinfo(res->ai_addr, res->ai_addrlen, \
		    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) != 0)
			err(EX_OSERR, "can't get numeric address");

		data = dbm_fetch(cfgdbp, key);
		hstent = (hostrule_t *)data.dptr;
		if (hstent == NULL) {
			if (vflag) {
				warnx("record for address %s not found", buf);
			}
			continue;
		}

		if (hstent->mask != mask)
			continue;

		if (attempts >= 0)
			hstent->attempts = attempts;
		if (locktime >= 0)
			hstent->locktime = locktime;
		if (lockcmd != NULL) {
			strncpy(hstent->lock_cmd, lockcmd, MAX_CMD_LEN);
			hstent->lock_cmd[MAX_CMD_LEN - 1] = '\0';
		}
		if (unlockcmd != NULL) {
			strncpy(hstent->unlock_cmd, unlockcmd, MAX_CMD_LEN);
			hstent->unlock_cmd[MAX_CMD_LEN - 1] = '\0';
		}

		data.dptr = (char *)hstent;
		data.dsize = sizeof(*hstent);
	
		if (dbm_store(cfgdbp, key, data, flags) == -1)
			err(EX_OSERR, "can't store record");

		if (vflag)
			warnx("modified rule for ip %s", buf);
		
		found = 1;
	}

	freeaddrinfo(res0);

	if (found == 0)
		warnx("no suitable records found");

	exit(EX_OK);
}

static void
handle_ruledel(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, found = 0;
	char *host = NULL;
	datum key, data;
	struct addrinfo hints, *res, *res0;
	hostrule_t *hstent;
	char *tmp;
	int mask;
	char buf[1024];

	while ((ch = getopt(argc, argv, "h:d:v")) != -1) {
		switch (ch) {
		case 'v':
			vflag = 1;
			break;

		case 'h':
			host = optarg;
			break;

		case 'd':
			cfgdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (host == NULL)
		usage();
		/* NOTREACHED */

	/* Open rules database */
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_EXLOCK, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	/* Extract mask specification from hostname */
	mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        mask = atoi(tmp);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_protocol = IPPROTO_TCP;

	if (mask > 128)
		errx(EX_USAGE, "invalid mask");
	else if (mask > 32)
		hints.ai_family = PF_INET6;
	else if (mask > 0)
		hints.ai_family = PF_INET;
	else
		hints.ai_family = PF_UNSPEC;

	if ((ret = getaddrinfo(host, NULL, &hints, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname %s: %s", \
		    host, gai_strerror(ret));

	for (res = res0; res; res = res->ai_next) {
		switch (res->ai_family) {
		case PF_INET:
				key.dptr = (char *)&(((struct sockaddr_in *) \
				res->ai_addr)->sin_addr.s_addr);
				key.dsize = 4;
				break;
		case PF_INET6:
				key.dptr = (char *)((struct sockaddr_in6 *) \
				res->ai_addr)->sin6_addr.s6_addr;
				key.dsize = 16;
				break;
		default:
				key.dptr = (char *)res->ai_addr;
				key.dsize = res->ai_addrlen;
				break;
		}
		
		if (getnameinfo(res->ai_addr, res->ai_addrlen, \
		    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) != 0)
			err(EX_OSERR, "can't get numeric address");

		data = dbm_fetch(cfgdbp, key);
		hstent = (hostrule_t *)data.dptr;
		if (hstent == NULL) {
			if (vflag) {
				warnx("record for address %s not found", buf);
			}
			continue;
		}

		if (hstent->mask != mask)
			continue;

		if (dbm_delete(cfgdbp, key) != 0)
			errx(EX_OSERR, "can't delete record for %s", buf);

		if (vflag)
			fprintf(stderr, "Deleted %s.\n", buf);
		found = 1;
	}

	freeaddrinfo(res0);

	if (found == 0)
		warnx("no suitable records found");

	exit(EX_OK);
}

static void
handle_rulelist(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, found = 0;
	datum key, data;
	hostrule_t *hstent;
	struct sockaddr_in sockaddr;
	struct sockaddr_in6 sockaddr6;
	char *tmp;
	char buf[1024];

	while ((ch = getopt(argc, argv, "d:")) != -1) {
		switch (ch) {
		case 'd':
			cfgdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
	cfgdbp = dbm_open(cfgdb, O_RDONLY, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	printf("<hostrules>\n");
	for (key = dbm_firstkey(cfgdbp); key.dptr; key = dbm_nextkey(cfgdbp)) {
		switch(key.dsize) {
		case 4:
			sockaddr.sin_family = PF_INET;
			sockaddr.sin_port = 0;
			sockaddr.sin_addr.s_addr = *(in_addr_t *)key.dptr;

			if (getnameinfo((const struct sockaddr *)&sockaddr, \
			    sizeof(sockaddr), buf, sizeof(buf), NULL, 0, \
			    NI_NUMERICHOST) != 0)
				err(EX_OSERR, "can't get numeric address");
			break;

		case 16:
			sockaddr6.sin6_family = PF_INET6;
			sockaddr6.sin6_port = 0;
			bcopy(key.dptr, sockaddr6.sin6_addr.s6_addr, key.dsize);

			if (getnameinfo((const struct sockaddr *)&sockaddr6, \
			    sizeof(sockaddr6), buf, sizeof(buf), NULL, 0, \
			    NI_NUMERICHOST) != 0)
				err(EX_OSERR, "can't get numeric address");
			break;

		default:
			errx(EX_DATAERR, "database broken");
		}

		data = dbm_fetch(cfgdbp, key);
		hstent = (hostrule_t *)data.dptr;
		if (hstent == NULL)
			err(EX_OSERR, "can't fetch data");

		if (hstent->mask != 0)
			printf("<host ip='%s' mask='%d'>\n", buf, hstent->mask);
		else	
			printf("<host ip='%s'>\n", buf);
		if (hstent->attempts != 0)
			printf("<attempts>%ld</attempts>\n", hstent->attempts);
		else
			printf("<attempts>%s</attempts>\n", UNLIM);
		printf("<locktime>%lds</locktime>\n", hstent->locktime);
		if (hstent->lock_cmd != NULL)
			printf("<lockcmd>%s</lockcmd>\n", hstent->lock_cmd);
		if (hstent->unlock_cmd != NULL)
			printf("<unlockcmd>%s</unlockcmd>\n", \
			    hstent->unlock_cmd);
		printf("</host>\n");
	}
	printf("</hostrules>\n");


	exit(EX_OK);
}

static void
handle_ruleflush(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, i = 0;
	datum key, data;
	hostrule_t hstent;
	char *tmp;
	char buf[1024];

	while ((ch = getopt(argc, argv, "d:v")) != -1) {
		switch (ch) {
		case 'd':
			cfgdb = optarg;
			break;

		case 'v':
			vflag = 1;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_EXLOCK, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	for (key = dbm_firstkey(cfgdbp); key.dptr; key = dbm_nextkey(cfgdbp)) {
		ret = dbm_delete(cfgdbp, key);
		if (ret != 0)
			err(EX_OSERR, "can't delete record");
		i++;
	}

	if (vflag)
		fprintf(stderr, "%d records flushed\n",i); 

	exit(EX_OK);
}

static void
handle_statdel(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, i = 0;
	datum key, data;
	hostrule_t hstent;
	char *host = NULL;
	char *tmp;
	char buf[1024];

	while ((ch = getopt(argc, argv, "d:h:v")) != -1) {
		switch (ch) {
		case 'd':
			stdb = optarg;
			break;

		case 'h':
			host = optarg;
			break;

		case 'v':
			vflag = 1;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (host == NULL)
		usage();
		/* NOTREACHED */

	/* Open statistics database */
	stdbp = dbm_open(stdb, O_RDWR | O_EXLOCK, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  stdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	ASSERT(host)
	key.dptr = host;
	key.dsize = strlen(host) + 1;
	
	ret = dbm_delete(stdbp, key);
	switch (ret) {
	case -1:
		err(EX_OSERR, "can't delete record");
	case 1:
		if (vflag)
			fprintf(stderr, "Record not found.\n");
	}
	
	if (vflag)
		fprintf(stderr, "Deleted.\n");


	exit(EX_OK);
}

static void
handle_statlist(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, found = 0;
	datum key, data;
	hostrec_t *hstrec;
	char *tmp;
	char buf[1024];

	while ((ch = getopt(argc, argv, "d:")) != -1) {
		switch (ch) {
		case 'd':
			stdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
	stdbp = dbm_open(stdb, O_RDONLY, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  stdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	printf("<hoststat>\n");
	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_nextkey(stdbp)) {
		data = dbm_fetch(stdbp, key);
		hstrec = (hostrec_t *)data.dptr;
		if (hstrec == NULL)
			err(EX_OSERR, "can't fetch data");

		printf("\t<host hostname='%s'>\n", (char *)key.dptr);
		printf("\t\t<attempts>%ld</attempts>\n", hstrec->num);
		printf("\t\t<last_attempt>%lds</last_attempt>\n", \
		    hstrec->last_attempt);
		printf("\t\t<status>%s</status>\n", hstrec->locked_for == 0 ? \
		    "unlocked" : "locked");
		printf("\t</host>\n");
	}
	printf("</hoststat>\n");


	exit(EX_OK);
}

static void
handle_statflush(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, i = 0;
	datum key, data;
	hostrec_t hstrec;
	char *tmp;
	char buf[1024];

	while ((ch = getopt(argc, argv, "vd:")) != -1) {
		switch (ch) {
		case 'v':
			vflag = 1;
			break;

		case 'd':
			stdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
	stdbp = dbm_open(stdb, O_RDWR | O_EXLOCK, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  stdb);

	atexit(cleanup);

	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_nextkey(stdbp)) {
		ret = dbm_delete(stdbp, key);
		if (ret != 0)
			err(EX_OSERR, "can't delete record");
		i++;
	}

	if (vflag)
		fprintf(stderr, "%d records flushed\n", i); 

	exit(EX_OK);
}

static void
handle_lock(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, i = 0;
	datum key, data;
	hostrec_t *hstrec;
	hostrule_t *hstent;
	char *tmp;
	char *host = NULL;
	char buf[1024];

	while ((ch = getopt(argc, argv, "h:s:r:fv")) != -1) {
		switch (ch) {
		case 'h':
			host = optarg;
			break;

		case 'v':
			vflag = 1;
			break;

		case 'f':
			fflag = 1;
			break;

		case 's':
			stdb = optarg;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
	stdbp = dbm_open(stdb, O_RDWR | O_CREAT | O_EXLOCK, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  stdb);

	/* Open cfg database */
	cfgdbp = dbm_open(cfgdb, O_RDONLY | O_CREAT, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open config database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	if (host != NULL) {
		key.dptr = host;
		key.dsize = strlen(host) + 1;
		data = dbm_fetch(stdbp, key);
		hstrec = (hostrec_t *)data.dptr;
		/* XXX: check dsize value */
		/* XXX: report used ip */

		if (hstrec == NULL)
			err(EX_OSERR, "can't fetch data from %s", stdb);

		hstent = find_host_rule(cfgdbp, host);
		ASSERT(hstent);

		if (lock_host(hstrec, hstent, fflag) == 0) {
			ret = dbm_store(stdbp, key, data, DBM_REPLACE);
			if (ret != 0)
				err(EX_OSERR, "can't store record");
		}
	}
	else {
		for (key = dbm_firstkey(stdbp); key.dptr; \
		    key = dbm_nextkey(stdbp)) {
			data = dbm_fetch(stdbp, key);
			hstrec = (hostrec_t *)data.dptr;

			if (hstrec == NULL)
				err(EX_OSERR, "can't fetch data from %s", stdb);

			hstent = find_host_rule(cfgdbp, key.dptr);
			ASSERT(hstent);
	
			if (lock_host(hstrec, hstent, fflag) == 0) {
				ret = dbm_store(stdbp, key, data, DBM_REPLACE);
				if (ret != 0)
					err(EX_OSERR, "can't store record");
			}
		}
	}

	exit(EX_OK);
}

static void
handle_unlock(argc, argv)
	int	argc;	
	char	*argv[];
{
	int ch, ret, i = 0;
	datum key, data;
	hostrec_t *hstrec;
	hostrule_t *hstent;
	char *tmp;
	char *host = NULL;
	char buf[1024];

	while ((ch = getopt(argc, argv, "h:s:r:fv")) != -1) {
		switch (ch) {
		case 'h':
			host = optarg;
			break;

		case 'v':
			vflag = 1;
			break;

		case 'f':
			fflag = 1;
			break;

		case 's':
			stdb = optarg;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
	stdbp = dbm_open(stdb, O_RDWR | O_CREAT | O_EXLOCK, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open rules database %s",  stdb);

	/* Open cfg database */
	cfgdbp = dbm_open(cfgdb, O_RDONLY | O_CREAT, \
	    CFGDB_PERM);
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open config database %s",  cfgdb);

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	if (host != NULL) {
		key.dptr = host;
		key.dsize = strlen(host) + 1;
		data = dbm_fetch(stdbp, key);
		hstrec = (hostrec_t *)data.dptr;
		/* XXX: check dsize value */
		/* XXX: report used ip */

		if (hstrec == NULL)
			err(EX_OSERR, "can't fetch data from %s", stdb);

		hstent = find_host_rule(cfgdbp, host);
		ASSERT(hstent);

		if (unlock_host(hstrec, hstent, fflag) == 0) {
			ret = dbm_store(stdbp, key, data, DBM_REPLACE);
			if (ret != 0)
				err(EX_OSERR, "can't store record");
		}
	}
	else {
		for (key = dbm_firstkey(stdbp); key.dptr; \
		    key = dbm_nextkey(stdbp)) {
			data = dbm_fetch(stdbp, key);
			hstrec = (hostrec_t *)data.dptr;

			if (hstrec == NULL)
				err(EX_OSERR, "can't fetch data from %s", stdb);

			hstent = find_host_rule(cfgdbp, host);
			ASSERT(hstent);
	
			if (unlock_host(hstrec, hstent, fflag) == 0) {
				ret = dbm_store(stdbp, key, data, DBM_REPLACE);
				if (ret != 0)
					err(EX_OSERR, "can't store record");
			}
		}
	}

	exit(EX_OK);
}
