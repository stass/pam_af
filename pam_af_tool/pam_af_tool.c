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
 * $Id: pam_af_tool.c,v 1.23 2005/10/06 15:18:03 stas Exp $
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
#include <time.h>
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

/*
 * This program allows to control behavour of pam_af module. It can load/
 * modify/flush host rules, operate on statistic bases, lock and unlock
 * hosts.
 */

/* Local prototypes */
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
int			lock_host		__P((char *host, int f));
int			unlock_host		__P((char *host, int f));

/* Global data */
static const char *cfgdb = CFGDB;
static const char *stdb = STATDB;
static DBM *stdbp = NULL;
static DBM *cfgdbp = NULL;

/* Local defines */
#define UNLIM "unlimited"

#define OPER(op) {#op, handle_##op} /* main targets for program */
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
#define NOPS (sizeof(ops) / sizeof(*ops))
	
#define VFLAG 0x00000001 /* -v flag */
#define FFLAG 0x00000002 /* -f flag */
#define AFLAG 0x00000004 /* -a flag */
#define TFLAG 0x00000008 /* -t flag */
#define LFLAG 0x00000010 /* -l flag */
#define UFLAG 0x00000020 /* -u flag */
#define NFLAG 0x00000040 /* -n flag */
#define HFLAG 0x00000080 /* -h flag */

static void
usage(void)
{
#ifdef FreeBSD
	const char	*prog = getprogname();
#else
	const char	*prog = "pam_af_tool";
#endif

	(void)fprintf(stderr, "usage:\n"				\
	    "\t%s ruleadd -h host -a attempts -t time"			\
	    "\n\t\t[-l cmd] [-u cmd] [-r file] [-v]\n"			\
	    "\t%s rulemod -h host [-a attempts] [-t time]"		\
	    "\n\t\t[-l cmd] [-u cmd] [-r file] [-v]\n"			\
	    "\t%s ruledel -h host [-r file] [-v]\n"			\
	    "\t%s rulelist [-r file]\n"					\
	    "\t%s ruleflush [-r file] [-v]\n"				\
	    "\t%s statdel -h host [-s file] [-v]\n"			\
	    "\t%s statlist [-s file]\n"					\
	    "\t%s statflush [-s file] [-v]\n"				\
	    "\t%s lock [-h host] [-s file] [-r file] [-fv]\n"		\
	    "\t%s unlock [-h host] [-s file] [-r file] [-fv]\n", 	\
	    prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);

	exit(EX_USAGE);
}

int
main(argc, argv)
	int	argc;
	char	*argv[];
{
	unsigned int	i;
	
	if (argc < 2)
		usage();
		/* NOTREACHED */
	
	for (i = 0; i < NOPS; i++)
		if (strncmp(ops[i].op, argv[1], strlen(ops[i].op)) == 0)
			ops[i].handler(--argc, ++argv);
	
	usage();
	
	/* NOTREACHED */

	return 0;
}	

/*
 * Default handler to execute in case of exit(). We must close bases to avoid 
 * inconsistencies.
 */
static void cleanup(void)
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
	char			*host = NULL;
	int			family;
	hostrule_t		hstent;
	datum			key, data;
	struct myaddrinfo	*res, *res0;
	char			buf[1024], *tmp;
	char			ch, *ep;
	int			flags = 0, dbflags;
	int			ret;

	bzero(&hstent, sizeof(hstent));

	while ((ch = getopt(argc, argv, "a:h:l:nr:t:u:v")) != -1) {
		switch (ch) {
		case 'a':
			flags |= AFLAG;
			if (strncmp(optarg, UNLIM, strlen(UNLIM)) == 0) {
				hstent.attempts = ULONG_MAX;
				break;
			}
			hstent.attempts = strtoul(optarg, &ep, 10);
			if (*ep != '\0')
				errx(EX_DATAERR, "invalid attempts: %s",
				    optarg);
			break;

		case 'h':
			flags |= HFLAG;
			host = optarg;
			break;

		case 'l':
			ASSERT(MAX_CMD_LEN > 0)
			(void)strncpy(hstent.lock_cmd, optarg, MAX_CMD_LEN);
			hstent.lock_cmd[MAX_CMD_LEN - 1] = 0;
			break;

		case 'n':
			/* Do not replace existing records */
			flags |= NFLAG;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		case 't':
			flags |= TFLAG;
			if(parse_time(optarg, &hstent.locktime) != 0 || \
			    hstent.locktime < 0)
				errx(EX_DATAERR, "invalid time: %s", optarg);
			break;

		case 'u':
			ASSERT(MAX_CMD_LEN > 0)
			(void)strncpy(hstent.unlock_cmd, optarg, MAX_CMD_LEN);
			hstent.unlock_cmd[MAX_CMD_LEN - 1] = 0;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (!(flags & (HFLAG | AFLAG | TFLAG)))
		usage();
		/* NOTREACHED */

	dbflags = flags & NFLAG ? DBM_INSERT : DBM_REPLACE;

	/* Open rules database */
#ifdef O_EXLOCK
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_CREAT | O_EXLOCK, \
	    CFGDB_PERM);
#else
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_CREAT, \
	    CFGDB_PERM);
#endif
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  cfgdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(cfgdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", cfgdb);
#endif

	atexit(cleanup);

	/* Extract mask specification from hostname */
	hstent.mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        hstent.mask = strtoul(tmp, &ep, 10);
		if (*ep != '\0')
			errx(EX_DATAERR, "invalid mask: %s", tmp);
	}

	/*
         * We're assuming, that mask in 1-32 interval belongs to IPv4
	 * addresses, 33-128 - to IPv6 addresses, masks for other address
	 * families aren't supported. 0 means no mask.
	 */
	if (hstent.mask > 128)
		errx(EX_DATAERR, "invalid mask: %d", hstent.mask);
	else if (hstent.mask > 32)
		family = PF_INET6;
	else if (hstent.mask > 0)
		family = PF_INET;
	else
		family = PF_UNSPEC;

	if ((ret = my_getaddrinfo(host, family, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname '%s': %s", \
		    host, my_gai_strerror(ret));

	for (res = res0; res; res = res->next) {
		ASSERT(res->addr);
		key.dptr = res->addr;
		key.dsize = res->addrlen;
		data.dptr = (char *)&hstent;
		data.dsize = sizeof(hstent);
	
		ret = dbm_store(cfgdbp, key, data, dbflags);
		switch (ret) {
		case -1:
			err(EX_OSERR, "can't store record");
			/* NOTREACHED */
		case 1:
			if (flags & VFLAG)
				warnx("ignored duplicate: %s", host);
			continue;
		}
		if (flags & VFLAG) {
			if ((ret = my_getnameinfo(res->addr, res->addrlen, \
			    buf, sizeof(buf))) != 0)
				errx(EX_OSERR, "can't get numeric address: %s",\
				    gai_strerror(ret));
			(void)fprintf(stderr, "Stored rule for '%s'.\n", buf);
		}
	}
	my_freeaddrinfo(res0);

	exit(EX_OK);
}

static void
handle_rulemod(argc, argv)
	int	argc;	
	char	*argv[];
{
	char			*host = NULL;
	datum			key, data;
	struct myaddrinfo	*res, *res0;
	hostrule_t		hstent;
	unsigned long		attempts;
	long			locktime;
	char			*lockcmd = NULL;
	char			*unlockcmd = NULL;
	char			buf[1024], *tmp;
	int			found = 0;
	uint			mask;
	int			family;
	int			flags = 0, ret;
	char			ch, *ep;

	/* Avoid compiller warnings */
	attempts = 0;
	locktime = 0;

	while ((ch = getopt(argc, argv, "a:h:l:r:t:u:v")) != -1) {
		switch (ch) {
		case 'a':
			flags |= AFLAG;
			if (strncmp(optarg, UNLIM, strlen(UNLIM)) == 0) {
				attempts = ULONG_MAX;
				break;
			}
			attempts = strtoul(optarg, &ep, 10);
			if (*ep != '\0')
				errx(EX_DATAERR, "invalid attempts: %s",
				    optarg);
			break;

		case 'h':
			flags |= HFLAG;
			host = optarg;
			break;

		case 'l':
			flags |= LFLAG;
			lockcmd = optarg;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		case 't':
			flags |= TFLAG;
			if(parse_time(optarg, &locktime) != 0 || locktime < 0)
				errx(EX_DATAERR, "invalid time: %s", optarg);
			break;

		case 'u':
			flags |= UFLAG;
			unlockcmd = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (!(flags & HFLAG))
		usage();
		/* NOTREACHED */

	/* Open rules database */
#ifdef O_EXLOCK
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_EXLOCK, \
	    CFGDB_PERM);
#else
	cfgdbp = dbm_open(cfgdb, O_RDWR, \
	    CFGDB_PERM);
#endif
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  cfgdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(cfgdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", cfgdb);
#endif

	atexit(cleanup);

	/* Extract mask specification from hostname */
	mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        hstent.mask = strtoul(tmp, &ep, 10);
		if (*ep != '\0')
			errx(EX_DATAERR, "invalid mask: %s", tmp);
	}

	/*
         * We're assuming, that mask in 1-32 interval belongs to IPv4
	 * addresses, 33-128 - to IPv6 addresses, masks for other address
	 * families aren't supported. 0 means no mask.
	 */
	if (mask > 128)
		errx(EX_DATAERR, "invalid mask: %d", mask);
	else if (mask > 32)
		family = PF_INET6;
	else if (mask > 0)
		family = PF_INET;
	else
		family = PF_UNSPEC;

	if ((ret = my_getaddrinfo(host, family, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname '%s': %s", \
		    host, my_gai_strerror(ret));

	for (res = res0; res; res = res->next) {
		ASSERT(res->addr);
		key.dptr = res->addr;
		key.dsize = res->addrlen;
		
		if ((ret = my_getnameinfo(res->addr, res->addrlen, buf, \
		    sizeof(buf))) != 0)
			errx(EX_OSERR, "can't get numeric address: %s", \
			    gai_strerror(ret));

		data = dbm_fetch(cfgdbp, key);
		if (data.dptr == NULL) {
			if (flags & VFLAG) {
				warnx("record for address '%s' not found", buf);
			}
			continue;
		}
		else if (data.dsize != sizeof(hstent))
			errx(EX_DATAERR, "database '%s' seriously broken", \
			    cfgdb);
		else 
			bcopy(data.dptr, &hstent, sizeof(hstent));

		if (hstent.mask != mask)
			continue;

		if (flags & AFLAG)
			hstent.attempts = attempts;
		if (flags & TFLAG)
			hstent.locktime = locktime;
		if (flags & LFLAG) {
			ASSERT(MAX_CMD_LEN > 0)
			ASSERT(lockcmd)
			(void)strncpy(hstent.lock_cmd, lockcmd, MAX_CMD_LEN);
			hstent.lock_cmd[MAX_CMD_LEN - 1] = '\0';
		}
		if (flags & UFLAG) {
			ASSERT(MAX_CMD_LEN > 0)
			ASSERT(unlockcmd)
			(void)strncpy(hstent.unlock_cmd, unlockcmd, \
			    MAX_CMD_LEN);
			hstent.unlock_cmd[MAX_CMD_LEN - 1] = '\0';
		}

		data.dptr = (char *)&hstent;
		data.dsize = sizeof(hstent);
		if (dbm_store(cfgdbp, key, data, DBM_REPLACE) == -1)
			err(EX_OSERR, "can't store record");

		if (flags & VFLAG)
			fprintf(stderr, "Modified rule for '%s'.\n", buf);
		
		found = 1;
	}

	my_freeaddrinfo(res0);

	if (found == 0)
		warnx("no suitable records found");

	exit(EX_OK);
}

static void
handle_ruledel(argc, argv)
	int	argc;	
	char	*argv[];
{
	char			*host = NULL;
	char			buf[1024], *tmp;
	datum			key, data;
	struct myaddrinfo	*res, *res0;
	hostrule_t		*hstent;
	uint			mask;
	int			family;
	int			ret, flags = 0, found = 0;
	char			ch;

	while ((ch = getopt(argc, argv, "h:r:v")) != -1) {
		switch (ch) {
		case 'h':
			flags |= HFLAG;
			host = optarg;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (!(flags & HFLAG))
		usage();
		/* NOTREACHED */

	/* Open rules database */
#ifdef O_EXLOCK
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_EXLOCK, \
	    CFGDB_PERM);
#else
	cfgdbp = dbm_open(cfgdb, O_RDWR, \
	    CFGDB_PERM);
#endif
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  cfgdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(cfgdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", cfgdb);
#endif

	atexit(cleanup);

	/* Extract mask specification from hostname */
	mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        mask = atoi(tmp);
	}

	/*
         * We're assuming, that mask in 1-32 interval belongs to IPv4
	 * addresses, 33-128 - to IPv6 addresses, masks for other address
	 * families aren't supported. 0 means no mask.
	 */
	if (mask > 128)
		errx(EX_DATAERR, "invalid mask: %d", mask);
	else if (mask > 32)
		family = PF_INET6;
	else if (mask > 0)
		family = PF_INET;
	else
		family = PF_UNSPEC;

	if ((ret = my_getaddrinfo(host, family, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname '%s': %s", \
		    host, my_gai_strerror(ret));

	for (res = res0; res; res = res->next) {
		ASSERT(res->addr)
		key.dptr = res->addr;
		key.dsize = res->addrlen;
		
		if ((ret = my_getnameinfo(res->addr, res->addrlen, buf, \
		    sizeof(buf))) != 0)
			errx(EX_OSERR, "can't get numeric address: %s", \
			    gai_strerror(ret));

		data = dbm_fetch(cfgdbp, key);
		if (data.dptr == NULL) {
			if (flags & VFLAG) {
				warnx("record for address '%s' not found", buf);
			}
			continue;
		}
		else if (data.dsize != sizeof(*hstent))
			errx(EX_DATAERR, "database '%s' seriously broken", \
			    cfgdb);
		else 
			hstent = (hostrule_t *)data.dptr;

		if (hstent->mask != mask)
			continue;

		if (dbm_delete(cfgdbp, key) != 0)
			errx(EX_OSERR, "can't delete record for '%s'", buf);

		if (flags & VFLAG)
			(void)fprintf(stderr, "Deleted rule for '%s'.\n", buf);
		found = 1;
	}

	my_freeaddrinfo(res0);

	if (found == 0)
		warnx("no suitable records found");

	exit(EX_OK);
}

static void
handle_rulelist(argc, argv)
	int	argc;	
	char	*argv[];
{
	datum		key, data;
	hostrule_t	*hstent;
	char		buf[1024];
	int		ret;
	char		ch;

	while ((ch = getopt(argc, argv, "r:")) != -1) {
		switch (ch) {
		case 'r':
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
		err(EX_IOERR, "can't open '%s' database",  cfgdb);

	atexit(cleanup);

	printf("<hostrules>\n");
	for (key = dbm_firstkey(cfgdbp); key.dptr; key = dbm_nextkey(cfgdbp)) {

		if ((ret = my_getnameinfo(key.dptr, key.dsize, buf, \
		    sizeof(buf))) != 0)
			errx(EX_OSERR, "can't get numeric address: %s", \
			    gai_strerror(ret));

		data = dbm_fetch(cfgdbp, key);
		if (data.dptr == NULL) {
			err(EX_OSERR, "can't fetch data");
		}
		else if (data.dsize != sizeof(*hstent))
			errx(EX_DATAERR, "database '%s' seriously broken", \
			    cfgdb);
		else 
			hstent = (hostrule_t *)data.dptr;

		if (hstent->mask != 0)
			printf("\t<host ip='%s' mask='%d'>\n", buf, \
			    hstent->mask);
		else	
			printf("\t<host ip='%s'>\n", buf);

		if (hstent->attempts != ULONG_MAX)
			printf("\t\t<attempts>%ld</attempts>\n", \
			    hstent->attempts);
		else
			printf("\t\t<attempts>%s</attempts>\n", UNLIM);

		printf("\t\t<locktime>%ldS</locktime>\n", hstent->locktime);

		if (hstent->lock_cmd != NULL)
			printf("\t\t<lockcmd>%s</lockcmd>\n", \
			    hstent->lock_cmd);

		if (hstent->unlock_cmd != NULL)
			printf("\t\t<unlockcmd>%s</unlockcmd>\n", \
			    hstent->unlock_cmd);

		printf("\t</host>\n");
	}
	printf("</hostrules>\n");


	exit(EX_OK);
}

static void
handle_ruleflush(argc, argv)
	int	argc;	
	char	*argv[];
{
	datum	key;
	int	flags = 0;
	int	ret, i;
	char	ch;

	while ((ch = getopt(argc, argv, "r:v")) != -1) {
		switch (ch) {
		case 'r':
			cfgdb = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
#ifdef O_EXLOCK
	cfgdbp = dbm_open(cfgdb, O_RDWR | O_EXLOCK, \
	    CFGDB_PERM);
#else
	cfgdbp = dbm_open(cfgdb, O_RDWR, \
	    CFGDB_PERM);
#endif
	if (cfgdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  cfgdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(cfgdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", cfgdb);
#endif

	atexit(cleanup);

	i = 0;
	for (key = dbm_firstkey(cfgdbp); key.dptr; key = dbm_firstkey(cfgdbp)) {
		ret = dbm_delete(cfgdbp, key);
		if (ret != 0)
			err(EX_OSERR, "can't delete record");
		i++;
	}

	if (flags & VFLAG)
		(void)fprintf(stderr, "%d records flushed.\n",i); 

	exit(EX_OK);
}

static void
handle_statdel(argc, argv)
	int	argc;	
	char	*argv[];
{
	datum	key;
	char	*host = NULL;
	int	flags = 0, ret;
	char	ch;

	while ((ch = getopt(argc, argv, "h:s:v")) != -1) {
		switch (ch) {
		case 'h':
			flags |= HFLAG;
			host = optarg;
			break;

		case 's':
			stdb = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (!(flags & HFLAG))
		usage();
		/* NOTREACHED */

	/* Open statistics database */
#ifdef O_EXLOCK
	stdbp = dbm_open(stdb, O_RDWR | O_EXLOCK, \
	    STATDB_PERM);
#else
	stdbp = dbm_open(stdb, O_RDWR, \
	    STATDB_PERM);
#endif
	if (stdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  stdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(stdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", stdb);
#endif

	atexit(cleanup);

	key.dptr = host;
	key.dsize = strlen(host) + 1;
	
	ret = dbm_delete(stdbp, key);
	switch (ret) {
	case -1:
		err(EX_OSERR, "can't delete record");
	case 1:
		warnx("record not found");
	}
	
	if (flags & VFLAG)
		(void)fprintf(stderr, "Deleted.\n");


	exit(EX_OK);
}

static void
handle_statlist(argc, argv)
	int	argc;	
	char	*argv[];
{
	datum		key, data;
	hostrec_t	*hstrec;
	char		*tstr;
	char		ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
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
		err(EX_IOERR, "can't open '%s' database",  stdb);

	atexit(cleanup);

	printf("<hoststat>\n");
	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_nextkey(stdbp)) {
		data = dbm_fetch(stdbp, key);
		if (data.dptr == NULL)
			err(EX_OSERR, "can't fetch data");
		else if (data.dsize != sizeof(*hstrec))
			errx(EX_DATAERR, "database '%s' seriously broken", \
			    stdb);
		else
			hstrec = (hostrec_t *)data.dptr;

		printf("\t<host hostname='%s'>\n", (char *)key.dptr);
		printf("\t\t<attempts>%ld</attempts>\n", hstrec->num);
		tstr = ctime((const time_t *)&hstrec->last_attempt);
		ASSERT(strlen(tstr) > 0)
		tstr[strlen(tstr) - 1] = 0;
		printf("\t\t<last_attempt>%s</last_attempt>\n", tstr);
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
	datum key;
	int flags = 0;
	int ret, i;
	char ch;

	while ((ch = getopt(argc, argv, "s:v")) != -1) {
		switch (ch) {
		case 's':
			stdb = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open rules database */
#ifdef O_EXLOCK
	stdbp = dbm_open(stdb, O_RDWR | O_EXLOCK, \
	    STATDB_PERM);
#else
	stdbp = dbm_open(stdb, O_RDWR, \
	    STATDB_PERM);
#endif
	if (stdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  stdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(stdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", stdb);
#endif

	atexit(cleanup);

	i = 0;
	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_firstkey(stdbp)) {
		ret = dbm_delete(stdbp, key);
		if (ret != 0)
			err(EX_OSERR, "can't delete record");
		i++;
	}

	if (flags & VFLAG)
		(void)fprintf(stderr, "%d records deleted.\n", i); 

	exit(EX_OK);
}

static void
handle_lock(argc, argv)
	int	argc;	
	char	*argv[];
{
	char		*host = NULL;
	int		flags = 0, ret;
	datum		key;
	char		ch;
	struct host_list {
		char			*host;
		struct host_list	*next;
	} *hosts = NULL, *hosts0, **hstp;
		

	while ((ch = getopt(argc, argv, "fh:r:s:v")) != -1) {
		switch (ch) {
		case 'f':
			flags |= FFLAG;
			break;

		case 'h':
			flags |= HFLAG;
			host = optarg;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		case 's':
			stdb = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open statistics database */
	stdbp = dbm_open(stdb, O_RDONLY, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  stdb);

	atexit(cleanup);

	if (flags & HFLAG) {
		ret = lock_host(host, flags & FFLAG);
		if (ret == 0 && (flags & VFLAG))
			fprintf(stderr, "Host '%s' is now locked.\n", host);
		
		exit(EX_OK);
	}

	hstp = &hosts;
	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_nextkey(stdbp)) {
		if (key.dsize <= 0)
			errx(EX_OSERR, "database %s seriously broken", stdb);

		*hstp = malloc(sizeof(struct host_list));
		if (*hstp == NULL)
			err(EX_OSERR, "malloc()");

		bzero(*hstp, sizeof(struct host_list));
		(*hstp)->host = pam_af_strdupn(key.dptr, key.dsize);
		if ((*hstp)->host == NULL)
			err(EX_OSERR, "malloc()");

		hstp = &((*hstp)->next);
	}
	
	dbm_close(stdbp);
	stdbp = NULL;

	while(hosts) {
		ret = lock_host(hosts->host, flags & FFLAG);
		if (ret == 0 && (flags & VFLAG))
			fprintf(stderr, "Host '%s' is now locked.\n", \
				    hosts->host);
		hosts0 = hosts;
		hosts = hosts->next;
		free(hosts0->host);
		free(hosts0);
	}

	exit(EX_OK);
}

static void
handle_unlock(argc, argv)
	int	argc;	
	char	*argv[];
{
	char		*host = NULL;
	int		flags = 0, ret;
	datum		key;
	char		ch;
	struct host_list {
		char			*host;
		struct host_list	*next;
	} *hosts = NULL, *hosts0, **hstp;
		

	while ((ch = getopt(argc, argv, "fh:r:s:v")) != -1) {
		switch (ch) {
		case 'f':
			flags |= FFLAG;
			break;

		case 'h':
			flags |= HFLAG;
			host = optarg;
			break;

		case 'r':
			cfgdb = optarg;
			break;

		case 's':
			stdb = optarg;
			break;

		case 'v':
			flags |= VFLAG;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Open statistics database */
	stdbp = dbm_open(stdb, O_RDONLY, \
	    STATDB_PERM);
	if (stdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  stdb);

	atexit(cleanup);

	if (flags & HFLAG) {
		ret = unlock_host(host, flags & FFLAG);
		if (ret == 0 && (flags & VFLAG))
			fprintf(stderr, "Host '%s' is now locked.\n", host);
		
		exit(EX_OK);
	}

	hstp = &hosts;
	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_nextkey(stdbp)) {
		if (key.dsize <= 0)
			errx(EX_OSERR, "database %s seriously broken", stdb);

		*hstp = malloc(sizeof(struct host_list));
		if (*hstp == NULL)
			err(EX_OSERR, "malloc()");

		bzero(*hstp, sizeof(struct host_list));
		(*hstp)->host = pam_af_strdupn(key.dptr, key.dsize);
		if ((*hstp)->host == NULL)
			err(EX_OSERR, "malloc()");

		hstp = &((*hstp)->next);
	}
	
	dbm_close(stdbp);
	stdbp = NULL;

	while(hosts) {
		ret = unlock_host(hosts->host, flags & FFLAG);
		if (ret == 0 && (flags & VFLAG))
			fprintf(stderr, "Host '%s' is now unlocked.\n", \
				    hosts->host);
		hosts0 = hosts;
		hosts = hosts->next;
		free(hosts0->host);
		free(hosts0);
	}

	exit(EX_OK);
}

/*
 * The purpose of this routine is to check if host must be locked or not,
 * and to make locking work in true case.
 */
int
lock_host(host, force)
	char			*host;
	int			force;
{
	char		*env[2];
	datum		key, data;
	hostrec_t	hstrec;
	hostrule_t	*hstent;

	/*
	 * Setup enviropment for possible command's execution
	 */
	if (asprintf(&env[0], "PAM_RHOST=%s", host) < 0)
		err(EX_OSERR, "malloc()");
	env[1] = NULL;

	/*
	 * Get rule for this host
	 */

	/* find_host_rule returns pointer to it's static data */
	hstent = find_host_rule(cfgdb, host);
	ASSERT(hstent);

	/* Open statistics database */
#ifdef O_EXLOCK
	stdbp = dbm_open(stdb, O_RDWR | O_EXLOCK, \
	    STATDB_PERM);
#else
	stdbp = dbm_open(stdb, O_RDWR, \
	    STATDB_PERM);
#endif
	if (stdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  stdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(stdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", stdb);
#endif
	key.dptr = host;
	key.dsize = strlen(host) + 1;
	data = dbm_fetch(stdbp, key);
	if (data.dptr == NULL)
		err(EX_OSERR, "can't fetch data");
	else if (data.dsize != sizeof(hstrec))
		errx(EX_DATAERR, "database '%s' seriously broken", \
		    stdb);
	else
		bcopy(data.dptr, &hstrec, sizeof(hstrec));

	if (hstrec.locked_for == 0 && hstent->locktime != 0 &&
	    ((hstrec.num >= hstent->attempts) || force != 0)) {
		hstrec.locked_for = hstent->locktime;
		hstrec.last_attempt = time(NULL);
		if (hstent->lock_cmd != NULL)
			(void)exec_cmd(hstent->lock_cmd, env);

		/* Free asprintf-allocated buffer */
		free(env[0]);

		/* Restore all structures - some implemetations can break it */
		data.dptr = (char *)&hstrec;
		data.dsize = sizeof(hstrec);
		key.dptr = host;
		key.dsize = strlen(host) + 1;

		if (dbm_store(stdbp, key, data, DBM_REPLACE) != 0)
			err(EX_OSERR, "can't store record");

		dbm_close(stdbp);
		stdbp = NULL;
		return 0;
	}

	dbm_close(stdbp);
	stdbp = NULL;
	return 1;
}

/*
 * The purpose of this routine is to check if host can be unlocked or not,
 * and to make unlocking work in true case.
 */
int
unlock_host(host, force)
	char			*host;
	int			force;
{
	char		*env[2];
	datum		key, data;
	hostrec_t	hstrec;
	hostrule_t	*hstent;

	/*
	 * Setup enviropment for possible command's execution
	 */
	if (asprintf(&env[0], "PAM_RHOST=%s", host) < 0)
		err(EX_OSERR, "malloc()");
	env[1] = NULL;

	/*
	 * Get rule for this host
	 */

	/* find_host_rule returns pointer to it's static data */
	hstent = find_host_rule(cfgdb, host);
	ASSERT(hstent);

	/* Open statistics database */
#ifdef O_EXLOCK
	stdbp = dbm_open(stdb, O_RDWR | O_EXLOCK, \
	    STATDB_PERM);
#else
	stdbp = dbm_open(stdb, O_RDWR, \
	    STATDB_PERM);
#endif
	if (stdbp == NULL)
		err(EX_IOERR, "can't open '%s' database",  stdb);

#ifndef O_EXLOCK
	/* If we can't obtain lock through open(2) */
	if (flock(dbm_pagfno(stdbp), LOCK_EX) != 0)
		err(EX_IOERR, "can't obtain exclusive lock on %s: %s\n", stdb);
#endif
	key.dptr = host;
	key.dsize = strlen(host) + 1;
	data = dbm_fetch(stdbp, key);
	if (data.dptr == NULL)
		err(EX_OSERR, "can't fetch data");
	else if (data.dsize != sizeof(hstrec))
		errx(EX_DATAERR, "database '%s' seriously broken", \
		    stdb);
	else
		bcopy(data.dptr, &hstrec, sizeof(hstrec));

	if ((hstrec.last_attempt + hstrec.locked_for < (unsigned)time(NULL) || \
	    force != 0) && hstrec.locked_for != 0) {
		hstrec.locked_for = 0;
		hstrec.num = 0;
		if (hstent->unlock_cmd != NULL)
			(void)exec_cmd(hstent->unlock_cmd, env);

		/* Free asprintf-allocated buffer */
		free(env[0]);

		/* Restore all structures - some implemetations can break it */
		data.dptr = (char *)&hstrec;
		data.dsize = sizeof(hstrec);
		key.dptr = host;
		key.dsize = strlen(host) + 1;

		if (dbm_store(stdbp, key, data, DBM_REPLACE) != 0)
			err(EX_OSERR, "can't store record");

		dbm_close(stdbp);
		stdbp = NULL;
		return 0;
	}

	dbm_close(stdbp);
	stdbp = NULL;
	return 1;
}
