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
 * $Id: pam_af_tool.c,v 1.7 2005/08/16 23:46:45 stas Exp $
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

	fprintf(stderr, "usage:\n"					\
	    "\t%1$s ruleadd -h host -a attempts -t time"		\
	    "\n\t\t[-l cmd] [-u cmd] [-d file] [-v]\n"			\
	    "\t%1$s rulemod -h host [-a attempts] [-t time]"		\
	    "\n\t\t[-l cmd] [-u cmd] [-d file] [-v]\n"			\
	    "\t%1$s ruledel -h host [-d file] [-v]\n"			\
	    "\t%1$s rulelist [-d file]\n"				\
	    "\t%1$s ruleflush [-d file] [-v]\n"				\
	    "\t%1$s statdel -h host [-d file] [-v]\n"			\
	    "\t%1$s statlist [-d file]\n"				\
	    "\t%1$s statflush [-d file] [-v]\n"				\
	    "\t%1$s lock [-h host] [-s file] [-r file] [-fv]\n"		\
	    "\t%1$s unlock [-h host] [-s file] [-r file] [-fv]\n", 	\
	    getprogname());

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
	struct myaddrinfo *res, *res0;
	hostrule_t hstent;
	char *tmp;
	char buf[1024];
	int family;

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

	/* Extract mask specification from hostname */
	hstent.mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        hstent.mask = atoi(tmp);
	}

	if (hstent.mask > 128)
		errx(EX_USAGE, "invalid mask");
	else if (hstent.mask > 32)
		family = PF_INET6;
	else if (hstent.mask > 0)
		family = PF_INET;
	else
		family = PF_UNSPEC;

	if ((ret = my_getaddrinfo(host, family, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname %s: %s", \
		    host, my_gai_strerror(ret));
	for (res = res0; res; res = res->next) {
		key.dptr = res->addr;
		key.dsize = res->addrlen;
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
			if (ret = my_getnameinfo(res->addr, res->addrlen, \
			    buf, sizeof(buf)) != 0)
				errx(EX_OSERR, "can't get numeric address: %s",\
				    gai_strerror(ret));
			fprintf(stderr, "Stored rule for %s.\n", buf);
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
	int ch, ret, flags = DBM_REPLACE;
	char *host = NULL;
	datum key, data;
	struct myaddrinfo *res, *res0;
	hostrule_t *hstent;
	long attempts = -1, locktime = -1;
	char *lockcmd = NULL, *unlockcmd = NULL;
	char buf[1024];
	char *tmp;
	int found = 0;
	int mask;
	int family;

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

	/* Extract mask specification from hostname */
	mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        mask = atoi(tmp);
	}

	if (mask > 128)
		errx(EX_USAGE, "invalid mask");
	else if (mask > 32)
		family = PF_INET6;
	else if (mask > 0)
		family = PF_INET;
	else
		family = PF_UNSPEC;

	if ((ret = my_getaddrinfo(host, family, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname %s: %s", \
		    host, my_gai_strerror(ret));

	for (res = res0; res; res = res->next) {
		key.dptr = res->addr;
		key.dsize = res->addrlen;
		
		if (ret = my_getnameinfo(res->addr, res->addrlen, buf, \
		    sizeof(buf)) != 0)
			errx(EX_OSERR, "can't get numeric address: %s", \
			    gai_strerror(ret));

		data = dbm_fetch(cfgdbp, key);
		if (data.dptr == NULL) {
			if (vflag) {
				warnx("record for address %s not found", buf);
			}
			continue;
		}
		else if (data.dsize != sizeof(*hstent))
			errx(EX_DATAERR, "database %s seriously broken", cfgdb);
		else 
			hstent = (hostrule_t *)data.dptr;

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

		if (dbm_store(cfgdbp, key, data, flags) == -1)
			err(EX_OSERR, "can't store record");

//		if (vflag)
//			warnx("modified rule for ip %s", buf);
/* XXX: fix */
		
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
	int ch, ret, found = 0;
	char *host = NULL;
	datum key, data;
	struct myaddrinfo *res, *res0;
	hostrule_t *hstent;
	char *tmp;
	int mask;
	char buf[1024];
	int family;

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

	/* Extract mask specification from hostname */
	mask = 0;
	if ((tmp = strchr(host, '/')) != NULL) {
	        *tmp = '\0';
	        tmp++;
	        mask = atoi(tmp);
	}

	if (mask > 128)
		errx(EX_USAGE, "invalid mask");
	else if (mask > 32)
		family = PF_INET6;
	else if (mask > 0)
		family = PF_INET;
	else
		family = PF_UNSPEC;

	if ((ret = my_getaddrinfo(host, family, &res0)) != 0)
		errx(EX_DATAERR, "can't resolve hostname %s: %s", \
		    host, my_gai_strerror(ret));

	for (res = res0; res; res = res->next) {
		key.dptr = res->addr;
		key.dsize = res->addrlen;
		
		if (ret = my_getnameinfo(res->addr, res->addrlen, buf, \
		    sizeof(buf)) != 0)
			errx(EX_OSERR, "can't get numeric address: %s", \
			    gai_strerror(ret));

		data = dbm_fetch(cfgdbp, key);
		if (data.dptr == NULL) {
			if (vflag) {
				warnx("record for address %s not found", buf);
			}
			continue;
		}
		else if (data.dsize != sizeof(*hstent))
			errx(EX_DATAERR, "database %s seriously broken", cfgdb);
		else 
			hstent = (hostrule_t *)data.dptr;

		if (hstent->mask != mask)
			continue;

		if (dbm_delete(cfgdbp, key) != 0)
			errx(EX_OSERR, "can't delete record for %s", buf);

		if (vflag)
			fprintf(stderr, "Deleted %s.\n", buf);
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

	printf("<hostrules>\n");
	for (key = dbm_firstkey(cfgdbp); key.dptr; key = dbm_nextkey(cfgdbp)) {

		if (ret = my_getnameinfo(key.dptr, key.dsize, buf, \
		    sizeof(buf)) != 0)
			errx(EX_OSERR, "can't get numeric address: %s", \
			    gai_strerror(ret));

		data = dbm_fetch(cfgdbp, key);
		if (data.dptr == NULL) {
			err(EX_OSERR, "can't fetch data");
		}
		else if (data.dsize != sizeof(*hstent))
			errx(EX_DATAERR, "database %s seriously broken", cfgdb);
		else 
			hstent = (hostrule_t *)data.dptr;

		if (hstent->mask != 0)
			printf("\t<host ip='%s' mask='%d'>\n", buf, hstent->mask);
		else	
			printf("\t<host ip='%s'>\n", buf);

		if (hstent->attempts != 0)
			printf("\t\t<attempts>%ld</attempts>\n", \
			    hstent->attempts);
		else
			printf("\t\t<attempts>%s</attempts>\n", UNLIM);

		printf("\t\t<locktime>%lds</locktime>\n", hstent->locktime);

		if (hstent->lock_cmd != NULL)
			printf("\t\t<lockcmd>%s</lockcmd>\n", hstent->lock_cmd);

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

	printf("<hoststat>\n");
	for (key = dbm_firstkey(stdbp); key.dptr; key = dbm_nextkey(stdbp)) {
		data = dbm_fetch(stdbp, key);
		if (data.dptr == NULL)
			err(EX_OSERR, "can't fetch data from %s", stdb);
		else if (data.dsize != sizeof(*hstrec))
			errx(EX_DATAERR, "database %s seriously broken", stdb);
		else
			hstrec = (hostrec_t *)data.dptr;

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

	atexit(cleanup);

	if (host != NULL) {
		key.dptr = host;
		key.dsize = strlen(host) + 1;
		data = dbm_fetch(stdbp, key);
		if (data.dptr == NULL)
			err(EX_OSERR, "can't fetch data from %s", stdb);
		else if (data.dsize != sizeof(*hstrec))
			errx(EX_DATAERR, "database %s seriously broken", stdb);
		else
			hstrec = (hostrec_t *)data.dptr;
		/* XXX: report used ip */

		/* XXX: let find_host_rule opens base */
		hstent = find_host_rule(cfgdb, host);
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
			if (data.dptr == NULL)
				err(EX_OSERR, "can't fetch data from %s", stdb);
			else if (data.dsize != sizeof(*hstrec))
				errx(EX_DATAERR, "database %s seriously " \
				    "broken", stdb);
			else
				hstrec = (hostrec_t *)data.dptr;

			hstent = find_host_rule(cfgdb, key.dptr);
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

	atexit(cleanup);

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	if (host != NULL) {
		key.dptr = host;
		key.dsize = strlen(host) + 1;
		data = dbm_fetch(stdbp, key);
		if (data.dptr == NULL)
			err(EX_OSERR, "can't fetch data from %s", stdb);
		else if (data.dsize != sizeof(*hstrec))
			errx(EX_DATAERR, "database %s seriously broken", stdb);
		else
			hstrec = (hostrec_t *)data.dptr;
		/* XXX: report used ip */

		hstent = find_host_rule(cfgdb, host);
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
			if (data.dptr == NULL)
				err(EX_OSERR, "can't fetch data from %s", stdb);
			else if (data.dsize != sizeof(*hstrec))
				errx(EX_DATAERR, "database %s seriously " \
				    "broken", stdb);
			else
				hstrec = (hostrec_t *)data.dptr;

/* XXX: check key.dsize */
			hstent = find_host_rule(cfgdb, key.dptr);
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
