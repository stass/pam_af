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
 * $Id: pam_af.c,v 1.3 2005/08/16 00:40:10 stas Exp $
 */

#include <errno.h>
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
#include <ndbm.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>
#include <security/openpam.h>

#define PAM_AF_DEFS
#include "pam_af.h"
#include "subr.h"

/* Prototypes */
static char **	pam_af_build_env	__P((pam_handle_t *pamh));

extern const char * cfgdb;
extern const char * stdb;

#define ENV_ITEM(item) {(item), #item}
static struct {
	int item;
	const char *name;
} env_items[] = {
	ENV_ITEM(PAM_SERVICE),
	ENV_ITEM(PAM_TTY),
	ENV_ITEM(PAM_USER),
	ENV_ITEM(PAM_RUSER),
	ENV_ITEM(PAM_RHOST)
};

#define PAM_AF_LOGERR(...) \
	openpam_log(PAM_LOG_ERROR, __VA_ARGS__)
#define PAM_AF_LOG(...) \
	openpam_log(PAM_LOG_VERBOSE, __VA_ARGS__)
	

static char **
pam_af_build_env(pamh)
	pam_handle_t	*pamh;
{
	int ret;
	int nitems, newitems;
	register int i;
	char **env, **tmp;
	char *item;
	char *envstr;
			
	env = pam_getenvlist(pamh);
	for (nitems = 0; env[nitems] != NULL; nitems++);
	newitems = sizeof(env_items) / sizeof(*env_items);
	tmp = realloc(env, (nitems + newitems + 1) \
	    * sizeof(*env));
	if (tmp == NULL) {
		PAM_AF_LOGERR("malloc(%d): %s",
		    nitems * sizeof(*env),
		    strerror(errno));
		openpam_free_envlist(env);
		return NULL;
	}
	env = tmp;
	for (i = 0; i < newitems; i++) {
		ret = pam_get_item(pamh, env_items[i].item,
		    (const void **)&item);
		if (ret != PAM_SUCCESS || item == NULL) {
			PAM_AF_LOG("can't get %s item", env_items[i].name);
			continue;
		}
		asprintf(&envstr, "%s=%s", env_items[i].name, item);
		if (envstr == NULL) {
			/* Maybe we'll be more lucky on next loop */
			PAM_AF_LOG("can't allocate memory: %s", \
			    strerror(errno));
			continue;
		}
		env[nitems++] = envstr;
		env[nitems] = NULL;
	}

	return env;
}

PAM_EXTERN int
pam_sm_authenticate(pamh, flags, argc, argv)
	pam_handle_t	*pamh;
	int		flags __unused;
	int		argc __unused;
	const char	*argv[] __unused;
{
	char *host;
	DBM *stdbp;
	datum key, data;
	hostrec_t hstr;
	hostrule_t *hostent;
	register time_t curtime;
	int ret, pam_ret = PAM_SUCCESS;
	int pam_err_ret = PAM_AUTH_ERR;
	int unlocked = 0;
	const char *tmp;
	char	ebuf[1024];
	char **env;

	int update_when_locked = 0; /* Update host stats when it's locked */

	PASS
	/* Get runtime configuration */
	if (openpam_get_option(pamh, "allow_on_error") != NULL)
		pam_err_ret = PAM_SUCCESS; 
	if (openpam_get_option(pamh, "update_locked") != NULL)
		update_when_locked = 1; 
	if ((tmp = openpam_get_option(pamh, "statdb")) != NULL)
		stdb = tmp;	
	if ((tmp = openpam_get_option(pamh, "cfgdb")) != NULL)
		cfgdb = tmp;	

	/* Get hostname */
	ret = pam_get_item(pamh, PAM_RHOST, (const void **)&host);
	if (ret != PAM_SUCCESS) {
		PAM_AF_LOGERR("can't get RHOST item");
		PAM_RETURN(pam_err_ret);
	}

	PAM_AF_LOG("processing host %s", host);

	/* Open statistics database and obtain exclusive lock */
	stdbp = dbm_open(stdb, O_RDWR | O_CREAT | O_EXLOCK, STATDB_PERM);
	if (stdbp == NULL) {
		PAM_AF_LOGERR("can't open statistics database %s: %s", \
		    stdb, strerror(errno));
		PAM_RETURN(pam_err_ret);
	}

	key.dptr = host;
	key.dsize = strlen(host) + 1;
	curtime = time(NULL);

	data = dbm_fetch(stdbp, key);
	if (data.dptr == NULL) {
		/* Not found */
		PAM_AF_LOG("host record not found in statistics database");
		hstr.num = 0;
		hstr.last_attempt = curtime;
		hstr.locked_for = 0;
	}
	else {
		PAM_AF_LOG("found host record in statistics database");
		if (data.dsize != sizeof(hstr)) {
			PAM_AF_LOGERR("database %s seriously broken", stdb);
			PAM_RETURN(pam_err_ret);	
		}
		bcopy(data.dptr, &hstr, sizeof(hstr));
	}
	
	/* Unlock host, if needed */
	if (hstr.locked_for != 0 && 
	    (curtime - hstr.last_attempt) > hstr.locked_for) {
		hstr.num = 0;
		hstr.locked_for = 0;
		unlocked = 1;
		pam_ret = PAM_SUCCESS;
	}

	/* Account current attempt too */
	hstr.num++;

	/* If it has locked yet, reject it */
	if (hstr.locked_for != 0) {
		PAM_AF_LOG("rejecting host %s, its blocked for %ld since %ld", \
		    (char *)host, hstr.last_attempt, hstr.locked_for);

		pam_ret = PAM_AUTH_ERR;
		if (update_when_locked == 0) {
			/* Fast rejection */
			dbm_close(stdbp);
			PAM_RETURN(pam_ret);
		}
	}

	hstr.last_attempt = curtime;

	/* Fetch rule for host */
	hostent = find_host_rule(cfgdb, host);
	ASSERT(hostent);

	/*
	 * Build enviropment, includind PAM_RHOST, PAM_RUSER, PAM_USER,
	 * PAM_TTY, PAM_SERVICE and other values. Then they could be used
	 * by external commands to do host or user-specific work.
	 */
	if ((env = pam_af_build_env(pamh)) == NULL) {
		PAM_AF_LOGERR("can't build env list");
	}

	/* Execute unlocking cmd, if needed */
	if (unlocked != 0 && strlen(hostent->unlock_cmd) > 0) {
		ret = exec_cmd(hostent->unlock_cmd, env, ebuf, sizeof(ebuf));
		if (ret != 0)
			PAM_AF_LOGERR("error executing unlocking cmd: %s", \
			    ebuf);
	}

	/* Lock host, if needed */
	if (hstr.num > hostent->attempts && hostent->attempts != 0) {
		PAM_AF_LOG("blocking host %s", host);
		hstr.locked_for = hostent->locktime;
		pam_ret = PAM_AUTH_ERR;
		if (strlen(hostent->lock_cmd) > 0) {
			ret = exec_cmd(hostent->unlock_cmd, env, ebuf, \
			    sizeof(ebuf));
			if (ret != 0)
				PAM_AF_LOGERR("error executing locking cmd:" \
				    " %s", ebuf);
		}
	}

	data.dptr = (char *)&hstr;
	data.dsize = sizeof(hstr);
	key.dptr = host;
	key.dsize = strlen(host) + 1;

	ret = dbm_store(stdbp, key, data, DBM_REPLACE);
	if (ret != 0)
		PAM_AF_LOGERR("can't update record: %s", strerror(ret));

	dbm_close(stdbp);

	PAM_RETURN(pam_ret);
}

PAM_EXTERN int
pam_sm_setcred(pamh, flags, argc, argv)
	pam_handle_t	*pamh;
	int		flags __unused;
	int		argc __unused;
	const char	*argv[] __unused;
{
	char *host;
	DBM *stdbp;
	datum key, data;
	hostrec_t hstr;
	int ret;
	const char *tmp;

	if ((tmp = openpam_get_option(pamh, "statdb")) != NULL)
		stdb = tmp;	

	/* Get peer host */
	ret = pam_get_item(pamh, PAM_RHOST, (const void **)&host);
	if (ret != PAM_SUCCESS) {
		PAM_AF_LOGERR("can't get RHOST item");
		PAM_RETURN(PAM_SERVICE_ERR);
	}

	/* Open statistics database */
	stdbp = dbm_open(stdb, O_RDWR | O_CREAT | O_EXLOCK, STATDB_PERM);
	if (stdbp == NULL) {
		PAM_AF_LOGERR("can't open statistics database %s: %s", \
		    stdb, strerror(errno));
		PAM_RETURN(PAM_CRED_UNAVAIL);
	}

	/* Update records */
	hstr.num = 0;
	hstr.locked_for = 0;
	hstr.last_attempt = time(NULL);

	data.dptr = (char *)&hstr;
	data.dsize = sizeof(hstr);
	key.dptr = host;
	key.dsize = strlen(host) + 1;

	ret = dbm_store(stdbp, key, data, DBM_REPLACE);
	if (ret != 0)
		PAM_AF_LOGERR("can't update record: %s", \
		    strerror(ret));

	dbm_close(stdbp);

	PAM_RETURN(PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_af");
