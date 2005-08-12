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
 * $Id: pam_af.c,v 1.1 2005/08/12 01:29:07 stas Exp $
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
#include <db.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>
#include <security/openpam.h>

#define DBNAME "/var/db/pam_af.db"
#define PERM (S_IRUSR|S_IWUSR)
#define UNSPECIFIED -1

/* Global definitions */
#define _PAM_AF_MAX_CMD_LEN 255
#define _PAM_AF_CFGDB_PATH "/etc/pam_af.conf"

#define _PAM_AF_ATTEMPTS_CAP "attempts"
#define _PAM_AF_LOCKTIME_CAP "locktime"
#define _PAM_AF_LOCKCMD_CAP "cmd_lock"
#define _PAM_AF_UNLOCKCMD_CAP "cmd_unlock"
#define DEFCAP "default"

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

#define PAM_AF_DEBUG
#if defined(PAM_AF_DEBUG)
# define ASSERT(exp) \
	assert(exp);
# define PASS \
	PAM_AF_LOGERR("pass: %d", __LINE__);
#else
# define ASSERT(exp)
# define PASS
#endif

typedef struct hostrec {
	long	num;
	long	last_attempt;
	long	locked_for; /* Time the host blocked for, 0 if not blocked */
} hostrec_t;

typedef struct hostrule {
	long attempts;
	long locktime;
	char lock_cmd[_PAM_AF_MAX_CMD_LEN];
	char unlock_cmd[_PAM_AF_MAX_CMD_LEN];
} hostrule_t;
	
static char cfgdbpath[] = _PAM_AF_CFGDB_PATH;
static char *capdb[2] = {cfgdbpath, NULL};

static const char	*capdb_strerror __P((int error));
static int		pam_af_parse_time __P((const char *str, long *ptime));
static int		pam_af_addr_cmp __P((const void *addr1, \
    const void *addr2, size_t addrlen, int32_t mask));
static hostrule_t	*pam_af_get_host_rule __P((pam_handle_t *pamh, \
    int flags, const void *addr, int family));
static int		pam_af_exec_cmd __P((pam_handle_t *pamh, const char *str));

static const char *
capdb_strerror(error)
	int error;
{
	static const char *errors[] = {
		"tc expansion failed",
		"reference loop detected",
		"record not found",
		"system error",
		"unknown error"
	};

	switch (error) {
	case 1:
		return errors[0];
		break;
	case -1:
		return errors[2];
		break;
	case -2:
		return errors[3];
		break;
	case -3:
		return errors[1];
		break;
	default:
		return errors[4];
	}
}

static int
pam_af_addr_cmp(addr1, addr2, addrlen, mask)
	const void	*addr1;
	const void	*addr2;
	size_t		addrlen;
	int32_t		mask;
{
	int bytes = mask / 8;
	int left = mask % 8;
	register int8_t byte1 = 0, byte2 = 0;

	if (mask > (signed)addrlen * 8)
		return 1;
	
	if (mask == UNSPECIFIED || mask <= (signed)addrlen * 2) {
		bytes = addrlen;
		left = 0;
	}

	PAM_AF_LOGERR("bytes = %d", bytes);
	if (bcmp(addr1 ,addr2, bytes) != 0)
		return 1;

	if (left != 0) {
		byte1 = ((const int8_t *)addr1)[bytes];
		byte1 = ((const int8_t *)addr2)[bytes];

		byte1 >>= (8 - left);
		byte2 >>= (8 - left);
	}

	if (byte1 == byte2) {
		return 0;
	}
	else
		return 1;
}
static int
pam_af_exec_cmd(pamh, str)
	pam_handle_t	*pamh;
	const char	*str;
{
	int pid, ret, status;
	int nitems, newitems;
	register int i;
	char **env, **tmp;
	char *item;
	char *envstr;
			
	/* Build enviropment list */
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
		return 1;
	}
	env = tmp;
	for (i = 0; i < newitems; i++) {
		ret = pam_get_item(pamh, env_items[i].item,
		    (const void **)&item);
		if (ret != PAM_SUCCESS || item == NULL) {
			PAM_LOG("can't get %s item", env_items[i].name);
			continue;
		}
		asprintf(&envstr, "%s=%s", env_items[i].name, item);
		if (envstr == NULL) {
			/* Maybe we'll be more lucky on next loop */
			PAM_LOG("can't allocate memory: %s", strerror(errno));
			free(item);
			continue;
		}
		env[nitems++] = envstr;
		env[nitems] = NULL;
		free(item);
	}

	ret = 0;
	switch (pid = vfork()) {
	case 0:
		(void)execle(_PATH_BSHELL, "sh", "-c", str, NULL,
		    (char * const *)env);
		ret = errno;
		_exit(1);
		break;
	case -1:
		PAM_AF_LOGERR("can't fork: %s", strerror(errno));
		return 1;
		break;
	default:
		break;
	}

	openpam_free_envlist(env);

	if (waitpid(pid, &status, 0) == -1) {
		PAM_AF_LOGERR("waitpid(): %s", strerror(errno));
		return 1;
	}
	
	/* Check child exit value */
	if (ret != 0) {
		PAM_AF_LOGERR("execle('%s'): %s", _PATH_BSHELL,
		    strerror(errno));
		return 1;
	}

	if (WIFSIGNALED(status)) {
		PAM_AF_LOGERR("External cmd caught signal %d%s",
		    WTERMSIG(status),
		    WCOREDUMP(status) ? " (core dumped)" : "");
		return 1;
	}
	if (WIFEXITED(status) == 0) {
		PAM_AF_LOGERR("unknown status 0x%x", status);
		return 1;
	}
	if (WEXITSTATUS(status) != 0) {
		PAM_AF_LOGERR("External cmd returned code %d",
		    WEXITSTATUS(status));
		return 1;
	}

	return 0;	
}	

static int
pam_af_parse_time(str, ptime)
	const char	*str;
	long		*ptime;
{
	register long rettime = 0;
	register int i;
	char *p;
	
	for (i = strtol(str, &p, 0); *p != '\0'; i = strtol(++p, &p, 0)) {
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
			PAM_AF_LOGERR("Invalid character in date "
			    "specification: %c", *p);
			return -1;
		}
	}

	*ptime = rettime;
	return 0;
}

static hostrule_t *
pam_af_get_host_rule(pamh, flags, addr, family)
	pam_handle_t	*pamh __unused;
	int		flags __unused;
	const void	*addr;
	int		family;
{
	int ret;
	static hostrule_t hostent;
	char *buf;
	int namelen;
	char const *nameend;
	char *name, *maskstart, *locktime;
	char *lockcmd, *unlockcmd;
	struct addrinfo *res, *res0, hints;
	void *addr1;
	int32_t mask = 0;

	if (strncmp(DEFCAP, addr, strlen(DEFCAP)) == 0) {
		/* We are checking for "default" entry */
		ret = cgetent(&buf, capdb, DEFCAP);
		if (ret != 0) {
			PAM_AF_LOGERR("Can't get '%s' capability entry: %s", \
			    DEFCAP, capdb_strerror(ret));
			return NULL;
		}
	}
	else {
		for (ret = cgetfirst(&buf, capdb);
		     ret == 1;
		     ret = cgetnext(&buf, capdb)) {
			/* We're assuming the first name is valid */
			nameend = strpbrk(buf, "|:");
			if (nameend == 0)
				nameend = buf + strlen(buf); 
			namelen = nameend - buf;
			name = (char *)malloc(namelen + 1);
			if (name == NULL) {
				PAM_AF_LOGERR("Can't allocate memory: %s", \
				    strerror(errno));
				free(buf);
				/* Maybe we'll more lucky on next loop */
				continue;
			}
			*name = '\0';
			(void)strncat(name, buf, namelen);
				
			/* We don't want resolve 'default' */
			if (strncmp(DEFCAP, name, strlen(DEFCAP)) == 0) {
				free(name);
				free(buf);
				continue;
			}

			/* Extract mask specification from hostname */
			mask = UNSPECIFIED;
			if ((maskstart = strchr(name, '/')) != NULL) {
				*maskstart = '\0';
				maskstart++;
				mask = atoi(maskstart);
				if (mask < 0) {
					PAM_AF_LOGERR("Invalid netmask: %s, " \
					    "ignoring entry", maskstart);
					free(name);
					free(buf);
					continue;
				}
			}
		
			bzero(&hints, sizeof(hints));
			hints.ai_family = family;
			hints.ai_protocol = IPPROTO_TCP;
			if ((ret = getaddrinfo(name, NULL, NULL, &res0)) != 0) {
				PAM_AF_LOGERR("Can't resolve %s: %s", \
				    name, gai_strerror(ret));
				free(name);
				free(buf);
				continue;
			}
			for (res = res0; res != NULL; res = res->ai_next) {
				if (family == PF_INET)
				    addr1 = &(((struct sockaddr_in *) \
				    res->ai_addr)->sin_addr.s_addr);
				else
				    addr1 = ((struct sockaddr_in6 *) \
				    res->ai_addr)->sin6_addr.s6_addr;

				if (pam_af_addr_cmp(addr, addr1, \
				    family == PF_INET ? 4 : 16, mask) == 0) {
					freeaddrinfo(res0);
					free(name);
					goto found; 
				}
			}
			freeaddrinfo(res0);
			free(name);
			free(buf);
		}
		/* Not found */
		if (ret != 0) {
			/* End of database isn't reached */
			PAM_AF_LOGERR("Config file processing error: %s", \
			    capdb_strerror(ret));
			cgetclose();
		}
		return NULL;
	}
found:
	cgetclose();

	ASSERT(buf != NULL);
	if ((ret = cgetnum(buf,_PAM_AF_ATTEMPTS_CAP, &hostent.attempts)) != 0) {
		PAM_AF_LOGERR("Can't get '%s' value in host record: %s", \
		    "attempts", capdb_strerror(ret));
		free(buf);
		return NULL;
	}

	if ((ret = cgetstr(buf, _PAM_AF_LOCKTIME_CAP, &locktime)) <= 0) {
		PAM_AF_LOGERR("Can't get '%s' value in host record: %s", \
		    "locktime", capdb_strerror(ret));
		free(locktime);
		free(buf);
		return NULL;
	}
	else {
		ASSERT(locktime != NULL)
		ret = pam_af_parse_time(locktime, &hostent.locktime);
		if (ret != 0) {
			PAM_AF_LOGERR("Syntax error in time specification:"\
			    " %s\n", locktime);
			free(locktime);
			free(buf);
			return NULL;
		}
		free(locktime);
	}

	if ((ret = cgetstr(buf, _PAM_AF_LOCKCMD_CAP, &lockcmd)) <= 0) {
		hostent.lock_cmd[0] = '\0';
	}
	else {
		ASSERT(lockcmd != NULL);
		strncpy(hostent.lock_cmd, lockcmd, _PAM_AF_MAX_CMD_LEN - 1);
		hostent.lock_cmd[_PAM_AF_MAX_CMD_LEN - 1] = '\0';
		free(lockcmd);
	}

	if ((ret = cgetstr(buf, _PAM_AF_UNLOCKCMD_CAP, &unlockcmd)) <= 0)
		hostent.unlock_cmd[0] = '\0';
	else {
		ASSERT(unlockcmd != NULL);
		strncpy(hostent.unlock_cmd, unlockcmd, _PAM_AF_MAX_CMD_LEN - 1);
		hostent.unlock_cmd[_PAM_AF_MAX_CMD_LEN - 1] = '\0';
		free(unlockcmd);
	}
		
	free(buf);
	return &hostent;
}

PAM_EXTERN int
pam_sm_authenticate(pamh, flags, argc, argv)
	pam_handle_t	*pamh;
	int		flags;
	int		argc __unused;
	const char	*argv[] __unused;
{
	char *host;
	DB *dbp;
	DBT key, data;
	struct addrinfo *res, *res0;
	hostrec_t hostrecord;
	hostrule_t *hostent;
	int pam_af_default_value = PAM_AUTH_ERR; /* Result in case of error */
	int update_when_locked = 0; /* Update host stats when it's locked */
	register time_t curtime;
	void *addr;
	struct addrinfo hints;
	int ret, pam_ret = PAM_SUCCESS;

	/* Check if we have proper uid */
	if (getuid() != 0)
		return PAM_SUCCESS;
	
	/* Get pear hostname */
	ret = pam_get_item(pamh, PAM_RHOST, (const void **)&host);
	if (ret != PAM_SUCCESS) {
		PAM_AF_LOGERR("Can't get RHOST item");
		PAM_RETURN(pam_af_default_value);
	}

	if (openpam_get_option(pamh, "allow_on_error") != NULL)
		pam_af_default_value = PAM_SUCCESS; 
	if (openpam_get_option(pamh, "update_locked") != NULL)
		update_when_locked = 1; 

	/* Open statistics database */
	dbp = dbopen(DBNAME, O_RDWR | O_CREAT, \
	    PERM, DB_HASH, NULL);
	if (dbp == NULL) {
		PAM_AF_LOGERR("Can't open host database: %s", \
		    strerror(errno));
		PAM_RETURN(pam_af_default_value);
	}

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	/* XXX: we are using host value */
	key.data = host;
	key.size = strlen(host);
	curtime = time(NULL);

	ret = dbp->get(dbp, &key, &data, 0);
	switch (ret) {
	case 1:
		/* Not found */
		hostrecord.num = 0;
		hostrecord.last_attempt = curtime;
		hostrecord.locked_for = 0;
		break;
	case 0:
		bcopy(data.data, &hostrecord, sizeof(hostrecord));
		break;
	default:
		PAM_AF_LOGERR("Can't perform db search: %s", \
		    strerror(ret));
		PAM_RETURN(pam_af_default_value);
	}
	
	/* Unlock host, if needed */
	if (hostrecord.locked_for != 0 && 
	    (curtime - hostrecord.last_attempt) > hostrecord.locked_for) {
		hostrecord.num = 0;
		hostrecord.locked_for = 0;
//		if (strlen(hostrecord.cmd_unlock) > 0)
//			(void)pam_af_exec_cmd(hostrecord.cmd_unlock);
	}

	hostrecord.num++;

	/* We're using fact that locked_for == 0 when not locked */
	if (hostrecord.last_attempt + hostrecord.locked_for > curtime ) {
		PAM_VERBOSE_ERROR("Rejecting host %s\n", (char *)host);
		pam_ret = PAM_AUTH_ERR;
		if (update_when_locked == 0) {
			ret = dbp->close(dbp);
			if (ret < 0)
				PAM_AF_LOGERR("Can't close database: %s", \
				    strerror(errno));
			PAM_RETURN(pam_ret);
		}
	}

	hostrecord.last_attempt = curtime;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	if ((ret = getaddrinfo(host, NULL, &hints, &res0)) != 0) {
		PAM_AF_LOGERR("Can't resolve pear hostname %s: %s", \
		    host, gai_strerror(ret));
		PAM_RETURN(pam_af_default_value);
	}
	/* Try to find host rule */
	for (res = res0; res; res = res->ai_next) {
		switch (res->ai_family) {
		case PF_INET:
				addr = &(((struct sockaddr_in *) \
				res->ai_addr)->sin_addr.s_addr);
				break;
		case PF_INET6:
				addr = ((struct sockaddr_in6 *) \
				res->ai_addr)->sin6_addr.s6_addr;
				break;
		default:
				continue;
		}

		if ((hostent = pam_af_get_host_rule(pamh, flags, addr, \
		    res->ai_family)) != NULL) {
			break;
		}
	}
	freeaddrinfo(res0);
	/* Host rule not found, try 'default' */
	if (hostent == NULL) {
		hostent = pam_af_get_host_rule(pamh, flags, DEFCAP, \
			      PF_UNSPEC);
	}
	if (hostent == NULL)
		PAM_RETURN(pam_af_default_value);

	/* Lock host, if needed */
	if (hostrecord.num > hostent->attempts) {
		hostrecord.locked_for = hostent->locktime;
		pam_ret = PAM_AUTH_ERR;
		if (strlen(hostent->lock_cmd) > 0)
			(void)pam_af_exec_cmd(pamh, hostent->lock_cmd);
	}

	data.data = &hostrecord;
	data.size = sizeof(hostrecord);
	key.data = host;
	key.size = strlen(host);

	ret = dbp->put(dbp, &key, &data, 0);
	if (ret != 0)
		PAM_AF_LOGERR("Can't update record: %s", strerror(ret));

	ret = dbp->close(dbp);
	if (ret < 0)
		PAM_AF_LOGERR("Can't close database: %s", strerror(errno));

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
	DB *dbp;
	DBT key, data;
	hostrec_t hostrecord;
	int ret;

	/* Check if we have proper uid */
	if (getuid() != 0)
		return PAM_SUCCESS;
	
	/* Get pear host */
	ret = pam_get_item(pamh, PAM_RHOST, (const void **)&host);
	if (ret != PAM_SUCCESS)
		PAM_RETURN(PAM_SERVICE_ERR);

	/* Open statistics database */
	dbp = dbopen(DBNAME, O_RDWR | O_CREAT, PERM, DB_HASH, NULL);
	if (dbp == NULL) {
		PAM_AF_LOGERR("Can't open statistics database: %s", \
		    strerror(errno));
		PAM_RETURN(PAM_CRED_UNAVAIL);
	}

	/* Clear BDB structures */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	
	/* Update records */
	hostrecord.num = 0;
	hostrecord.locked_for = 0;
	hostrecord.last_attempt = time(NULL);

	data.data = &hostrecord;
	data.size = sizeof(hostrecord);
	key.data = host;
	key.size = strlen(host);

	ret = dbp->put(dbp, &key, &data, 0);
	if (ret != 0)
		PAM_AF_LOGERR("Can't update record: %s", \
		    strerror(ret));

	ret = dbp->close(dbp);
	if (ret < 0)
		PAM_AF_LOGERR("Can't close database: %s", \
		    strerror(errno));

	PAM_RETURN(PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_af");
