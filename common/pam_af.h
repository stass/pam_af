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
 * $Id: pam_af.h,v 1.12 2005/10/16 15:55:28 stas Exp $
 */
#ifndef _PAM_AF_H_
#define _PAM_AF_H_

#define STATDB "/var/db/pam_af"
#define STATDB_PERM (S_IRUSR | S_IWUSR)

#define MAX_CMD_LEN 255
#define CFGDB "/etc/pam_af.conf"
#define CFGDB_PERM (S_IRUSR | S_IWUSR)

#ifdef _OPENPAM
# define PAM_AF_LOG(...) \
	PAM_LOG(__VA_ARGS__)
# define PAM_AF_LOGERR(...) \
	openpam_log(PAM_LOG_ERROR, __VA_ARGS__)
#else
# define PAM_AF_LOG(...) \
	syslog(LOG_DEBUG, __VA_ARGS__)
# define PAM_AF_LOGERR(...) \
	syslog(LOG_CRIT, __VA_ARGS__)
# define _USE_SYSLOG_
#endif

#undef PAM_AF_DEBUG
#if defined(PAM_AF_DEBUG)
# define ASSERT(exp) \
	assert(exp);
# if defined(PAM_AF_DEFS)
#  define PASS \
	PAM_AF_LOGERR("pass: %s ==> %s: %d", __FILE__,		\
	__FUNCTION__, __LINE__);
# else
#   define PASS \
	fprintf(stderr, "pass: %s ==> %s: %d\n", __FILE__,	\
	__FUNCTION__, __LINE__);
# endif
#else
# define ASSERT(exp)
# define PASS
#endif

#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#ifndef _HAVE_FLOCK_
# define flock(a,b) 0
#endif

#ifdef __STDC__
#ifndef __P
#define __P(x)  x
#endif
#else
#ifndef __P
#define __P(x)  ()
#endif
#endif /* __STDC__ */

#ifndef _PATH_BSHELL
# define _PATH_BSHELL DEFSHL
#endif

#ifndef __packed
# ifdef __GNUC__
#  define __packed __attribute__((packed))
# else /* __GNUC__ */
#  define __packed
# endif /* __GNUC__ */
#endif

#ifndef __unused
# ifdef __GNUC__
#  define __unused __attribute__((unused))
# else /* __GNUC__ */
#  define __unused
# endif /* __GNUC__ */
#endif

#ifndef PAM_RETURN
# define PAM_RETURN return
#endif

typedef struct hostrec {
	unsigned long	num;
	time_t		last_attempt;
	unsigned long	locked_for;
} __packed hostrec_t;

typedef struct hostrule {
	uint mask;
	unsigned long	attempts;
	long		locktime;
	char		lock_cmd[MAX_CMD_LEN];
	char		unlock_cmd[MAX_CMD_LEN];
} __packed hostrule_t;
#define DEFAULT_ATTEMPTS	ULONG_MAX
#define DEFAULT_LOCKTIME	0
#define DEFRULE "*"

#endif /* _PAM_AF_H_ */
