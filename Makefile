# Copyright (c) 2005 Stanislav Sedov <ssedov@mbsd.msk.ru>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id: Makefile,v 1.6 2005/10/14 04:14:53 stas Exp $
#
# Parts of this file was derived from software distributed by Solar Designer
# under the following copyright:
#
#-------------------------------------------------------------------------
# Copyright (c) 2000-2003,2005 by Solar Designer.
#
# You're allowed to do whatever you like with this software (including        
# re-distribution in source and/or binary form, with or without
# modification), provided that credit is given where it is due and any
# modified versions are marked as such.  There's absolutely no warranty.
#-------------------------------------------------------------------------
#

.POSIX:

# C compiler
#CC = gcc
CC = cc
CC_GCC = gcc
CC_SUN = cc
CC_HP = cc

# Linker 
LD = $(CC)
LD_GCC = $(CC_GCC)
LD_SUN = $(CC_SUN)
LD_HP = $(CC_HP)

# Other stuff
RM = rm -f
MKDIR = mkdir -p
INSTALL = install -c
UNAME = uname -s

CFLAGS = -I./common/
CFLAGS_GCC =	-O2 -Wall -Wsystem-headers -Werror -Wno-format-y2k	\
		-Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch	\
		-Wshadow -Wcast-align -Wunused-parameter		\
		-Wchar-subscripts -Winline -Wnested-externs -fPIC
CFLAGS_SUN = -KPIC -xO2 -D_SUN_PAM_ -D_HAVE_USERDEFS_H_
CFLAGS_HP = -Ae +w1 +W 474,486,542 +z +O2
CFLAGS_BSD = -D_HAVE_PATHS_H_ -D_HAVE_ERR_H_ -D_HAVE_GETPROGNAME_
CFLAGS_GNU =	-D_GNU_SOURCE -D_HAVE_PATHS_H_ -D_HAVE_ERR_H_ -D_HAVE_FLOCK_ \
		-D_HAVE_SYS_FILE_H_

LDFLAGS_BSD =
LDFLAGS_LINUX = -lgdbm -lgdbm_compat
LDFLAGS_SUN = -lnsl -lsocket
LDFLAGS_HP =
SHLDFLAGS_GCC = -s --shared -lpam -lcrypt
SHLDFLAGS_SUN = -s -G -lpam -lcrypt
SHLDFLAGS_HP = -s -b -lpam -lsec

LIBDIR = .
TOOLDIR = ./pam_af_tool
DISTLIB = pam_af.so
DISTTOOL = pam_af_tool
LIB = $(LIBDIR)/pam_af
TOOL = $(TOOLDIR)/pam_af_tool

LIBBIN = $(LIB).so
TOOLBIN = $(TOOL)

BINMODE = 755
MANMODE = 644

COMMSRC = common/subr.c common/subr.h common/pam_af.h
DISTLIBMAN = pam_af.8
DISTTOOLMAN = pam_af_tool.8
LIBMAN = $(LIBDIR)/$(DISTLIBMAN)
TOOLMAN = $(TOOLDIR)/$(DISTTOOLMAN)

SECUREDIR = /lib/security
SBINDIR = /sbin
MANDIR = /share/man
DESTDIR = /usr/local

LIB_OBJS = $(LIBDIR)/pam_af.o $(LIBDIR)/subr.o
TOOL_OBJS = $(TOOLDIR)/pam_af_tool.o $(TOOLDIR)/subr.o

all:
	if [ "`$(UNAME)`" = "FreeBSD" ]; then \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_GCC) $(CFLAGS_BSD)" \
			LD=ld LDFLAGS="$(LDFLAGS_BSD) $(SHLDFLAGS_GCC)" \
			$(LIBBIN); \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_GCC) $(CFLAGS_BSD)" \
			LDFLAGS="$(LDFLAGS_BSD)" $(TOOLBIN); \
	elif [ "`$(UNAME)`" = "Linux" ]; then \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_GCC) $(CFLAGS_GNU)" \
			LD=ld LDFLAGS="$(LDFLAGS_LINUX) $(SHLDFLAGS_GCC)" \
			$(LIBBIN); \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_GCC) $(CFLAGS_GNU)" \
			LDFLAGS="$(LDFLAGS_LINUX)" $(TOOLBIN); \
	elif [ "`$(UNAME)`" = "SunOS" ]; then \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_SUN)" \
			LD=ld LDFLAGS="$(LDFLAGS_SUN) $(SHLDFLAGS_SUN)" \
			$(LIBBIN); \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_SUN)" \
			LDFLAGS="$(LDFLAGS_SUN)" $(TOOLBIN); \
	elif [ "`$(UNAME)`" = "HP-UX" ]; then \
		$(MAKE) CFLAGS="$(CFLAGS_HP)" \
			LD=ld LDFLAGS="$(LDFLAGS_HP) $(SHLDFLAGS_HP)" \
			$(LIBBIN); \
		$(MAKE) CFLAGS="$(CFLAGS) $(CFLAGS_HP)" \
			LDFLAGS="$(LDFLAGS_HP)" $(TOOLBIN); \
	else \
		$(MAKE) $(LIBBIN); \
		$(MAKE) $(TOOLBIN); \
	fi

$(LIBBIN): $(LIB_OBJS)
	$(LD) $(LDFLAGS) $(LIB_OBJS) -o $(LIBBIN)

$(TOOLBIN): $(TOOL_OBJS)
	$(CC) $(LDFLAGS) $(TOOL_OBJS) -o $(TOOLBIN)

$(LIBDIR)/subr.o:
	$(CC) $(CFLAGS) -DPAM_AF_DEFS -c ./common/$(*F).c -o $@
$(LIBDIR)/pam_af.o:
	$(CC) $(CFLAGS) -c $(LIBDIR)/$(*F).c -o $@
$(TOOLDIR)/pam_af_tool.o:
	$(CC) $(CFLAGS) -c $(TOOLDIR)/$(*F).c -o $@
$(TOOLDIR)/subr.o:
	$(CC) $(CFLAGS) -c ./common/$(*F).c -o $@

$(LIB).o: pam_af.c $(COMMSRC)
$(TOOL).o: pam_af_tool/pam_af_tool.c $(COMMSRC)

install:
	$(MKDIR) $(DESTDIR)$(SECUREDIR)
	$(MKDIR) $(DESTDIR)$(SBINDIR)
	$(MKDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m $(BINMODE) $(LIBBIN) $(DESTDIR)$(SECUREDIR)/$(DISTLIB)
	$(INSTALL) -m $(MANMODE) $(LIBMAN) \
		$(DESTDIR)$(MANDIR)/man8/$(DISTLIBMAN)
	$(INSTALL) -m $(BINMODE) $(TOOLBIN) $(DESTDIR)$(SBINDIR)/$(DISTTOOL)
	$(INSTALL) -m $(MANMODE) $(TOOLMAN) \
		$(DESTDIR)$(MANDIR)/man8/$(DISTTOOLMAN)

deinstall:
	$(RM) $(DESTDIR)$(SECUREDIR)/$(DISTLIB)
	$(RM) $(DESTDIR)$(SBINDIR)/$(DISTTOOL)
	$(RM) $(DESTDIR)$(MANDIR)/man8/$(DISTLIBMAN)
	$(RM) $(DESTDIR)$(MANDIR)/man8/$(DISTTOOLMAN)

clean:
	$(RM) $(LIBBIN) $(TOOLBIN) $(LIB_OBJS) $(TOOL_OBJS)
