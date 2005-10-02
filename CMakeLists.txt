# Main cmake-file for pam_af
#
# $Id: CMakeLists.txt,v 1.2 2005/10/02 08:20:07 stas Exp $

PROJECT(PAM_AF)

ADD_LIBRARY(pam_af SHARED pam_af.c ${PAM_AF_SOURCE_DIR}/common/subr.c)
INCLUDE_DIRECTORIES(${PAM_AF_SOURCE_DIR}/common)
SET_TARGET_PROPERTIES(pam_af PROPERTIES PREFIX "")

IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
	LINK_LIBRARIES(gdbm gdbm_compat)
ENDIF(CMAKE_SYSTEM_NAME MATCHES "Linux")

IF(CMAKE_COMPILER_IS_GNUCC_RUN)
	SET_SOURCE_FILES_PROPERTIES(${PAM_AF_SOURCE_DIR}/pam_af.c 
	${PAM_AF_SOURCE_DIR}/common/subr.c
	${PAM_AF_SOURCE_DIR}/pam_af_tool/pam_af_tool.c PROPERTIES
	COMPILE_FLAGS "-Wall -Wsystem-headers -Werror -Wno-format-y2k -Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch -Wshadow -Wcast-align -Wunused-parameter -Wchar-subscripts -Winline -Wnested-externs -Wredundant-decls")
ENDIF(CMAKE_COMPILER_IS_GNUCC_RUN)

INSTALL_TARGETS(/lib pam_af)
INSTALL_FILES(/man/man8 FILES pam_af.8)

SUBDIRS(pam_af_tool)
