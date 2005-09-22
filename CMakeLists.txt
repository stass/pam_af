# Main cmake-file for pam_af
#
# $Id: CMakeLists.txt,v 1.1 2005/09/22 03:54:32 stas Exp $

PROJECT(PAM_AF)

ADD_LIBRARY(pam_af SHARED pam_af.c ${PAM_AF_SOURCE_DIR}/common/subr.c)
INCLUDE_DIRECTORIES(${PAM_AF_SOURCE_DIR}/common)
SET_TARGET_PROPERTIES(pam_af PROPERTIES PREFIX "")

INSTALL_TARGETS(/lib pam_af)
INSTALL_FILES(/man/man8 FILES pam_af.8)

SUBDIRS(pam_af_tool)
