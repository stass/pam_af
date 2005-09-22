# Main cmake-file for pam_af_tool
#
# $Id: CMakeLists.txt,v 1.1 2005/09/22 03:56:20 stas Exp $

ADD_EXECUTABLE(pam_af_tool pam_af_tool.c ${PAM_AF_SOURCE_DIR}/common/subr.c)
INCLUDE_DIRECTORIES(${PAM_AF_SOURCE_DIR}/common)

INSTALL_TARGETS(/sbin pam_af_tool)
INSTALL_FILES(/man/man8 FILES pam_af_tool.8)
