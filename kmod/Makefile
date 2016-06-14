KMOD=	fastd
SRCS=	fastd.c
KMODDIR=	/boot/modules

.include <bsd.kmod.mk>

BuildMode ?= Release

.if $(BuildMode) == "Debug"
CFLAGS += -g -DDEBUG
.endif
