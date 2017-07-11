/*-
 * Copyright (c) 2009-2013 Klaus P. Ohrhallinger <k@7he.at>
 * All rights reserved.
 *
 * Development of this software was partly funded by:
 *    TransIP.nl <http://www.transip.nl/>
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
 */

/* $Id: vps.h 189 2013-07-12 07:15:07Z klaus $ */

#ifndef _VPS_H
#define _VPS_H

#include <sys/cdefs.h>

#ifdef VPS
#ifndef VIMAGE
#error "You can't have option VPS without option VIMAGE !"
#endif
#endif

/* For sysctl stuff. */
#include <sys/vnet2.h>

#define TD_TO_VPS(x)	(x)->td_ucred->cr_vps
#define P_TO_VPS(x)	(x)->p_ucred->cr_vps

/*
 * At least for now, just use vnet's facility for virtualized
 * global variables.
 * But map to our own names for easier change in the future.
 */

/* Keep in sync with ''struct vps'' declared in vps/vps2.h ! */
struct vps2 {
	struct vnet *vnet;
};

#define VPS_NAME		VNET_NAME
#define VPS_DEFINE		VNET_DEFINE

#define VPS_VPS(vps, n)		\
    VNET_VNET(((struct vps2 *)vps)->vnet, n)
#define VPS_VPS_PTR(vps, n)	\
    VNET_VNET_PTR(((struct vps2 *)vps)->vnet, n)

#ifdef VPS
#define VPS_DECLARE		VNET_DECLARE
#define VPSV(n)			\
    VNET_VNET(((struct vps2 *)curthread->td_vps)->vnet, n)
#else
#define VPS_DECLARE(t, n)	extern t n
#define	VPSV(n)			(n)
#endif /* !VPS */

struct vps;
extern struct vps *vps0;

#endif /* _VPS_H */

/* EOF */
