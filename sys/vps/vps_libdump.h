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

/* $Id: vps_libdump.h 206 2013-12-16 18:15:42Z klaus $ */

#ifndef _VPS_LIBDUMP_H
#define _VPS_LIBDUMP_H

#include <machine/vps_md.h>

#ifndef _KERNEL

struct vps_snapst_ctx {
	void *data;
	void *cpos;
	long dsize;
	long maxsize;
	struct vps_dumpobj *rootobj;
	struct vps_dumpobj *lastobj;
	struct vps_dumpobj *curobj;
	int level;
	int elements;
	char relative;
};

struct vps_dumpheader;

/* object functions */
struct vps_dumpobj *vps_dumpobj_create(struct vps_snapst_ctx *ctx,
    int type, int how);
void *vps_dumpobj_space(struct vps_snapst_ctx *ctx, long size, int how);
int vps_dumpobj_append(struct vps_snapst_ctx *ctx, const void *data,
    long size, int how);
void vps_dumpobj_close(struct vps_snapst_ctx *ctx);
void vps_dumpobj_discard(struct vps_snapst_ctx *ctx, struct vps_dumpobj *o);
int vps_dumpobj_checkobj(struct vps_snapst_ctx *ctx, struct vps_dumpobj *o);
void vps_dumpobj_setcur(struct vps_snapst_ctx *ctx, struct vps_dumpobj *o);
struct vps_dumpobj *vps_dumpobj_next(struct vps_snapst_ctx *ctx);
struct vps_dumpobj *vps_dumpobj_prev(struct vps_snapst_ctx *ctx);
struct vps_dumpobj *vps_dumpobj_peek(struct vps_snapst_ctx *ctx);
struct vps_dumpobj *vps_dumpobj_getcur(struct vps_snapst_ctx *ctx);
int vps_dumpobj_typeofnext(struct vps_snapst_ctx *ctx);
int vps_dumpobj_nextischild(struct vps_snapst_ctx *ctx,
    struct vps_dumpobj *op);
int vps_dumpobj_recurse(struct vps_snapst_ctx *ctx, struct vps_dumpobj *o,
    void (*func)(struct vps_snapst_ctx *ctx, struct vps_dumpobj *));

/* tree functions */
int vps_dumpobj_makerelative(struct vps_snapst_ctx *ctx);
int vps_dumpobj_makeabsolute(struct vps_snapst_ctx *ctx);
int vps_dumpobj_printtree(struct vps_snapst_ctx *ctx);
int vps_dumpobj_checktree(struct vps_snapst_ctx *ctx);

/* various subroutines */
int vps_dumpobj_checkptr(struct vps_snapst_ctx *ctx, void *p, size_t off);
const char *vps_libdump_objtype2str(int objt);
int vps_libdump_checkheader(struct vps_dumpheader *h);
void vps_libdump_printheader(struct vps_dumpheader *h);

#endif /* !_KERNEL */

#define VPS_DUMPOBJT_ROOT                2
#define VPS_DUMPOBJT_SYSINFO             3
#define VPS_DUMPOBJT_VPS                 4
#define VPS_DUMPOBJT_ARG                 6
#define VPS_DUMPOBJT_END                 9
#define VPS_DUMPOBJT_PROC               10
#define VPS_DUMPOBJT_THREAD             12
#define VPS_DUMPOBJT_PGRP               14
#define VPS_DUMPOBJT_SESSION            15
#define	VPS_DUMPOBJT_SELTD		16
#define VPS_DUMPOBJT_SAVEFPU		18
#define VPS_DUMPOBJT_SYSENTVEC          19
#define VPS_DUMPOBJT_VMSPACE            20
#define VPS_DUMPOBJT_VMMAPENTRY		22
#define VPS_DUMPOBJT_VMOBJECT           23
#define VPS_DUMPOBJT_VMPAGE             24
#define VPS_DUMPOBJT_VMOBJ_VNPATH       25
#define VPS_DUMPOBJT_FDSET              30
#define VPS_DUMPOBJT_FILE               31
#define VPS_DUMPOBJT_FILE_PATH          32
#define VPS_DUMPOBJT_PTS                33
#define VPS_DUMPOBJT_PIPE               34
#define VPS_DUMPOBJT_PARGS              35
#define VPS_DUMPOBJT_SOCKET             36
#define VPS_DUMPOBJT_SOCKBUF            37
#define VPS_DUMPOBJT_MBUFCHAIN          38
#define VPS_DUMPOBJT_SOCKET_UNIX        39
#define VPS_DUMPOBJT_MOUNT              40
#define VPS_DUMPOBJT_VNET_IFACE         50
#define VPS_DUMPOBJT_VNET_ADDR          52
#define VPS_DUMPOBJT_VNET_ROUTETABLE    55
#define VPS_DUMPOBJT_VNET_ROUTE         56
#define VPS_DUMPOBJT_VNET               59
#define VPS_DUMPOBJT_SYSVSEM_VPS        70
#define VPS_DUMPOBJT_SYSVSEM_PROC       71
#define VPS_DUMPOBJT_SYSVSHM_VPS        72
#define VPS_DUMPOBJT_SYSVSHM_PROC       73
#define VPS_DUMPOBJT_SYSVMSG_VPS        74
#define VPS_DUMPOBJT_SYSVMSG_PROC       75
#define VPS_DUMPOBJT_KQUEUE             80
#define VPS_DUMPOBJT_KNOTE              81
#define VPS_DUMPOBJT_KEVENT             82
#define VPS_DUMPOBJT_UMTX               90
#define VPS_DUMPOBJT_FILE_INODENUM      95
#define VPS_DUMPOBJT_PRISON             100
#define VPS_DUMPOBJT_UCRED              120

#define VPS_DUMPH_MAGIC			0xc0debabe
#define VPS_DUMPH_VERSION		0x20131216
#define VPS_DUMPH_MSB			12
#define VPS_DUMPH_LSB			21
#define VPS_DUMPH_32BIT			32
#define VPS_DUMPH_64BIT			64

#if defined(VPS_ARCH_AMD64)
/* AMD64 declarations */
typedef unsigned char	uint8;
typedef unsigned short 	uint16;
typedef unsigned int 	uint32;
typedef unsigned long 	uint64;
typedef signed char	sint8;
typedef signed short 	sint16;
typedef signed int 	sint32;
typedef signed long 	sint64;
typedef unsigned char	byte;
typedef void * 		ptr;
typedef uint64		offset;
#define PTR(x)		ptr x
#define ALIGN_MASK	0x7
#define PTRTO64(x)	(uint64)(x)
#define PTRFROM64(x)	(void *)(x)

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#endif

#ifndef _KERNEL
/*
typedef unsigned long size_t;
*/
#endif

/* end amd64 declarations */

#elif defined(VPS_ARCH_I386)
/* i386 declarations */
typedef unsigned char	uint8;
typedef unsigned short 	uint16;
typedef unsigned int 	uint32;
typedef unsigned long long	uint64;
typedef signed char	sint8;
typedef signed short 	sint16;
typedef signed int 	sint32;
typedef signed long long 	sint64;
typedef unsigned char	byte;
typedef void * 		ptr;
typedef uint32		offset;
#define PTR(x)		ptr x; uint32 _pad_##x
#define ALIGN_MASK	0x3
#define PTRTO64(x)	(uint64)(uint32)(x)
#define PTRFROM64(x)	(void *)(uint32)(x)

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#endif

#if 0
#ifndef _KERNEL
typedef unsigned int size_t;
#endif
#endif

/* end i386 declarations */

#elif defined(VPS_ARCH_MIPSEB64)

/* mipseb64 declarations */
typedef unsigned char	uint8;
typedef unsigned short 	uint16;
typedef unsigned int 	uint32;
typedef unsigned long 	uint64;
typedef signed char	sint8;
typedef signed short 	sint16;
typedef signed int 	sint32;
typedef signed long 	sint64;
typedef unsigned char	byte;
typedef void * 		ptr;
typedef uint64		offset;
#define PTR(x)		ptr x
#define ALIGN_MASK	0x7
#define PTRTO64(x)	(uint64)(x)
#define PTRFROM64(x)	(void *)(x)

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#endif

#ifndef _KERNEL
/*
typedef unsigned long size_t;
*/
#endif

/* end mipseb64 declarations */

#else
#error "unsupported architecture"
#endif


struct vps_dumpobj {
	uint32 magic;	/* for debugging purposes; 0x0 or 0xc0debabe */
	uint16 type;
	uint16 level;	/* level this object is in */
	uint32 size;	/* size of this object including it's header */
	sint16 prio;	/* priority; 0 == any */
	uint16 pad0;
	PTR(parent);	/* offset to parent object (from start of
			   snapshot) */
	PTR(next);	/* offset to next object (from start of
			   snapshot) */
	PTR(list_children);	/* internal: SLIST_ENTRY(vps_dumpobj)
				   list */
	PTR(list_siblings);	/* internal: SLIST_ENTRY(vps_dumpobj)
				   list */
	byte data[0];	/* amount of data specified by 'size' */
	/* next object is always aligned to 'ptrsize' */
};


struct vps_dumpheader {
	uint8 byteorder;	/* 0d12 == MSB; 0d21 == LSB */
	uint8 ptrsize;		/* 0d32 == 32 bits; 0d64 == 64 bits; ... */
	uint8 pageshift;	/* e.g. 0d12 for 4096 byte pages */
	byte pad0[5];
	uint32 version;		/* date in hexadecimal; e.g. 0x20120518 */
	uint32 magic;
	sint64 time;
	uint64 size;
	uint64 checksum;
	uint32 nsyspages;
	uint32 nuserpages;
};

#if 0
/* Example of a vps_snapst_ctx. */
struct vps_snapst_ctx {
	void *data;
	void *cpos;
	long dsize;
	long maxsize;
	struct vps_dumpobj *rootobj;
	struct vps_dumpobj *lastobj;
	struct vps_dumpobj *curobj;
	int level;
	int elements;
	char relative;
};
#endif

/*
 * functions
 */



/*
 * dump object types
 */

struct vps_dump_sysinfo {
	char kernel[0x100];
	char hostname[0x100];
	PTR(shared_page_obj);
};

struct vps_dump_vps {
	char hostname[0x100];
	char vps_name[0x100];
	char rootpath[0x400];

	struct bintime boottime;

	sint32 lastpid;
	sint32 initpgrp_id;
	sint32 initproc_id;
	uint32 restore_count;
};

struct vps_dump_mount {
        char mntfrom[0x80];
        char mnton[0x80];
        char fstype[0x10];
        uint8 vpsmount;
	uint8 optcnt;
        uint8 _pad0[6];
        uint64 flags;
        PTR(mnt_cred);
};

struct vps_dump_mount_opt {
	char name[0x40];
	char value[0x100];
	uint16 len;
	uint16 _pad0[3];
};

struct vps_dump_vnet {
	PTR(orig_ptr);
};

struct vps_dump_vnet_ifnet {
	char if_dname[0x10];
	char if_xname[0x10];
	uint32 if_dunit;
	uint32 if_flags;
};

struct vps_dump_vnet_ifaddr {
	uint8 have_addr;
	uint8 have_dstaddr;
	uint8 have_netmask;
	uint8 _pad0[5];
};

// #define SOCK_MAXADDRLEN 255             /* longest possible addresses */
struct vps_dump_vnet_sockaddr {
	uint16 sa_len;
	uint16 sa_family;
	uint32 _pad0;
	char sa_data[0x100];
};

struct vps_dump_vnet_inet6_lifetime {
	sint64 ia6t_expire;
	sint64 ia6t_preferred;
	uint32 ia6t_vltime;
	uint32 ia6t_pltime;
};

struct vps_dump_ucred {
	uint32 cr_uid;
	uint32 cr_ruid;
	uint32 cr_svuid;
	sint32 cr_ngroups;

	uint32 cr_rgid;
	uint32 cr_svgid;
	uint32 cr_flags;
	uint32 cr_ref;

	PTR(cr_origptr);
	PTR(cr_prison);
	PTR(cr_vps);

	uint32 cr_groups[0];	/* always padded to 64 bit alignment */
};

struct vps_dump_prison {
	uint32 pr_id;
	uint32 pr_securelevel;
	uint32 pr_enforce_statfs;
	uint32 pr_childmax;

	uint32 pr_ip4s;
	uint32 pr_ip6s;

	uint64 pr_flags;
	uint64 pr_allow;

	char pr_name[0x100];
	char pr_path[0x400];

	PTR(pr_root);
	PTR(pr_origptr);
	PTR(pr_parent);

	char pr_ipdata[0];
};

struct vps_dump_pgrp {
	uint32 pg_id;
	uint32 pg_jobc;

	uint32 pg_session_id;
	uint32 _pad0;
};

struct vps_dump_session {
	uint32 s_sid;
	uint32 s_leader_id;

	uint32 s_count;
	uint8 s_have_ttyvp;
	uint8 _pad0[3];

	char s_login[0x30];
};

struct vps_dump_proc {
	sint32 p_pid;
	uint32 p_swtick;

	char p_comm[0x20];

	sint64 p_cpulimit;

	sint32 p_flag;
	sint32 p_state;

	uint32 p_stops;
	uint32 p_stype;

	sint8 p_nice;
	sint8 p_step;
	sint32 p_oppid;

	uint32 p_xthread_id;
	sint32 p_sigparent;

	PTR(p_ucred);

	uint8 p_have_tracevp;
	uint8 p_have_textvp;
	uint16 _pad0;
	sint32 p_traceflag;

	PTR(p_tracecred);

	sint32 p_pptr_id;
	sint32 p_peers_id;

	sint32 p_leader_id;
	sint32 p_pgrp_id;

	PTR(p_fd);

	PTR(p_vmspace);

	sint32 p_reaper_pid;
	sint32 p_reapsubtree;

	struct {
		uint32 ps_maxsig;
		uint32 ps_sigwords;
		uint64 ps_sigact[0x80];
		uint32 ps_catchmask[0x80][0x4];
		uint32 ps_sigonstack[0x4];
		uint32 ps_sigintr[0x4];
		uint32 ps_sigreset[0x4];
		uint32 ps_signodefer[0x4];
		uint32 ps_siginfo[0x4];
		uint32 ps_sigignore[0x4];
		uint32 ps_sigcatch[0x4];
		uint32 ps_freebsd4[0x4];
		uint32 ps_osigset[0x4];
		uint32 ps_usertramp[0x4];
		uint32 ps_flag;
		uint32 _pad0;
	} p_sigacts;

	struct {
		uint32 pl_nlimits;
		uint32 pl_refcnt;
		struct {
			sint64 rlim_cur;
			sint64 rlim_max;
		} pl_rlimit[RLIM_NLIMITS];
	} p_limit;

	struct {
		struct {	/* rusage */
			struct timeval ru_utime;
			struct timeval ru_stime;
			sint64	ru_maxrss;
			sint64	ru_ixrss;
			sint64	ru_idrss;
			sint64	ru_isrss;
			sint64	ru_minflt;
			sint64	ru_majflt;
			sint64	ru_nswap;
			sint64	ru_inblock;
			sint64	ru_oublock;
			sint64	ru_msgsnd;
			sint64	ru_msgrcv;
			sint64	ru_nsignals;
			sint64	ru_nvcsw;
			sint64	ru_nivcsw;
		} p_cru;
		struct  itimerval p_timer[3];

		struct {
			uint64	pr_base;	/* caddr_t */
			uint64  pr_size;
			uint64  pr_off;
			uint64  pr_scale;
		} p_prof;

		struct timeval p_start;
	} p_stats;
};

struct vps_dump_pargs {
	uint32 ar_length;
	uint32 _pad0;
	char ar_args[0];	/* always padded to 64 bit alignment */
};

struct vps_dump_savefpu {
	uint32 sf_length;
	uint32 _pad0;
	char sf_data[0];	/* always padded to 64 bit alignment */
};

struct vps_dump_sysentvec {
	uint32 sv_type;
	uint32 _pad0;
};

struct vps_dump_vmmap {
	uint64 minoffset;
	uint64 maxoffset;
};

struct vps_dump_vmspace {
	PTR(vm_orig_ptr);
	struct vps_dump_vmmap vm_map;
	uint64 vm_tsize;
	uint64 vm_dsize;
	uint64 vm_ssize;
};

struct vps_dump_vmmapentry {
	PTR(map_object);
	PTR(cred);

	uint32 eflags;
	uint8 protection;
	uint8 max_protection;
	sint8 inheritance;
	uint8 _pad0;

	uint64 offset;
	uint64 start;
	uint64 end;
};

struct vps_dump_vmobject {
	PTR(orig_ptr);
	PTR(cred);
	PTR(backing_object);

	uint16 flags;
	uint8 type;
	uint8 have_vnode;
	uint8 is_sharedpageobj;
	uint8 _pad0[3];

	uint64 size;
	uint64 charge;
	uint64 backing_object_offset;
};

struct vps_dump_vmpages {
	uint64 count;
};

struct vps_dump_seltd {
	/* st_selq */
	/* st_free1 */
	/* st_free2 */
	/* st_mtx */
	/* st_wait */
	uint32 st_flags;
};

struct vps_dump_thread {

	PTR(td_sel_orig);

	struct {
		uint64 ss_sp;
		uint64 ss_size;
		sint32 ss_flags;
		sint32 _pad0;
	} td_sigstk;
	uint32 td_sigmask[0x4];
	uint32 td_oldsigmask[0x4];
	sint32 td_xsig;
	sint32 td_dbgflags;

	uint8 td_rqindex;
	uint8 td_base_pri;
	uint8 td_priority;
	uint8 td_pri_class;
	uint8 td_user_pri;
	uint8 td_base_user_pri;
	uint8 _pad1[2];

	uint64 tdu_retval[2];
	sint32 td_errno;
	uint32 _pad2;

	uint64 td_spare[4];

	struct {
		uint32 code;
		sint32 narg;
		PTR(callp);
		uint64 args[8];
	} td_sa;

	sint32 td_tid;
	uint32 td_kstack_pages;
	char td_kstack[0];	/* always padded to 64 bit alignment */
};

struct vps_dump_filedesc {
	PTR(fd_orig_ptr);

	uint8 fd_have_cdir;
	uint8 fd_have_rdir;
	uint8 fd_have_jdir;
	uint8 _pad0[5];

	uint32 fdt_nfiles;
	uint32 _pad1;

	struct {
		PTR(fp);
		uint8 flags;
		/* XXX This is system global, so only keep store once. */
		uint8 cap_rights_version;
		uint8 _pad0[6];
		uint64 cap_rights[2];
	} fd_entries[0];
};

struct vps_dump_file {
	uint32 flags;
	uint32 _pad0;

	PTR(orig_ptr);
	PTR(f_cred);

	uint64 f_offset;

	uint32 f_flag;
	sint16 f_type;
	uint16 _pad1;
};

struct vps_dump_pipe {
	uint8 pi_have_dumped_pipe;
	uint8 _pad0[7];
	PTR(pi_localend);
	PTR(pi_pair);
	PTR(pi_rpipe);
	PTR(pi_wpipe);
};

struct vps_dump_filepath {
	uint32 fp_size;
	uint32 _pad0;

	char fp_path[0];	/* always padded to 64 bit alignment */
};

struct vps_dump_fileinodenum {
	uint64 fsid;
	sint32 fileid;
	uint32 _pad0;
};

struct vps_dump_pts {
	sint32 pt_index;
	sint32 pt_pgrp_id;
	uint32 pt_flags;
	uint32 _pad0;
	PTR(pt_cred);
	struct {
		uint32 c_iflag;
		uint32 c_oflag;
		uint32 c_cflag;
		uint32 c_lflag;
		uint8 c_cc[0x20];
		uint32 c_ispeed;
		uint32 c_ospeed;
	} pt_termios;
};

struct vps_dump_socket {
	PTR(so_orig_ptr);

	sint16 so_type;
	sint16 so_options;
	sint16 so_linger;
	sint16 so_state;
	/* so_pcb */
	PTR(so_vnet);
	/* so_protosw: */
	sint16 so_family;
	sint16 so_protocol;
	/* sint16 so_timeo; */
	uint16 so_error;
	/* so_sigio */
	PTR(so_cred);
	/* so_label */
	/* (so_gencnt) */
	/* so_emuldata */
	/* osd */
	sint32 so_fibnum;
	uint32 so_user_cookie;
	sint32 so_ts_clock;
	uint32 so_max_pacing_rate;

	/* UNION !LISTEN SOCKET */
	/* so_rcv */
	/* so_snd */
	/* so_list */
	PTR(so_listen);
	sint32 so_qstate;
	/* so_peerlabel */
	uint64 so_oobmark;

	/* UNION LISTEN SOCKET */
	/* sol_incomp */
	/* sol_comp */
	uint32 sol_qlen;
	uint32 sol_incqlen;
	uint32 so_qlimit;

	/* sol_accept_filter */
	/* sol_accept_filter_arg */
	/* sol_accept_filter_str */

	/* sol_upcall */
	/* sol_upcallarg */

	sint32 sol_sbrcv_lowat;
	sint32 sol_sbsnd_lowat;
	uint32 sol_sbrcv_hiwat;
	uint32 sol_sbsnd_hiwat;
	sint16 sol_sbrcv_flags;
	sint16 sol_sbsnd_flags;
	sint64 sol_sbrcv_timeo;
	sint64 sol_sbsnd_timeo;
};

struct vps_dump_unixpcb {
	uint8 unp_have_conn;
	uint8 unp_have_addr;
	uint8 unp_have_vnode;
	uint8 _pad0[5];

	sint16 unp_flags;
	sint16 _pad1;
	uint32 _pad2;

	sint32 unp_cc;
	sint32 unp_mbcnt;

	PTR(unp_socket);

	PTR(unp_conn_socket);

	struct {
		uint32 cr_uid;
		uint16 cr_ngroups;
		uint16 _pad3;

		uint32 cr_groups[16];
	} unp_peercred;
};

struct vps_dump_inetpcb {
	/* inp_hash */
	/* inp_pcbgrouphash */
	/* inp_lock */

	/* inp_refcount; initialized on in_pcballoc */
	sint32 inp_flags;
	sint32 inp_flags2;
	/* inp_ppcb */
	/* inp_socket; set during in_pcballoc */
	/* inp_pcbinfo; set during in_pcballoc */
	/* inp_pcbgroup */
	/* inp_cred; inherited from socket */
	uint32 inp_flow; /* from syncache, in6_pcbconnect_mbuf */
	uint8 inp_vflag;
	uint8 inp_ip_ttl;
	uint8 inp_ip_p;
	uint8 inp_ip_minttl;
	/* inp_flowid */
	/* inp_snd_tag */
	/* inp_flowtype */
	/* inp_rss_listen_bucket */

	/* XXX-BZ review struct */
	struct {
		uint8 inc_flags;
		uint8 inc_len;
		uint16 inc_fibnum;	/* inherited from socket */

		/* in_endpoints */
		uint16 ie_fport;
		uint16 ie_lport;
		uint8 ie_ufaddr[16];
		uint8 ie_uladdr[16];
		uint32 ie6_zoneid;	/* dead code? */
		uint32 _pad0;
	} inp_inc;

	/* inp_label */
	/* inp_sp */

	/* Protocol-dependent part; options. */
	struct {
		uint8 inp_ip_tos;
		/* inp_options */	/* comes from syncache; should restore? */
		/* inp_moptions */
	};

	struct {
		/* in6p_options */	/* dead code */
		/* in6p_outputopts */	/* comes from syncache; should restore? */
		/* in6p_moptions */
		/* in6p_icmp6filt */	/* XXX alloc()ed in rip6_attach() */
		sint32 in6p_cksum;
		uint16 in6p_hops;
	};
	/* inp_portlist */
	/* inp_phd */
	/* inp_gencnt; set on in_pcballoc */
	/* inp_lle */			/* dead code? */
	/* inp_rt_cookie */		/* Should fix itself. */
	/*
	uinon {
		inp_route
		inp_route6
	};
	*/
	/* inp_list */

	/* VPS INTERNAL */
	uint8 inp_have_ppcb;
	uint8 _pad0[7];
};

struct vps_dump_udppcb {
	uint8 u_have_tun_func;
	uint8 u_have_icmp_func;
	uint8 _pad0[2];
	uint32 u_flags;
	uint16 u_rxcslen;
	uint16 u_txcslen;
	/* PTR(u_tun_ctx); */
};

struct vps_dump_tcppcb {

	/* t_segq */
	/* sint32 t_segqlen */
	sint32 t_dupacks;

	/* t_timers */
	/* t_inpcb */

	sint32 t_state;
	uint32 t_flags;

	/* t_vnet */

	uint32 snd_una;
	uint32 snd_max;

	uint32 snd_nxt;
	uint32 snd_up;

	uint32 snd_wl1;
	uint32 snd_wl2;
	uint32 iss;
	uint32 irs;

	uint32 rcv_nxt;
	uint32 rcv_adv;
	uint32 rcv_wnd;
	uint32 rcv_up;

	uint32 snd_wnd;
	uint32 snd_cwnd;
	uint32 snd_ssthresh;

	uint32 snd_recover;

	uint32 t_rcvtime;
	uint32 t_starttime;
	uint32 t_rtttime;
	uint32 t_rtseq;

	sint32 t_rxtcur;
	uint32 t_maxseg;
	uint32 t_pmtud_saved_maxseg;
	sint32 t_srtt;
	sint32 t_rttvar;

	sint32 t_rxtshift;
	uint32 t_rttmin;
	uint32 t_rttbest;
	uint64 t_rttupdated;
	uint32 max_sndwnd;

	sint32 t_softerror;

	sint8 t_oobflags;
	sint8 t_iobc;

	uint8 snd_scale;
	uint8 rcv_scale;
	uint8 request_r_scale;
	uint32 ts_recent;
	uint32 ts_recent_age;
	uint32 ts_offset;

	uint32 last_ack_sent;

	uint32 snd_cwnd_prev;
	uint32 snd_ssthresh_prev;
	uint32 snd_recover_prev;
	sint32 t_sndzerowin;
	uint32 t_badrxtwin;
	uint8 snd_limited;

	sint32 snd_numholes;
	/* snd_holes */

	uint32 snd_fack;
	sint32 rcv_numsacks;
	/* sackblks[] */
	uint32 sack_newdata;
	/* sackhint */
	sint32 t_rttlow;
	uint32 rfbuf_ts;
	sint32 rfbuf_cnt;
	/* tod */
	sint32 t_sndrexmitpack;
	sint32 t_rcvoopack;
	/* t_toe */
	sint32 t_bytes_acked;
	/* cc_algo */
	/* ccv */
	/* osd */

	uint32 t_keepinit;
	uint32 t_keepidle;
	uint32 t_keepintvl;
	uint32 t_keepcnt;

	uint32 t_tsomax;
	uint32 t_tsomaxsegcount;
	uint32 t_tsomaxsegsize;
	uint32 t_flags2;
	/* t_fb */
	/* t_fb_ptr */
	uint64 t_tfo_cookie;
	/* t_tfo_pending */

	/* t_inpkts */
	/* t_outpkts */
};

struct vps_dump_sockbuf {
	PTR(sb_mb);
	PTR(sb_mbtail);
	PTR(sb_lastrecord);
	PTR(sb_sndptr);

	sint16 sb_state;
	sint16 sb_flags;
	uint32 sb_sndptroff;

	uint32 sb_acc;
	uint32 sb_ccc;
	uint32 sb_hiwat;
	uint32 sb_mbcnt;
	uint32 sb_mcnt;
	uint32 sb_ccnt;
	uint32 sb_mbmax;
	uint32 sb_ctl;
	sint32 sb_lowat;
	uint32 sb_timeo;
};

struct vps_dump_mbufchain {
	uint32 mc_mbcount;
	uint32 _pad0;
};

struct vps_dump_mbuf {
	PTR(mb_orig_ptr);

	sint16 mb_type;
	sint16 _pad0[3];

	sint32 mb_len;
	sint32 mb_flags;

	uint8 mb_have_dat;
	uint8 mb_have_ext;
	uint8 mb_have_data;
	uint8 _pad1[5];

	/*
	uint32 mb_dat_size;
	uint32 mb_ext_size;
	*/
	uint32 mb_payload_size;
	uint32 _pad2;

	uint32 mb_data_off;
	uint32 mb_checksum;

	char mb_payload[0];	/* always padded to 64 bit alignment */
};

struct vps_dump_vmpageref {
        PTR(pr_vmobject);
        uint64 pr_pindex;
	uint64 _debug;
};

struct vps_dump_route {
	sint32 rt_flags;
	uint32 rt_fibnum;

	uint8 rt_have_mask;
	uint8 rt_have_gateway;
	uint8 rt_have_ifp;
	uint8 rt_have_ifa;
	uint8 _pad0[4];

	struct {
		uint64 rmx_mtu;
		uint64 rmx_expire;
		uint64 rmx_pksent;
		uint64 rmx_weight;
	} rt_rmx;
};

struct vps_dump_knote {
	sint32 kn_status;
	uint32 _pad0;

	sint16 ke_filter;
	uint16 ke_flags;
	uint32 ke_fflags;

	uint64 ke_ident;
	uint64 ke_data;
	PTR(ke_udata);
};

struct vps_dump_accounting_val {
	uint64 cur;
	uint64 cnt_cur;
	uint64 soft;
	uint64 hard;
	uint32 hits_soft;
	uint32 hits_hard;
};

struct vps_dump_accounting {
	struct vps_dump_accounting_val virt;
	struct vps_dump_accounting_val phys;
	struct vps_dump_accounting_val kmem;
	struct vps_dump_accounting_val kernel;
	struct vps_dump_accounting_val buffer;
	struct vps_dump_accounting_val pctcpu;
	struct vps_dump_accounting_val blockio;
	struct vps_dump_accounting_val threads;
	struct vps_dump_accounting_val procs;
};

struct vps_dump_arg_ip4 {
	uint8 a4_addr[0x4];
	uint8 a4_mask[0x4];
};

struct vps_dump_arg_ip6 {
	uint8 a6_addr[0x10];
	uint8 a6_plen;
	uint8 _pad0[7];
};

struct vps_dump_arg {
        uint32 ip4net_cnt;
        uint32 ip6net_cnt;

        uint32 privset_size;
        uint8 have_accounting;
	uint8 _pad0[3];
};

struct vps_dump_sysv_ipcperm {
	uint32 cuid;
	uint32 cgid;
	uint32 uid;
	uint32 gid;
	uint16 mode;
	uint16 seq;
	uint32 _pad0;
	sint64 key;
};

/* sysv msg */
struct vps_dump_sysvmsg_msginfo {
	sint32 msgmax;
	sint32 msgmni;
	sint32 msgmnb;
	sint32 msgtql;
	sint32 msgssz;
	sint32 msgseg;

	sint32 nfree_msgmaps;
	sint32 free_msgmaps;
	uint64 free_msghdrs_idx;
	unsigned msg_prison_slot;
};

struct vps_dump_sysvmsg_msg {
	sint64 msg_next;

	sint64 msg_type;

	uint16 msg_ts;
	sint16 msg_spot;
	uint32 _pad0;

	PTR(label);
};

struct vps_dump_sysvmsg_msqid {
	struct vps_dump_sysv_ipcperm msg_perm;
	sint64 msg_first;
	sint64 msg_last;
	uint64 msg_cbytes;
	uint64 msg_qnum;
	uint64 msg_qbytes;
	sint32 msg_lspid;
	sint32 msg_lrpid;
	uint64 msg_stime;
	uint64 msg_rtime;
	uint64 msg_ctime;
	PTR(label);
	PTR(cred);
};

/* sysv sem */

struct vps_dump_sysvsem_seminfo {
	sint32 semmni;
	sint32 semmns;
	sint32 semmnu;
	sint32 semmsl;
	sint32 semopm;
	sint32 semume;
	sint32 semusz;
	sint32 semvmx;
	sint32 semaem;
	unsigned sem_prison_slot;

        sint32 semtot;
        sint32 semundo_active;
};

struct vps_dump_sysvsem_semid {
	struct vps_dump_sysv_ipcperm sem_perm;
	sint64 sem_base;
	uint16 sem_nsems;
	uint16 _pad0[3];
	uint64 sem_otime;
	uint64 sem_ctime;
	PTR(label);
	PTR(cred);
};

struct vps_dump_sysvsem_sem {
	uint16 semval;
	uint16 _pad0[3];
	sint32 sempid;
	uint16 semncnt;
	uint16 semzcnt;
};

struct vps_dump_sysvsem_sem_undo {
	sint32 un_proc;
	sint16 un_cnt;
	uint16 _pad0;

	struct {
		sint16 un_adjval;
		sint16 un_num;
		sint32 un_id;
		uint16 un_seq;
		uint16 _pad1[3];
	} un_ent[0];
};

/* sysv shm */

struct vps_dump_sysvshm_shmid {
	struct vps_dump_sysv_ipcperm shm_perm;
	uint64 shm_segsz;
	sint32 shm_lpid;
	sint32 shm_cpid;
	sint32 shm_nattch;
	sint32 _pad0;
	uint64 shm_atime;
	uint64 shm_dtime;
	uint64 shm_ctime;
	PTR(object);
	PTR(label);
	PTR(cred);
};

struct vps_dump_sysvshm_shminfo {
	uint64 shmmax;
	uint64 shmmin;
	uint64 shmmni;
	uint64 shmseg;
	uint64 shmall;

	sint32 shm_last_free;
	sint32 shm_nused;
	sint32 shmalloced;
	unsigned shm_prison_slot;
	uint64 shm_committed;

	struct vps_dump_sysvshm_shmid shmsegs[0];
};

struct vps_dump_sysvshm_shmmap_state {
	uint64 va;

	sint32 shmid;
	uint32 _pad0;
};

#endif /*_VPS_LIBDUMP_H*/

/* EOF */
