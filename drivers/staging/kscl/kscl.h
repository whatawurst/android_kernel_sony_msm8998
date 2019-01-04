/*
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 */
/******************************************************************************/

#ifndef _CRYPTO_KSCL_H
#define _CRYPTO_KSCL_H

#if 0
#ifdef __KERNEL__
#include "linux/threads.h"
#if defined NR_CPUS
#ifndef KSCL_MAX_WORKERS
#define KSCL_MAX_WORKERS NR_CPUS /* At most max CPUs. */
#endif /* KSCL_MAX_WORKERS */
#else
#ifndef KSCL_MAX_WORKERS
#define KSCL_MAX_WORKERS 1 /* The default. */
#endif /* KSCL_MAX_WORKERS */
#endif /* Kernel space KSCL_MAX_WORKERS. */
#endif /* Number of workers. */
#endif

#define KSCL_MAX_WORKERS 4

#define KSCL_PROC_NAME "driver/kscl"
#define KSCL_PROC_PATH "/proc/" KSCL_PROC_NAME

#ifndef KSCL_BUFFER_SIZE
	/* Optimize for buffer sizes >= 512 bytes. */
	#define KSCL_BUFFER_SIZE 512
#endif /* KSCL_BUFFER_SIZE */

#define KSCL_AES_MAX_KEY_SIZE 32
#define KSCL_AES_BLOCK_SIZE 16

/* kscl ioctl magic number */
#define KSCL_MAGIC_IOCTL 'q'

#ifdef __ANDROID__
/* Use "BAD" version of _IOWR for Android to avoid
   undefined __invalid_size_argument_for_IOC. */
#define KSCL_QUEUE_IOCTL _IOWR_BAD(KSCL_MAGIC_IOCTL, 1, int)
#else /* __ANDROID__ */
#define KSCL_QUEUE_IOCTL _IOWR(KSCL_MAGIC_IOCTL, 1, int)
#endif /* __ANDROID__ */

/* Values for combined_valid. */
#define REQUEST_VALID 1
#define RESPONSE_VALID 2

/* Control part of request (key, iv and lengths) */
struct kscl_ctrl {
	/* two keys for XTS, one for ECB and CBC */
	uint8_t key[2 * KSCL_AES_MAX_KEY_SIZE];
	/* initialization vector */
	uint8_t iv[KSCL_AES_BLOCK_SIZE];
	/* length of data */
	uint32_t len;
	/* key length in bytes */
	uint32_t keylen;
};

/* Individual KSCL Operation (control + bookkeeping) */
struct kscl_req {
	/* Operation and direction. */
	uint32_t flags;         /* Command/Status */
	uint32_t context;       /* For book keeping.
				   User-space: do not touch. */
	struct kscl_ctrl ctrl; /* Input only. */
};

#define KSCL_FLAGS_BLANK       0x80000000U /* Block is not filled. */
#define KSCL_FLAGS_SEND        0x40000000U /* Block is finished. */
#define KSCL_FLAGS_ERR         0x20000000U /* Block cannot be finished. */
#define KSCL_FLAGS_BUSY        0x10000000U /* Long queue. */
#define KSCL_FLAGS_QUEUE_MASK  0xF0000000U /* Reserved for queue's operation. */

/* Flags for kscl (encryption operation and mode.) */
#define KSCL_FLAGS_DECRYPT 0x01
#define KSCL_FLAGS_ENCRYPT 0x02
#define KSCL_FLAGS_ECB 0x04
#define KSCL_FLAGS_CBC 0x08
#define KSCL_FLAGS_XTS 0x10

/* operation ring or entry buffer */
#define KSCL_RING_ENTRIES (1 << 7)
#define KSCL_RING_INDEX_MASK (KSCL_RING_ENTRIES - 1)
#define KSCL_RING_ENTRIES_SAFE (KSCL_RING_ENTRIES - 1)
#define KSCL_DATA_SIZE (KSCL_BUFFER_SIZE * KSCL_RING_ENTRIES_SAFE)

#if KSCL_RING_ENTRIES_SAFE > KSCL_RING_ENTRIES
#  error "Invalid parameters KSCL_RING_ENTRIES_SAFE/KSCL_RING_ENTRIES"
#endif

/* Select combination of requests and data area size, which fits
   inside IOCTL. */
struct kscl_reqs_and_data {
	uint8_t         data[KSCL_DATA_SIZE];
	struct kscl_req reqs[KSCL_RING_ENTRIES_SAFE];
};

/* KSCL_Key ID size used by UFIPS and FIPS Lib */
#define KSCL_KEY_ID_SIZE ((unsigned int)sizeof(uint32_t))

#define KSCL_PENDING_LEN (9999)

#endif /* _CRYPTO_KSCL_H */
