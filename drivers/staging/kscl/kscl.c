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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <asm/div64.h>
#include <crypto/scatterwalk.h>
#include "kscl.h"
#include <linux/ioctl.h>
#include <crypto/aes.h>
#include <linux/device-mapper.h>
#if KSCL_AES_MAX_KEY_SIZE != AES_MAX_KEY_SIZE
#error bad KSCL_AES_MAX_KEY_SIZE
#endif
#if KSCL_AES_BLOCK_SIZE != AES_BLOCK_SIZE
#error bad KSCL_AES_BLOCK_SIZE
#endif

#define SYSTEM_PROC_UID 1000
static kuid_t proc_uid;	/* system */
static int uid;
static kgid_t proc_gid;	/* root */

struct per_request_ctx *packets_in_play[KSCL_MAX_WORKERS][KSCL_RING_ENTRIES];

struct per_crypto_alg_transform_ctx {
	int keylen;
	uint32_t key[(AES_MAX_KEY_SIZE * 2) / sizeof(uint32_t)];
};

struct per_request_ctx {
	struct list_head list; /* typecasts exists in few places. */
	uint32_t flags; /* which are related to request. */
	struct ablkcipher_request *req;
};

static struct list_head queue_pending;
static wait_queue_head_t g_file_wq; /* queue for blocking file operations */
static int num_queues; /* number of established queues. */
static uint32_t queue_pending_len;

static DEFINE_SPINLOCK(global_lock); /* lock for non-per worker variables. */
static DEFINE_SPINLOCK(queue_lock); /* protect access to queue_pending. */

/*
 * Count the number of elements in scatterlist.
 */
static int sg_count(struct scatterlist *sg, size_t nbytes)
{
	int n = 0;

	while (sg && nbytes > 0) {
		n++;
		nbytes -= sg->length;
		sg = sg_next(sg);
	}
	if (!sg && nbytes > 0)
		pr_err("not enought input");

	return n;
}

/*
 * Copy data from userspace process to sg.
 */
static int sg_copy_from_user_buffer(struct scatterlist *sg,
				    unsigned int nents,
				    const unsigned char __user *src,
				    size_t nbytes)
{
	int ret = 0;
	struct sg_mapping_iter miter;

	sg_miter_start(&miter, sg, nents, SG_MITER_TO_SG);
	while (sg_miter_next(&miter) && nbytes > 0 && miter.addr) {
		size_t len = min(miter.length, nbytes);

		if (__copy_from_user(miter.addr, src, len)) {
			ret = -EINVAL;
			goto error_sg_copy_from_user_buffer;
		}
		nbytes -= len;
		src += len;
	}
	/* non-zero remainder means that not all bytes are copied. */
	BUG_ON(nbytes != 0);

error_sg_copy_from_user_buffer:
	sg_miter_stop(&miter);
	return ret;
}

/*
 * Copy data to userspace process from sg.
 */
static int sg_copy_to_user_buffer(struct scatterlist *sg,
				  unsigned int nents,
				  unsigned char __user *dst,
				  size_t nbytes)
{
	int ret = 0;
	struct sg_mapping_iter miter;

	sg_miter_start(&miter, sg, nents, SG_MITER_FROM_SG);
	while (sg_miter_next(&miter) && nbytes > 0 && miter.addr) {
		size_t len = min(miter.length, nbytes);

		if (__copy_to_user(dst, miter.addr, len)) {
			ret = -EINVAL;
			goto error_sg_copy_to_user_buffer;
		}
		nbytes -= len;
		dst += len;
	}
	/* non-zero remainder means that not all bytes are copied. */
	BUG_ON(nbytes != 0);

error_sg_copy_to_user_buffer:
	sg_miter_stop(&miter);
	return ret;
}

/*
 * Open files.
 */
static int file_open(struct inode *inode, struct file *filp)
{
	unsigned int current_worker;

	spin_lock_bh(&global_lock);
	current_worker = num_queues;

	/* Only as many files are allowed to be open as there are queues. */
	if (current_worker >= KSCL_MAX_WORKERS) {
		spin_unlock_bh(&global_lock);
		pr_err("Too many workers to attach pid %d.\n",
		       (int) (current->pid));
		return -EPERM;
	}

	num_queues = current_worker + 1;
	spin_unlock_bh(&global_lock);
	filp->private_data = (void *)(long)current_worker;
	pr_info("Process %d connected - %d queues available\n",
		current->pid, num_queues);
	return 0;
}

/*
 * Get requests for specific worker.
 */
static uint32_t get_reqs(struct per_request_ctx *reqs[],
			 unsigned int current_worker,
			 uint32_t num_req,
			 size_t   szleft)
{
	uint32_t count = 0;

	spin_lock_bh(&queue_lock);
	while (num_req && !list_empty(&queue_pending)) {
		struct per_request_ctx *req
			= (struct per_request_ctx *)queue_pending.next;
		if (!req || !req->req || req->req->nbytes > szleft) {
			pr_debug("Buffer full at %dth data request",
				 (int)count);
			break;
		}
		list_del(&req->list);
		reqs[count] = req;
		count++;
		num_req--;
		queue_pending_len--;
		szleft -= req->req->nbytes; /* Count remainder. */
	}
	spin_unlock_bh(&queue_lock);
	return count;
}

/*
 * Transfer single reply.
 */
static int transfer_user_reply(uint32_t flags,
			       uint32_t context,
			       struct per_request_ctx *rctx,
			       void __user *data)
{
	struct ablkcipher_request *req = rctx->req;
	int bytes;
	int ret;

	if (!(flags & KSCL_FLAGS_SEND)) {
		/* Error, always report as -EINVAL. */
		req->base.complete(&req->base, -EINVAL);
		return 0;
	}

	bytes = req->nbytes;
	ret = sg_copy_from_user_buffer(req->dst,
				       sg_count(req->dst, bytes),
				       data, req->nbytes);

	/* Return value chosen according to copy success or fail. */
	req->base.complete(&req->base, ret);

	return bytes;
}

/*
 * Transfer single request.
 */
static uint32_t transfer_user_req(uint32_t flags,
				  uint32_t context,
				  struct per_request_ctx *rctx,
				  struct kscl_ctrl __user *ctrl,
				  void __user *data)
{
	/* Control information. */
	long comb;
	struct ablkcipher_request *req = rctx->req;
	struct per_crypto_alg_transform_ctx *ctx =
	crypto_ablkcipher_ctx(crypto_ablkcipher_reqtfm(req));

	uint32_t len = req->nbytes;
	uint32_t keylen = ctx->keylen;

	comb = __copy_to_user(&ctrl->key, ctx->key, ctx->keylen);
	comb |= __copy_to_user(&ctrl->iv, req->info, AES_BLOCK_SIZE);
	comb |= __put_user(len, &ctrl->len) == -EFAULT;
	comb |= __put_user(keylen, &ctrl->keylen) == -EFAULT;

	comb |= sg_copy_to_user_buffer(req->src,
				       sg_count(req->src,
						req->nbytes),
				       data, req->nbytes);

	if (!comb)
		return keylen; /* Success, return key length. */
	else
		return 0; /* Failure, return 0. */
}

/*
 * Copy the results and acknowledge that the requests have been handled.
 */
static int transfer_user_replies(struct kscl_req __user *reqs,
				 unsigned char __user *data_p,
				 unsigned int current_worker,
				 uint32_t num_req)
{
	uint32_t blank = KSCL_FLAGS_BLANK;
	int ret = 0;
	uint32_t i;

	for (i = 0; i < num_req; i++) {
		uint32_t flags;
		uint32_t context;
		struct per_request_ctx *rctx;

		__get_user(flags, &reqs->flags);
		pr_debug("Check flags (%d): %x\n", i, flags);
		if (!(flags & (KSCL_FLAGS_SEND | KSCL_FLAGS_ERR))) {
			reqs += 1;
			continue;
		}

		__get_user(context, &reqs->context);

		pr_debug("Processing from user (%d): wrk: %d ctx: %u\n",
			 i, (int)current_worker,
			 (unsigned int) context);

		rctx = packets_in_play[current_worker][context &
						KSCL_RING_INDEX_MASK];
		if (!rctx) {
			pr_debug("unable to get rctx: (%u,%u) (idx=%d)",
				 (unsigned int) current_worker,
				 (unsigned int) context, (int) i);
			return -EFAULT;
		}
		packets_in_play[current_worker][context &
					 KSCL_RING_INDEX_MASK] = NULL;
		pr_debug("rctx: %p req: %p from data = %p\n",
			 rctx, rctx->req, data_p);
		data_p += transfer_user_reply(flags, context, rctx, data_p);
		__put_user(blank, &reqs->flags);

		reqs += 1;
	}
	return ret;
}

/*
 * Get queued requests.
 */
static int transfer_reqs(struct kscl_req __user *reqs,
			 unsigned char __user *datap,
			 struct per_request_ctx **rctxs,
			 unsigned int current_worker,
			 uint32_t num_req)
{
	int ret = 0;
	uint32_t i;

	for (i = 0; i < num_req; i++) {
		uint32_t flags;

		__get_user(flags, &reqs->flags);
		pr_debug("Transfer req (%d) to userspace\n", i);
		if ((flags & (KSCL_FLAGS_BLANK)) != 0) {
			uint32_t context;
			uint32_t kl;

			context = i;

			if (packets_in_play[current_worker][i])
				return -EFAULT;

			pr_debug("set packets_in_play(%d, %d) = %p\n",
				 current_worker, i, *rctxs);
			packets_in_play[current_worker][i] = *rctxs;
			flags = (*rctxs)->flags;

			/* If busy was signalled, signal other context that
			   busy has ended */
			if ((flags & KSCL_FLAGS_BUSY) != 0) {
				struct ablkcipher_request *req;

				/* Has signalled busy => wake up. */
				req = (*rctxs)->req;
				req->base.complete(&req->base, -EINPROGRESS);
				flags &= ~KSCL_FLAGS_BUSY;
				(*rctxs)->flags = flags;
				pr_debug("Worker %d queue", current_worker);
				pr_debug(" problem resolved,");
				pr_debug(" signalling -EINPROGRESS\n");
			}
			kl = transfer_user_req(flags, context, *rctxs,
					       &reqs->ctrl, datap);

			if (kl == 0 ||
			    (__put_user(flags, &reqs->flags) == -EFAULT) ||
			    (__put_user(context, &reqs->context) == -EFAULT)) {
				/* Send request to user space failed. */
				struct ablkcipher_request *req;

				req = (*rctxs)->req;
				req->base.complete(&req->base, -EINVAL);
				/* mark it as blank. */
				flags = KSCL_FLAGS_BLANK;
				(void)__put_user(flags, &reqs->flags);
			} else {
				datap += (*rctxs)->req->nbytes;
			}
		}
		reqs += 1;
		rctxs += 1;
	}
	if (num_req == 0)
		pr_debug("No requests are transferred to userspace\n");
	return ret;
}

/*
 * Handle combined reply-and-request operation via ioctl.
 */
static long file_ioctl(struct file *filp,
		       unsigned int cmd,
		       unsigned long arg)
{
	uint32_t blank = KSCL_FLAGS_BLANK;
	unsigned int current_worker =
		((unsigned int)(unsigned long)(filp->private_data));
	int ret = 0;
	const uint32_t iosize = sizeof(struct kscl_reqs_and_data);
	uint32_t num_req = KSCL_RING_ENTRIES_SAFE;
	uint32_t num_reqo;
	struct kscl_reqs_and_data __user *userp = (void __user *)arg;
	unsigned char __user *datap = (void __user *)(&userp->data);
	struct per_request_ctx **reqs;

	BUG_ON(current_worker == ((unsigned int)-1));

	if (num_req == 0)
		return 0; /* Allow zero length request. */

	pr_debug("IOCTL Request: cmd = %x, exp = %lx sz: %zd/%zd <%zd : %zd >\n",
		 cmd,
		 KSCL_QUEUE_IOCTL,
		 sizeof(struct kscl_req), sizeof(struct kscl_reqs_and_data),
		 sizeof(struct kscl_reqs_and_data) / sizeof(struct kscl_req),
		 sizeof(struct kscl_reqs_and_data) % sizeof(struct kscl_req));

	if (cmd != KSCL_QUEUE_IOCTL)
		return -EINVAL; /* wrong command. */

	/* Verify read-write access to entire area */
	if (!access_ok(VERIFY_WRITE, userp, iosize) ||
	    !access_ok(VERIFY_READ, userp, iosize))
		return -EFAULT;

	pr_debug("IOCTL Request: valid\n");

	/* Send packets forwards. */
	ret = transfer_user_replies(userp->reqs, datap,
				    current_worker, num_req);
	if (ret != 0)
		return ret;

	reqs = (struct per_request_ctx **)
		kmalloc(KSCL_RING_ENTRIES * sizeof(struct per_request_ctx *),
			GFP_KERNEL);
	if (!reqs) {
		pr_err("Memory %d bytes allocation failed",
			(int)(KSCL_RING_ENTRIES *
					sizeof(struct per_request_ctx *)));
		return -ENOMEM;
	}

	num_reqo = get_reqs(reqs, current_worker, num_req,
			    KSCL_DATA_SIZE);

	while (num_reqo == 0) {
		/* Sleep until work or interrupted. */
		ret = wait_event_interruptible(g_file_wq,
					       !list_empty(&queue_pending));
		if (ret != 0) {
			kfree(reqs);
			return ret;
		}
		num_reqo = get_reqs(reqs, current_worker, num_req,
				    KSCL_DATA_SIZE);
	}
	pr_debug("wake up: %d req(s) to handle.\n", num_reqo);

	/* Fill-in the first 'num_reqo' entries. */
	ret = transfer_reqs(userp->reqs, datap, reqs, current_worker,
			    num_reqo);
	/* Mark remaining entries unused. */
	while (num_req > num_reqo) {
		num_req--;
		(void)__put_user(blank, &userp->reqs[num_req].flags);
	}

	/* Free request buffer */
	kfree(reqs);

	return ret;
}

static ssize_t file_read(struct file *filp, char *buf, size_t count,
			 loff_t *pos)
{
	return -EINVAL; /* not supported */
}

static ssize_t file_write(struct file *filp, const char *buf, size_t count,
			  loff_t *pos)
{
	return -EINVAL; /* not supported */
}

static int file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL; /* not supported */
}

/*
 * Disconnect worker.
 */
static int file_release(struct inode *inode, struct file *filp)
{
	int i;
	unsigned int current_worker =
			(unsigned int) (unsigned long) (filp->private_data);
	BUG_ON(current_worker >= KSCL_MAX_WORKERS);
	pr_info("Process %d disconnected\n", current->pid);

	/* Respond all remaining entries in "packets_in_play". */
	for (i = 0; i < KSCL_RING_INDEX_MASK; i++) {
		struct per_request_ctx *rctx =
			packets_in_play[current_worker][i];
		if (rctx)
			transfer_user_reply(KSCL_FLAGS_ERR, i, rctx, NULL);
		packets_in_play[current_worker][i] = 0;
	}

	spin_lock_bh(&global_lock);
	num_queues--; /* update the available queues number. */
	spin_unlock_bh(&global_lock);
	return 0;
}

/*
 * Queue crypto operation for execution and wait userspace process handle it.
 */
static int kscl_aes_qcrypt(struct ablkcipher_request *req, uint32_t flags)
{
	struct per_request_ctx *rctx = ablkcipher_request_ctx(req);
	int rc;
	int rflags = req->base.flags;
	uint32_t pending_len;

	if (req->nbytes < AES_BLOCK_SIZE) {
		pr_err("request size %d less than AES block size\n",
		       (int)req->nbytes);
		return -EINVAL;
	}
	if (req->nbytes > KSCL_DATA_SIZE) {
		pr_err("request size %d greater than maximum supported\n",
		       (int)req->nbytes);
		return -ENOMEM;
	}

	/* Check blocksize */
	if (req->nbytes % AES_BLOCK_SIZE) {
		pr_err("request size is not multiple of AES block size\n");
		return -EINVAL;
	}
	if (!(rflags & CRYPTO_TFM_REQ_MAY_SLEEP)) {
		pr_err("non-sleeping request for somc kscl");
		return -EINVAL;
	}

	if (!req->base.complete) {
		pr_err("no completion callback?!?");
		return -EINVAL;
	}

	/* save the flags and ablkcipher pointer to the request context. */
	rctx->flags = flags;
	rctx->req = req;

	spin_lock_bh(&queue_lock);

	list_add_tail(&rctx->list, &queue_pending);
	pending_len = (++queue_pending_len);

	if (pending_len > KSCL_PENDING_LEN) {
		rc = -EBUSY; /* Indicate busy. */
		rctx->flags |= KSCL_FLAGS_BUSY;
		pr_debug("Waiting queue is too long, signalling -EBUSY");
	} else {
		rc = -EINPROGRESS; /* standard "in-progress" status. */
	}

	spin_unlock_bh(&queue_lock);

	/* Wake the processing thread up. */
	wake_up_interruptible(&g_file_wq);

	return rc;
}

/*
 * Set key for kscl's AES cipher in ECB, CBC or XTS mode.
 */
static int kscl_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
			    unsigned int keylen)
{
	struct ablkcipher_alg *alg = crypto_ablkcipher_alg(tfm);
	struct per_crypto_alg_transform_ctx *ctx = crypto_ablkcipher_ctx(tfm);

	if (alg->max_keysize == AES_MAX_KEY_SIZE) {
		if (keylen != KSCL_KEY_ID_SIZE &&
		    keylen != AES_KEYSIZE_128 &&
		    keylen != AES_KEYSIZE_192 &&
		    keylen != AES_KEYSIZE_256)
			return -EINVAL;
	} else if (alg->max_keysize == AES_MAX_KEY_SIZE * 2) {
		if (keylen != KSCL_KEY_ID_SIZE &&
		    keylen != AES_KEYSIZE_128 * 2 &&
		    keylen != AES_KEYSIZE_256 * 2)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;
	return 0;
}

/*
 * AES in ECB mode, encryption with 128-256 bit key.
 */
static int kcsl_aes_ecb_encrypt(struct ablkcipher_request *req)
{
	return kscl_aes_qcrypt(req, KSCL_FLAGS_ENCRYPT | KSCL_FLAGS_ECB);
}

/*
 * AES in ECB mode, decryption with 128-256 bit key.
 */
static int kcsl_aes_ecb_decrypt(struct ablkcipher_request *req)
{
	return kscl_aes_qcrypt(req, KSCL_FLAGS_DECRYPT | KSCL_FLAGS_ECB);
}

/*
 * AES in CBC mode, encryption with 128-256 bit key.
 */
static int kscl_aes_cbc_encrypt(struct ablkcipher_request *req)
{
	return kscl_aes_qcrypt(req, KSCL_FLAGS_ENCRYPT | KSCL_FLAGS_CBC);
}

/*
 * AES in CBC mode, decryption with 128-256 bit key.
 */
static int kscl_aes_cbc_decrypt(struct ablkcipher_request *req)
{
	return kscl_aes_qcrypt(req, KSCL_FLAGS_DECRYPT | KSCL_FLAGS_CBC);
}

/*
 * AES in XTS mode, encryption with 256-512 bit key.
 */
static int kscl_aes_xts_encrypt(struct ablkcipher_request *req)
{
	return kscl_aes_qcrypt(req, KSCL_FLAGS_ENCRYPT | KSCL_FLAGS_XTS);
}

/*
 * AES in XTS mode, decryption with 256-512 bit key.
 */
static int kscl_aes_xts_decrypt(struct ablkcipher_request *req)
{
	return kscl_aes_qcrypt(req, KSCL_FLAGS_DECRYPT | KSCL_FLAGS_XTS);
}

/*
 * initialize tfm for kscl.
 */
static int kscl_aes_cra_init(struct crypto_tfm *tfm)
{
	tfm->crt_ablkcipher.reqsize = sizeof(struct per_request_ctx);
	return 0;
}

/*
 * Unitialize tfm for kscl.
 */
static void kscl_aes_cra_exit(struct crypto_tfm *tfm)
{
}

static struct crypto_alg algs[] = {
	{
		.cra_name = "ecb(fipsaes)",
		.cra_driver_name = "ecb-fipsaes",
		.cra_priority = 500,
		.cra_flags = CRYPTO_ALG_TYPE_GIVCIPHER | CRYPTO_ALG_ASYNC,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct per_crypto_alg_transform_ctx),
		.cra_alignmask = 0,
		.cra_type = &crypto_ablkcipher_type,
		.cra_module = THIS_MODULE,
		.cra_init = kscl_aes_cra_init,
		.cra_exit = kscl_aes_cra_exit,
		.cra_u.ablkcipher = {
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = 0,
			.setkey = kscl_aes_setkey,
			.encrypt = kcsl_aes_ecb_encrypt,
			.decrypt = kcsl_aes_ecb_decrypt,
		}
	}, {
		.cra_name = "cbc(fipsaes)",
		.cra_driver_name = "cbc-fipsaes",
		.cra_priority = 500,
		.cra_flags = CRYPTO_ALG_TYPE_GIVCIPHER | CRYPTO_ALG_ASYNC,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct per_crypto_alg_transform_ctx),
		.cra_alignmask = 0,
		.cra_type = &crypto_ablkcipher_type,
		.cra_module = THIS_MODULE,
		.cra_init = kscl_aes_cra_init,
		.cra_exit = kscl_aes_cra_exit,
		.cra_u.ablkcipher = {
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
			.setkey = kscl_aes_setkey,
			.encrypt = kscl_aes_cbc_encrypt,
			.decrypt = kscl_aes_cbc_decrypt,
		}
	}, {
		.cra_name = "xts(fipsaes)",
		.cra_driver_name = "xts-fipsaes",
		.cra_priority = 500,
		.cra_flags = CRYPTO_ALG_TYPE_GIVCIPHER | CRYPTO_ALG_ASYNC,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct per_crypto_alg_transform_ctx),
		.cra_alignmask = 0,
		.cra_type = &crypto_ablkcipher_type,
		.cra_module = THIS_MODULE,
		.cra_init = kscl_aes_cra_init,
		.cra_exit = kscl_aes_cra_exit,
		.cra_u.ablkcipher = {
			.min_keysize = KSCL_KEY_ID_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE * 2,
			.ivsize = AES_BLOCK_SIZE,
			.setkey = kscl_aes_setkey,
			.encrypt = kscl_aes_xts_encrypt,
			.decrypt = kscl_aes_xts_decrypt,
		}
	}
};

enum kscl_load_state {
	KSCL_STATE_CRYPTO_REGISTERED,
	KSCL_STATE_LOADED
};

/*
 * Unload.
 */
static void kscl_aes_mod_unload(enum kscl_load_state mstate)
{
	int i;

	pr_debug("kscl_aes_mod_unload, state %d\n", mstate);

	switch (mstate) {
	case KSCL_STATE_LOADED:
		remove_proc_entry(KSCL_PROC_NAME, NULL);
		/* through */
	case KSCL_STATE_CRYPTO_REGISTERED:
		for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++)
			crypto_unregister_alg(&algs[i]);
		break;
	default:
		pr_err("Invalid module state.\n");
		break;
	}
}

static const struct file_operations file_fops = {
	.open = file_open,
	.release = file_release,
	.unlocked_ioctl = file_ioctl,
	.read = file_read,
	.write = file_write,
	.mmap = file_mmap,
	.owner = THIS_MODULE,
};

/*
 * Module initialization.
 */
static int __init kscl_aes_mod_init(void)
{
	int rc;
	int i;
	struct proc_dir_entry *proc_entry;

	INIT_LIST_HEAD(&queue_pending);
	init_waitqueue_head(&g_file_wq);
	memset(&packets_in_play, 0, sizeof(packets_in_play));

	pr_debug("Loading kscl\n");
	for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
		INIT_LIST_HEAD(&algs[i].cra_list);
		rc = crypto_register_alg(&algs[i]);
		if (rc != 0) {
			pr_err("Error registering %s\n", algs[i].cra_name);
			while (i > 0)
				crypto_unregister_alg(&algs[--i]);
			return rc;
		}
	}
	/* create_proc_entry() was deprecated and replace with
	 * proc_create_data() since it's open to a race condition where the
	 * proc entry is visible before the file operations have been set for
	 * it. */
	proc_entry = proc_create_data(KSCL_PROC_NAME, S_IWUSR | S_IRUSR, NULL,
				      &file_fops, NULL);
	if (!proc_entry) {
		pr_err("Unable to register proc entry %s\n", KSCL_PROC_NAME);
		kscl_aes_mod_unload(KSCL_STATE_CRYPTO_REGISTERED);
		return -EINVAL;
	}

	if (!uid)
		proc_uid = KUIDT_INIT(SYSTEM_PROC_UID);
	else
		proc_uid = KUIDT_INIT(uid);
	pr_debug("kscl: uid:%d proc_uid:%d\n", uid,
			from_kuid(&init_user_ns, proc_uid));

	proc_set_user(proc_entry, proc_uid, proc_gid);

	return 0;
}

/*
 * Cleanup the module during onload.
 */
static void __exit kscl_aes_mod_exit(void)
{
	kscl_aes_mod_unload(KSCL_STATE_LOADED);
}

module_init(kscl_aes_mod_init);
module_exit(kscl_aes_mod_exit);

MODULE_DESCRIPTION("Sony Mobile Communications FIPS AES-XTS/AES-CBC Driver.");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");
MODULE_AUTHOR("Sony Mobile Communications");

module_param(uid, int, 0);
MODULE_PARM_DESC(
	uid,
	"User id for the userland device access (default 1000 == system)");
