/*
 * RDMA support for KVM software distributed memory
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 *
 * Authors:
 *   Chen Yubin <i@binss.me>
 *   Ding Zhuocheng <tcbbdddd@gmail.com>
 *   Zhang Jin <437629012@qq.com>
 *   Xiong Tianlei <qmyyxtl@gmai.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/kvm_host.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#include "krdma.h"

static bool dbg = 0;
#define pgprintk(x...) do { if (dbg) printk(x); } while (0)

#define KRDMA_RECV_WAIT_BUCKETS 64

static bool krdma_current_should_stop(void)
{
	if (fatal_signal_pending(current))
		return true;

	if ((current->flags & PF_KTHREAD) && current->worker_private)
		return kthread_should_stop();

	return false;
}

/* Invalid slots are reusable; posted slots are owned by the HCA. */
enum krdma_trans_state { INVALID = 0, POSTED };

typedef struct krdma_send_trans {
	/* For DMA */
	void *send_buf;
	dma_addr_t send_dma_addr;
	enum krdma_trans_state state;
	struct completion done;
	int completion_status;
	bool auto_reclaim;

	struct ib_sge send_sge;
	struct ib_send_wr sq_wr;
} krdma_send_trans_t;

typedef struct krdma_recv_trans {
	/* For DMA */
	void *recv_buf;
	dma_addr_t recv_dma_addr;
	enum krdma_trans_state state;

	struct ib_sge recv_sge;
	struct ib_recv_wr rq_wr;
} krdma_recv_trans_t;

struct krdma_recv_msg {
	struct list_head list;
	tx_add_t tx_add;
	size_t length;
	char data[];
};

/* control block */
struct krdma_cb {
	struct mutex slock;
	struct mutex cq_pump_lock;
	struct semaphore send_slots;
	spinlock_t recv_queue_lock;
	wait_queue_head_t recv_any_wait;
	wait_queue_head_t recv_tx_wait[KRDMA_RECV_WAIT_BUCKETS];
	wait_queue_head_t recv_cq_wait;
	wait_queue_head_t send_cq_wait;

	enum krdma_role role;

	enum {
		KRDMA_INIT = 0,
		KRDMA_ADDR_RESOLVED = 1,
		KRDMA_ROUTE_RESOLVED = 2,
		KRDMA_CONNECTED = 3,
		KRDMA_FLUSHING = 4,
		KRDMA_CLOSING = 5,
		KRDMA_CLOSED = 6,
		KRDMA_SEND_DONE = 7,
		KRDMA_RECV_DONE = 8,
		KRDMA_ERROR = 9,
		KRDMA_CONNECT_REJECTED = 10,
		KRDMA_DISCONNECTED = 11,
	} state;

	/* Communication Manager id */
	struct rdma_cm_id *cm_id;

	/* Completion Queue */
	struct ib_cq *send_cq;
	struct ib_cq *recv_cq;
	/* Protection Domain */
	struct ib_pd *pd;
	/* Queue Pair */
	struct ib_qp *qp;

	/*
	 * The buffers to buffer async requests.
	 */
	krdma_send_trans_t send_trans_buf[RDMA_SEND_BUF_SIZE];
	krdma_recv_trans_t recv_trans_buf[RDMA_RECV_BUF_SIZE];
	struct list_head recv_msg_queue;
	atomic64_t recv_seq;
	atomic64_t recv_cq_seq;
	atomic64_t send_cq_seq;
	struct task_struct *rx_task;
	struct task_struct *tx_task;
	int recv_error;
	unsigned int next_send_slot;

	struct completion cm_done;

	struct list_head list;

	struct list_head ready_conn;
	struct list_head active_conn;

	int retry_count;
};

int krdma_create_cb(struct krdma_cb **cbp, enum krdma_role role)
{
	struct krdma_cb *cb;
	unsigned int i;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	init_completion(&cb->cm_done);
	INIT_LIST_HEAD(&cb->recv_msg_queue);
	spin_lock_init(&cb->recv_queue_lock);
	init_waitqueue_head(&cb->recv_any_wait);
	for (i = 0; i < KRDMA_RECV_WAIT_BUCKETS; i++)
		init_waitqueue_head(&cb->recv_tx_wait[i]);
	init_waitqueue_head(&cb->recv_cq_wait);
	init_waitqueue_head(&cb->send_cq_wait);
	atomic64_set(&cb->recv_seq, 0);
	atomic64_set(&cb->recv_cq_seq, 0);
	atomic64_set(&cb->send_cq_seq, 0);

	cb->role = role;
	if (cb->role == KRDMA_LISTEN_CONN) {
		INIT_LIST_HEAD(&cb->ready_conn);
		INIT_LIST_HEAD(&cb->active_conn);
	}

	*cbp = cb;
	return 0;
}

static wait_queue_head_t *krdma_recv_tx_waitq(struct krdma_cb *cb,
		uint32_t txid)
{
	return &cb->recv_tx_wait[txid & (KRDMA_RECV_WAIT_BUCKETS - 1)];
}

static void krdma_wake_message_waiters(struct krdma_cb *cb, uint32_t txid)
{
	wake_up_interruptible(krdma_recv_tx_waitq(cb, txid));
	wake_up_interruptible(&cb->recv_any_wait);
}

static void krdma_wake_all_message_waiters(struct krdma_cb *cb)
{
	unsigned int i;

	wake_up_all(&cb->recv_any_wait);
	for (i = 0; i < KRDMA_RECV_WAIT_BUCKETS; i++)
		wake_up_all(&cb->recv_tx_wait[i]);
}

/* CQ callbacks run in interrupt context; defer all polling to the pumps. */
static void krdma_recv_cq_comp_handler(struct ib_cq *cq, void *context)
{
	struct krdma_cb *cb = context;

	atomic64_inc(&cb->recv_cq_seq);
	wake_up(&cb->recv_cq_wait);
}

static void krdma_send_cq_comp_handler(struct ib_cq *cq, void *context)
{
	struct krdma_cb *cb = context;

	atomic64_inc(&cb->send_cq_seq);
	wake_up(&cb->send_cq_wait);
}

static int krdma_cma_event_handler(struct rdma_cm_id *cm_id,
		struct rdma_cm_event *event)
{
	int ret;
	struct krdma_cb *cb = cm_id->context;
	struct krdma_cb *conn_cb = NULL;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		pgprintk("%s: RDMA_CM_EVENT_ADDR_RESOLVED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_ADDR_RESOLVED;
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		pgprintk("%s: RDMA_CM_EVENT_ROUTE_RESOLVED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_ROUTE_RESOLVED;
		break;

	case RDMA_CM_EVENT_ROUTE_ERROR:
		pgprintk("%s: RDMA_CM_EVENT_ROUTE_ERROR, cm_id %p, error %d\n",
				__func__, cm_id, event->status);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		pgprintk("%s: RDMA_CM_EVENT_CONNECT_REQUEST, cm_id %p\n",
				__func__, cm_id);
		/* create a new cb */
		ret = krdma_create_cb(&conn_cb, KRDMA_ACCEPT_CONN);
		if (!ret) {
			conn_cb->cm_id = cm_id;
			cm_id->context = conn_cb;
			list_add_tail(&conn_cb->list, &cb->ready_conn);
		} else {
			printk(KERN_ERR "%s: krdma_create_cb fail, ret %d\n",
					__func__, ret);
			cb->state = KRDMA_ERROR;
		}
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		pgprintk("%s: RDMA_CM_EVENT_ESTABLISHED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_CONNECTED;
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		pgprintk(KERN_ERR "%s: RDMA_CM_EVENT_DISCONNECTED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_DISCONNECTED;
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		printk(KERN_ERR "%s: RDMA_CM_EVENT %d, cm_id %p\n",
				__func__, event->event, cm_id);
		cb->state = KRDMA_CONNECT_REJECTED;
		break;
	default:
		pgprintk("%s: unknown event %d, cm_id %p\n",
				__func__, event->event, cm_id);
	}
	krdma_wake_all_message_waiters(cb);
	wake_up_all(&cb->recv_cq_wait);
	wake_up_all(&cb->send_cq_wait);
	complete(&cb->cm_done);
	return 0;
}

int krdma_setup_buffers(struct krdma_cb *cb)
{
	int i;

	mutex_init(&cb->slock);
	mutex_init(&cb->cq_pump_lock);
	sema_init(&cb->send_slots, RDMA_SEND_BUF_SIZE);

	memset(cb->send_trans_buf, 0, RDMA_SEND_BUF_SIZE *
			sizeof(krdma_send_trans_t));
	memset(cb->recv_trans_buf, 0, RDMA_RECV_BUF_SIZE *
			sizeof(krdma_recv_trans_t));

	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		init_completion(&cb->send_trans_buf[i].done);
		cb->send_trans_buf[i].send_buf = dma_alloc_coherent(cb->pd->device->dma_device,
				RDMA_SEND_BUF_LEN, &cb->send_trans_buf[i].send_dma_addr,
				GFP_KERNEL | GFP_DMA);
		if (!cb->send_trans_buf[i].send_buf) {
			printk(KERN_ERR "%s: dma_alloc_coherent send_buf failed\n",
					 __func__);
			goto out_free_bufs;
		}

		cb->send_trans_buf[i].send_sge.lkey = cb->pd->local_dma_lkey;
		/* .length is set at runtime. */
		cb->send_trans_buf[i].send_sge.addr = cb->send_trans_buf[i].send_dma_addr;
		cb->send_trans_buf[i].sq_wr.next = NULL;
		/* .wr_id is set at runtime. */
		cb->send_trans_buf[i].sq_wr.sg_list = &cb->send_trans_buf[i].send_sge;
		cb->send_trans_buf[i].sq_wr.num_sge = 1;
		cb->send_trans_buf[i].sq_wr.opcode = IB_WR_SEND_WITH_IMM;
		cb->send_trans_buf[i].sq_wr.send_flags = IB_SEND_SIGNALED;
		/* .ex.imm_data is set at runtime. */
	}

	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		cb->recv_trans_buf[i].recv_buf = dma_alloc_coherent(cb->pd->device->dma_device,
				RDMA_RECV_BUF_LEN, &cb->recv_trans_buf[i].recv_dma_addr,
				GFP_KERNEL | GFP_DMA);
		if (!cb->recv_trans_buf[i].recv_buf) {
			printk(KERN_ERR "%s: ib_dma_alloc_coherent recv_buf failed\n",
					 __func__);
			goto out_free_bufs;
		}

		cb->recv_trans_buf[i].recv_sge.lkey = cb->pd->local_dma_lkey;
		cb->recv_trans_buf[i].recv_sge.length = RDMA_RECV_BUF_LEN;
		cb->recv_trans_buf[i].recv_sge.addr = cb->recv_trans_buf[i].recv_dma_addr;
		cb->recv_trans_buf[i].rq_wr.next = NULL;
		cb->recv_trans_buf[i].rq_wr.wr_id = i;
		cb->recv_trans_buf[i].rq_wr.sg_list = &cb->recv_trans_buf[i].recv_sge;
		cb->recv_trans_buf[i].rq_wr.num_sge = 1;
	}

	return 0;

out_free_bufs:
	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		if (cb->send_trans_buf[i].send_buf) {
			dma_free_coherent(cb->pd->device->dma_device, RDMA_SEND_BUF_LEN,
					cb->send_trans_buf[i].send_buf,
					cb->send_trans_buf[i].send_dma_addr);
		}
	}
	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].recv_buf) {
			dma_free_coherent(cb->pd->device->dma_device, RDMA_RECV_BUF_LEN,
					cb->recv_trans_buf[i].recv_buf,
					cb->recv_trans_buf[i].recv_dma_addr);
		}
	}
	return -ENOMEM;
}

int krdma_free_buffers(struct krdma_cb *cb)
{
	struct krdma_recv_msg *msg, *tmp;
	int i;

	list_for_each_entry_safe(msg, tmp, &cb->recv_msg_queue, list) {
		list_del(&msg->list);
		kvfree(msg);
	}

	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		if (cb->send_trans_buf[i].send_buf) {
			dma_free_coherent(cb->pd->device->dma_device, RDMA_SEND_BUF_LEN,
					cb->send_trans_buf[i].send_buf,
					cb->send_trans_buf[i].send_dma_addr);
			cb->send_trans_buf[i].send_buf = NULL;
		}
	}
	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].recv_buf) {
			dma_free_coherent(cb->pd->device->dma_device, RDMA_RECV_BUF_LEN,
					cb->recv_trans_buf[i].recv_buf,
					cb->recv_trans_buf[i].recv_dma_addr);
		}
		cb->recv_trans_buf[i].recv_buf = NULL;
	}

	return 0;
}

int krdma_map_remote_page(struct krdma_cb *cb, struct page *page,
		u64 *remote_addr, u32 *rkey)
{
	u64 dma;

	if (!cb || !cb->pd || !page || !remote_addr || !rkey)
		return -EINVAL;
	dma = ib_dma_map_page(cb->pd->device, page, 0, PAGE_SIZE, DMA_FROM_DEVICE);
	if (ib_dma_mapping_error(cb->pd->device, dma))
		return -EIO;
	*remote_addr = dma;
	*rkey = cb->pd->unsafe_global_rkey;
	return 0;
}

void krdma_unmap_remote_page(struct krdma_cb *cb, struct page *page,
		u64 remote_addr)
{
	if (cb && cb->pd && page)
		ib_dma_unmap_page(cb->pd->device, remote_addr, PAGE_SIZE,
				  DMA_FROM_DEVICE);
}

void krdma_sync_remote_page_for_device(struct krdma_cb *cb, u64 remote_addr)
{
	if (cb && cb->pd)
		ib_dma_sync_single_for_device(cb->pd->device, remote_addr,
					      PAGE_SIZE, DMA_FROM_DEVICE);
}

void krdma_sync_remote_page_for_cpu(struct krdma_cb *cb, u64 remote_addr)
{
	if (cb && cb->pd)
		ib_dma_sync_single_for_cpu(cb->pd->device, remote_addr, PAGE_SIZE,
					   DMA_FROM_DEVICE);
}

static int krdma_post_recv(struct krdma_cb *cb);
static int krdma_start_cq_pumps(struct krdma_cb *cb);
static void krdma_stop_cq_pumps(struct krdma_cb *cb);

static int krdma_connect_single(const char *host, const char *port,
		struct krdma_cb *cb)
{
	int ret;
	struct sockaddr_in addr;
	long portdec;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_init_attr;
	struct rdma_conn_param conn_param;

	if (host == NULL || port == NULL || cb == NULL)
		return -EINVAL;

	/* Create cm_id */
	cb->cm_id = rdma_create_id(&init_net, krdma_cma_event_handler, cb,
					RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cb->cm_id)) {
		ret = PTR_ERR(cb->cm_id);
		printk(KERN_ERR "rdma_create_id error %d\n", ret);
		goto exit;
	}
	printk("created cm_id %p\n", cb->cm_id);

	/* Resolve address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	BUG_ON(kstrtol(port, 10, &portdec) != 0);
	addr.sin_addr.s_addr = in_aton(host);
	addr.sin_port = htons(portdec);
	ret = rdma_resolve_addr(cb->cm_id, NULL,
			(struct sockaddr *)&addr, RDMA_RESOLVE_TIMEOUT);
	if (ret) {
		printk(KERN_ERR "rdma_resolve_addr failed, ret %d\n", ret);
		goto free_cm_id;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_ADDR_RESOLVED) {
		ret = -STATE_ERROR;
		printk(KERN_ERR "rdma_resolve_route state error, ret %d\n", ret);
		goto exit;
	}
	pgprintk("rdma_resolve_addr succeed, device[%s] port_num[%u]\n",
			cb->cm_id->device->name, cb->cm_id->port_num);

	/* Resolve route. */
	ret = rdma_resolve_route(cb->cm_id, RDMA_RESOLVE_TIMEOUT);
	if (ret) {
		printk(KERN_ERR "rdma_resolve_route failed, ret %d\n", ret);
		goto free_cm_id;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_ROUTE_RESOLVED) {
		ret = -STATE_ERROR;
		printk(KERN_ERR "rdma_resolve_route state error, ret %d\n", ret);
		goto exit;
	}
	pgprintk("rdma_resolve_route succeed, cm_id %p\n", cb->cm_id);

	/* Create Protection Domain. */
	cb->pd = ib_alloc_pd(cb->cm_id->device, IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(cb->pd)) {
		ret = PTR_ERR(cb->pd);
		printk(KERN_ERR "ib_alloc_pd failed\n");
		goto free_cm_id;
	}
	pgprintk("ib_alloc_pd succeed, cm_id %p\n", cb->cm_id);

	/* Create send Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->send_cq = ib_create_cq(cb->cm_id->device,
			krdma_send_cq_comp_handler, NULL, cb, &cq_attr);
	if (IS_ERR(cb->send_cq)) {
		ret = PTR_ERR(cb->send_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_pd;
	}

	/* Create recv Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->recv_cq = ib_create_cq(cb->cm_id->device,
			krdma_recv_cq_comp_handler, NULL, cb, &cq_attr);
	if (IS_ERR(cb->recv_cq)) {
		ret = PTR_ERR(cb->recv_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_send_cq;
	}

	pgprintk("ib_create_cq succeed, cm_id %p\n", cb->cm_id);

	/* Create Queue Pair. */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = RDMA_SEND_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_wr = RDMA_RECV_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_send_sge = 1;
	/* Mlx doesn't support inline sends for kernel QPs (yet) */
	qp_init_attr.cap.max_inline_data = 0;
	qp_init_attr.qp_type = IB_QPT_RC;
	qp_init_attr.send_cq = cb->send_cq;
	qp_init_attr.recv_cq = cb->recv_cq;
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ret = rdma_create_qp(cb->cm_id, cb->pd, &qp_init_attr);
	if (ret) {
		printk(KERN_ERR "rdma_create_qp failed, ret %d\n", ret);
		goto free_recv_cq;
	}
	cb->qp = cb->cm_id->qp;
	pgprintk("ib_create_qp succeed, cm_id %p\n", cb->cm_id);
	/* Setup buffers. */
	ret = krdma_setup_buffers(cb);
	if (ret) {
		printk(KERN_ERR "krdma_setup_buffers failed, ret %d\n", ret);
		goto free_buffers;
	}

	ret = krdma_post_recv(cb);
	if (ret) {
		printk(KERN_ERR "krdma_post_recv failed, ret %d\n", ret);
		goto free_buffers;
	}

	/* Connect to remote. */
	memset(&conn_param, 0, sizeof(conn_param));
	/*
	 * The maximum number of times that a data transfer operation
	 * should be retried on the connection when an error occurs. This setting controls
	 * the number of times to retry send, RDMA, and atomic operations when timeouts
	 * occur.
	 */
	conn_param.retry_count = 7;
	/*
	 * The maximum number of times that a send operation from the
	 * remote peer should be retried on a connection after receiving a receiver not
	 * ready (RNR) error.
	 */
	conn_param.rnr_retry_count = 7;

	ret = rdma_connect(cb->cm_id, &conn_param);
	if (ret) {
		printk(KERN_ERR "rdma_connect failed, ret %d\n", ret);
		goto free_buffers;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_CONNECTED) {
		printk(KERN_ERR "%s: wait for KRDMA_CONNECTED state, but get %d\n",
				__func__, cb->state);
		if (cb->state == KRDMA_CONNECT_REJECTED)
			ret = -CLIENT_RETRY;
		else
			ret = -CLIENT_EXIT;

		goto free_buffers;
	}
	pgprintk("krdma_connect_single succeed, cm_id %p\n", cb->cm_id);
	ret = krdma_start_cq_pumps(cb);
	if (ret) {
		printk(KERN_ERR "krdma_start_cq_pumps failed, ret %d\n", ret);
		rdma_disconnect(cb->cm_id);
		goto free_buffers;
	}
	return 0;

free_buffers:
	krdma_free_buffers(cb);
	rdma_destroy_qp(cb->cm_id);
free_recv_cq:
	ib_destroy_cq(cb->recv_cq);
free_send_cq:
	ib_destroy_cq(cb->send_cq);
free_pd:
	ib_dealloc_pd(cb->pd);
free_cm_id:
	rdma_destroy_id(cb->cm_id);
	cb->cm_id = NULL;
exit:
	return ret;
}

int krdma_connect(const char *host, const char *port, struct krdma_cb **conn_cb)
{
	int ret;
	struct krdma_cb *cb;

	if (host == NULL || port == NULL || conn_cb == NULL)
		return -EINVAL;

	ret = krdma_create_cb(&cb, KRDMA_CLIENT_CONN);
	if (ret) {
		printk(KERN_ERR "%s: krdma_create_cb fail, ret %d\n",
				__func__, ret);
		return ret;
	}

retry:
	ret = krdma_connect_single(host, port, cb);
	if (ret == 0) {
		/*
		 * If multiple clients desire to connect to remote servers, only one of
		 * them can call this function. Others must be blocked even if conn_cb
		 * has not been set here. Then double checking whether conn_cb is
		 * non-NULL can ensure the correctness of lazy connection.
		 */
		smp_mb();
		*conn_cb = cb;
		printk("%s: %p krdma_connect succeed\n", __func__, cb);
		return 0;
	}
	if (ret == -CLIENT_RETRY &&
				++cb->retry_count < RDMA_CONNECT_RETRY_MAX) {
		printk(KERN_ERR "%s: krdma_connect_single failed, retry_count %d, " \
				"reconnecting...\n", __func__, cb->retry_count);
		msleep(1000);
		goto retry;
	}
	*conn_cb = NULL;
	printk(KERN_ERR "%s: krdma_connect_single failed, ret: %d\n",
			__func__, ret);
	kfree(cb);
	return ret;
}

int krdma_listen(const char *host, const char *port, struct krdma_cb **listen_cb)
{
	int ret;
	long portdec;
	struct sockaddr_in addr;
	struct krdma_cb *cb;

	if (host == NULL || port == NULL || listen_cb == NULL)
		return -EINVAL;

	ret = krdma_create_cb(listen_cb, KRDMA_LISTEN_CONN);
	if (ret) {
		printk(KERN_ERR "%s: krdma_create_cb fail, ret %d\n",
				 __func__, ret);
		goto exit;
	}
	cb = *listen_cb;

	/* Create cm_id. */
	cb->cm_id = rdma_create_id(&init_net, krdma_cma_event_handler, cb,
			RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cb->cm_id)) {
		ret = PTR_ERR(cb->cm_id);
		printk(KERN_ERR "rdma_create_id error %d\n", ret);
		goto exit;
	}
	printk("created cm_id %p\n", cb->cm_id);

	/* Bind address. */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	BUG_ON(kstrtol(port, 10, &portdec) != 0);
	addr.sin_addr.s_addr = in_aton(host);
	addr.sin_port = htons(portdec);
	ret = rdma_bind_addr(cb->cm_id, (struct sockaddr *)&addr);
	if (ret) {
		printk(KERN_ERR "rdma_bind_addr failed, ret %d\n", ret);
		goto free_cm_id;
	}
	printk("rdma_bind_addr succeed, device[%s] port_num[%u]\n",
			cb->cm_id->device->name, cb->cm_id->port_num);

	ret = rdma_listen(cb->cm_id, 3);
	if (ret) {
		printk(KERN_ERR "rdma_listen failed: %d\n", ret);
		goto free_cm_id;
	}
	printk("rdma_listen start...\n");
	return 0;

free_cm_id:
	rdma_destroy_id(cb->cm_id);
exit:
	return ret;
}

int krdma_accept(struct krdma_cb *listen_cb, struct krdma_cb **accept_cb,
		unsigned long flag)
{
	int ret = 0;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_init_attr;
	struct rdma_conn_param conn_param;
	struct krdma_cb *cb;

	if (listen_cb == NULL) {
		printk(KERN_ERR "%s: null listen_socket\n", __func__);
		ret = -EINVAL;
		goto exit;
	}

	while (list_empty(&listen_cb->ready_conn)) {
		wait_for_completion_interruptible(&listen_cb->cm_done);
		if (listen_cb->state == KRDMA_ERROR) {
			printk(KERN_ERR "%s: rdma_listen cancel\n", __func__);
			ret = -SERVER_EXIT;
			goto exit;
		}
		if (kthread_should_stop()) {
			ret = -SERVER_EXIT;
			goto exit;
		}
	}

	/* Pick a ready connnection. */
	cb = list_first_entry(&listen_cb->ready_conn, struct krdma_cb, list);
	list_del(&cb->list);
	list_add_tail(&cb->list, &listen_cb->active_conn);
	*accept_cb = cb;

	printk("get connection, cm_id %p\n", cb->cm_id);

	/* Create Protection Domain. */
	cb->pd = ib_alloc_pd(cb->cm_id->device, IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(cb->pd)) {
		printk(KERN_ERR "ib_alloc_pd failed\n");
		goto free_conn_cm_id;
	}
	printk("ib_alloc_pd succeed, cm_id %p\n", cb->cm_id);

	/* Create send Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->send_cq = ib_create_cq(cb->cm_id->device,
			krdma_send_cq_comp_handler, NULL, cb, &cq_attr);
	if (IS_ERR(cb->send_cq)) {
		ret = PTR_ERR(cb->send_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_pd;
	}

	/* Create recv Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->recv_cq = ib_create_cq(cb->cm_id->device,
			krdma_recv_cq_comp_handler, NULL, cb, &cq_attr);
	if (IS_ERR(cb->recv_cq)) {
		ret = PTR_ERR(cb->recv_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_send_cq;
	}

	printk("ib_create_cq succeed, cm_id %p\n", cb->cm_id);

	/* Create Queue Pair. */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = RDMA_SEND_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_wr = RDMA_RECV_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_send_sge = 1;
	/* Mlx doesn't support inline sends for kernel QPs (yet) */
	qp_init_attr.cap.max_inline_data = 0;
	qp_init_attr.qp_type = IB_QPT_RC;
	qp_init_attr.send_cq = cb->send_cq;
	qp_init_attr.recv_cq = cb->recv_cq;
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ret = rdma_create_qp(cb->cm_id, cb->pd, &qp_init_attr);
	if (ret) {
		printk(KERN_ERR "rdma_create_qp failed, ret %d\n", ret);
		goto free_recv_cq;
	}
	cb->qp = cb->cm_id->qp;
	printk("ib_create_qp succeed, cm_id %p\n", cb->cm_id);
	/* Setup buffers. */
	ret = krdma_setup_buffers(cb);
	if (ret) {
		printk(KERN_ERR "krdma_setup_buffers failed, ret %d\n", ret);
		goto free_buffers;
	}

	ret = krdma_post_recv(cb);
	if (ret) {
		printk(KERN_ERR "krdma_post_recv failed, ret %d\n", ret);
		goto free_buffers;
	}

	/* Accept */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.retry_count = conn_param.rnr_retry_count = 7;

	ret = rdma_accept(cb->cm_id, &conn_param);
	if (ret) {
		printk(KERN_ERR "rdma_accept error: %d\n", ret);
		goto free_buffers;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_CONNECTED) {
		printk(KERN_ERR "%s: wait for KRDMA_CONNECTED state, but get %d\n",
				 __func__, cb->state);
		goto free_buffers;
	}

	printk("new connection accepted with the following attributes:\n"
		"local: %pI4:%d\nremote: %pI4:%d\n",
		&((struct sockaddr_in *)&cb->cm_id->route.addr.src_addr)->sin_addr.s_addr,
		ntohs(((struct sockaddr_in *)&cb->cm_id->route.addr.src_addr)->sin_port),
		&((struct sockaddr_in *)&cb->cm_id->route.addr.dst_addr)->sin_addr.s_addr,
		ntohs(((struct sockaddr_in *)&cb->cm_id->route.addr.dst_addr)->sin_port));
	ret = krdma_start_cq_pumps(cb);
	if (ret) {
		printk(KERN_ERR "krdma_start_cq_pumps failed, ret %d\n", ret);
		rdma_disconnect(cb->cm_id);
		goto free_buffers;
	}

	return 0;

free_buffers:
	krdma_free_buffers(cb);
	rdma_destroy_qp(cb->cm_id);
free_recv_cq:
	ib_destroy_cq(cb->recv_cq);
free_send_cq:
	ib_destroy_cq(cb->send_cq);
free_pd:
	ib_dealloc_pd(cb->pd);
free_conn_cm_id:
	rdma_destroy_id(cb->cm_id);
	cb->cm_id = NULL;
	list_del(&cb->list);
	kfree(cb);
	*accept_cb = NULL;
exit:
	return ret;
}

int krdma_release(struct krdma_cb *cb)
{
	struct krdma_cb *entry = NULL;
	struct krdma_cb *this = NULL;

	if (cb == NULL)
		return -EINVAL;

	if (cb->role == KRDMA_LISTEN_CONN) {
		list_for_each_entry_safe(entry, this, &cb->ready_conn, list) {
			list_del(&entry->list);
			krdma_release(entry);
		}
		/*
		 * Accepted connections are owned by dsm_conn and are released
		 * from kvm_dsm_threadfn().  active_conn is only bookkeeping for
		 * the listener, so walking it here would double-release them.
		 */
	}

	if (!cb->cm_id) {
		kfree(cb);
		return 0;
	}

	if (cb->qp) {
		mutex_lock(&cb->slock);
		if (cb->state == KRDMA_CONNECTED)
			WRITE_ONCE(cb->state, KRDMA_CLOSING);
		mutex_unlock(&cb->slock);
		krdma_wake_all_message_waiters(cb);
		wake_up_all(&cb->recv_cq_wait);
		wake_up_all(&cb->send_cq_wait);
		krdma_stop_cq_pumps(cb);
	}
	rdma_disconnect(cb->cm_id);
	if (cb->cm_id->qp)
		rdma_destroy_qp(cb->cm_id);

	krdma_free_buffers(cb);
	if (cb->send_cq)
		ib_destroy_cq(cb->send_cq);
	if (cb->recv_cq)
		ib_destroy_cq(cb->recv_cq);

	if (cb->pd)
		ib_dealloc_pd(cb->pd);

	rdma_destroy_id(cb->cm_id);
	cb->cm_id = NULL;

	kfree(cb);

	return 0;
}

static int krdma_post_recv(struct krdma_cb *cb);

int krdma_shutdown(struct krdma_cb *cb)
{
	if (!cb || !cb->cm_id || !cb->qp)
		return -EINVAL;

	mutex_lock(&cb->slock);
	WRITE_ONCE(cb->state, KRDMA_CLOSING);
	mutex_unlock(&cb->slock);
	krdma_wake_all_message_waiters(cb);
	wake_up_all(&cb->recv_cq_wait);
	wake_up_all(&cb->send_cq_wait);
	krdma_stop_cq_pumps(cb);
	rdma_disconnect(cb->cm_id);
	complete_all(&cb->cm_done);

	return 0;
}

/* Poll one receive completion.  Only the per-QP RX pump calls this. */
static int krdma_poll_recv(struct krdma_cb *cb, imm_t *imm, size_t *length)
{
	struct ib_wc wc;
	int ret;

	switch (READ_ONCE(cb->state)) {
	case KRDMA_ERROR:
		return -STATE_ERROR;
	case KRDMA_CLOSING:
	case KRDMA_CLOSED:
	case KRDMA_DISCONNECTED:
		return -EPIPE;
	default:
		break;
	}

	ret = ib_poll_cq(cb->recv_cq, 1, &wc);
	if (ret <= 0)
		return ret ? ret : -EAGAIN;
	if (wc.status != IB_WC_SUCCESS) {
		printk(KERN_ERR "%s: wc.status: %s wr.id %llu\n", __func__,
		       ib_wc_status_msg(wc.status), wc.wr_id);
		return wc.status == IB_WC_WR_FLUSH_ERR ? -EPIPE : -STATE_ERROR;
	}
	if (wc.opcode != IB_WC_RECV || !(wc.wc_flags & IB_WC_WITH_IMM) ||
	    wc.wr_id >= RDMA_RECV_BUF_SIZE) {
		printk(KERN_ERR "%s: invalid receive completion opcode %u flags 0x%x wr.id %llu\n",
		       __func__, wc.opcode, wc.wc_flags, wc.wr_id);
		return -STATE_ERROR;
	}

	*imm = ntohl(wc.ex.imm_data);
	*length = wc.byte_len;
	return wc.wr_id;
}

/* Poll one send completion.  Only the per-QP TX pump calls this. */
static int krdma_poll_send_cq(struct krdma_cb *cb)
{
	krdma_send_trans_t *trans;
	struct ib_wc wc;
	bool notify = false;
	bool reclaim = false;
	int status;
	int ret;

	ret = ib_poll_cq(cb->send_cq, 1, &wc);
	if (ret <= 0)
		return ret ? ret : -EAGAIN;
	if (wc.wr_id >= RDMA_SEND_BUF_SIZE) {
		printk(KERN_ERR "%s: invalid send completion wr.id %llu\n",
		       __func__, wc.wr_id);
		return -STATE_ERROR;
	}

	trans = &cb->send_trans_buf[wc.wr_id];
	if (unlikely(READ_ONCE(trans->state) != POSTED)) {
		printk(KERN_ERR "%s: completion for inactive send slot %llu\n",
		       __func__, wc.wr_id);
		return -STATE_ERROR;
	}

	if (wc.status != IB_WC_SUCCESS) {
		printk(KERN_ERR "%s: wc.status: %s wr.id %llu\n", __func__,
		       ib_wc_status_msg(wc.status), wc.wr_id);
		status = wc.status == IB_WC_WR_FLUSH_ERR ? -EPIPE : -STATE_ERROR;
	} else if (wc.opcode != IB_WC_SEND && wc.opcode != IB_WC_RDMA_WRITE) {
		printk(KERN_ERR "%s: invalid send completion opcode %u wr.id %llu\n",
		       __func__, wc.opcode, wc.wr_id);
		status = -STATE_ERROR;
	} else {
		status = 0;
	}
	mutex_lock(&cb->slock);
	if (trans->state == POSTED) {
		if (trans->auto_reclaim) {
			trans->completion_status = status;
			trans->auto_reclaim = false;
			trans->state = INVALID;
			reclaim = true;
		} else if (cmpxchg(&trans->completion_status, -EINPROGRESS,
					  status) == -EINPROGRESS) {
			notify = true;
		}
	}
	mutex_unlock(&cb->slock);
	if (reclaim)
		up(&cb->send_slots);
	else if (notify)
		complete(&trans->done);
	return status;
}

static void krdma_fail_pending_sends(struct krdma_cb *cb, int status)
{
	unsigned int i;

	cmpxchg(&cb->state, KRDMA_CONNECTED, KRDMA_ERROR);
	mutex_lock(&cb->slock);
	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		krdma_send_trans_t *trans = &cb->send_trans_buf[i];

		if (trans->state != POSTED)
			continue;
		if (trans->auto_reclaim) {
			trans->completion_status = status;
			trans->auto_reclaim = false;
			trans->state = INVALID;
			up(&cb->send_slots);
		} else if (cmpxchg(&trans->completion_status, -EINPROGRESS,
					  status) == -EINPROGRESS) {
			complete(&trans->done);
		}
	}
	mutex_unlock(&cb->slock);
}

static int krdma_wait_send(struct krdma_cb *cb, krdma_send_trans_t *trans)
{
	for (;;) {
		if (wait_for_completion_timeout(&trans->done, 5 * HZ))
			return READ_ONCE(trans->completion_status);
		printk_ratelimited(KERN_ERR
				   "cb %p waiting for TX completion too long\n", cb);
	}
}

static struct krdma_recv_msg *krdma_find_recv_msg(struct krdma_cb *cb,
		uint32_t txid)
{
	struct krdma_recv_msg *msg = NULL;
	unsigned long flags;

	spin_lock_irqsave(&cb->recv_queue_lock, flags);
	list_for_each_entry(msg, &cb->recv_msg_queue, list) {
		if (txid == DSM_TXID_ANY || msg->tx_add.txid == txid) {
			list_del(&msg->list);
			spin_unlock_irqrestore(&cb->recv_queue_lock, flags);
			return msg;
		}
	}
	spin_unlock_irqrestore(&cb->recv_queue_lock, flags);
	return NULL;
}

static int search_empty_send_buf(struct krdma_cb *cb, krdma_send_trans_t **trans)
{
	unsigned int i;

	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		unsigned int slot = (cb->next_send_slot + i) % RDMA_SEND_BUF_SIZE;

		if (cb->send_trans_buf[slot].state == INVALID) {
			*trans = &cb->send_trans_buf[slot];
			cb->next_send_slot = (slot + 1) % RDMA_SEND_BUF_SIZE;
			return slot;
		}
	}
	return -ENOSPC;
}

static int search_empty_recv_buf(struct krdma_cb *cb, krdma_recv_trans_t **trans)
{
	int i;

	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].state == INVALID) {
			*trans = &cb->recv_trans_buf[i];
			return i;
		}
	}
	return -ENOENT;
}

static void build_posted_send_trans(krdma_send_trans_t *trans, bool auto_reclaim)
{
	reinit_completion(&trans->done);
	trans->completion_status = -EINPROGRESS;
	trans->auto_reclaim = auto_reclaim;
	trans->state = POSTED;
}

static void build_posted_recv_trans(krdma_recv_trans_t *trans)
{
	trans->state = POSTED;
}
/*
 * Content + additional(without first 32-bit data, which is store in imm)
 *
 * imm:
 * |<---1st part of tx_add, i.e., the first 32 bit--->|
 * payload: receive DMA buffer:
 * |<------------------------sz=wc.byte_len------------------------------->|
 * |<----real data (sz=ret_val of send/recv)--->|<---2nd part of tx_add--->|
 */
static int build_krdma_recv_output(struct krdma_recv_msg *msg, char *buffer,
		size_t buffer_len, tx_add_t *tx_add)
{
	int ret = msg->length;

	if (msg->length > buffer_len) {
		printk(KERN_ERR
		       "%s: krdma payload length %zu exceeds caller buffer %zu\n",
		       __func__, msg->length, buffer_len);
		ret = -EMSGSIZE;
		goto out;
	}

	*tx_add = msg->tx_add;
	memcpy(buffer, msg->data, msg->length);
out:
	kvfree(msg);
	return ret;
}

static int krdma_repost_recv_slot(struct krdma_cb *cb, unsigned int slot)
{
	krdma_recv_trans_t *trans = &cb->recv_trans_buf[slot];
	const struct ib_recv_wr *bad_wr;
	int ret;

	build_posted_recv_trans(trans);
	ret = ib_post_recv(cb->qp, &trans->rq_wr, &bad_wr);
	if (ret) {
		trans->state = INVALID;
		printk(KERN_ERR "%s: ib_post_recv error, ret %d\n",
		       __func__, ret);
		return -STATE_ERROR;
	}
	return 0;
}

/* Copy a CQ-completed DMA buffer into the independent software queue. */
static int krdma_queue_recv_completion(struct krdma_cb *cb, unsigned int slot,
		imm_t imm, size_t length)
{
	krdma_recv_trans_t *trans = &cb->recv_trans_buf[slot];
	const size_t tx_tail_len = sizeof(tx_add_t) - sizeof(imm_t);
	struct krdma_recv_msg *msg = NULL;
	unsigned long flags;
	size_t payload_len;
	uint32_t txid;
	int ret;

	if (unlikely(trans->state != POSTED))
		return -STATE_ERROR;
	if (unlikely(length < tx_tail_len || length > RDMA_RECV_BUF_LEN)) {
		printk(KERN_ERR "%s: invalid krdma message length %zu\n",
		       __func__, length);
		ret = -EINVAL;
		goto repost;
	}

	payload_len = length - tx_tail_len;
	msg = kvmalloc(sizeof(*msg) + payload_len, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto repost;
	}
	msg->length = payload_len;
	memcpy(&msg->tx_add, &imm, sizeof(imm));
	memcpy((char *)&msg->tx_add + sizeof(imm),
	       trans->recv_buf + payload_len, tx_tail_len);
	memcpy(msg->data, trans->recv_buf, payload_len);
	txid = msg->tx_add.txid;
	ret = 0;

repost:
	/* The HCA may reuse the DMA buffer as soon as this succeeds. */
	trans->state = INVALID;
	if (krdma_repost_recv_slot(cb, slot) < 0) {
		if (!ret)
			kvfree(msg);
		return -STATE_ERROR;
	}
	if (ret)
		return ret;

	spin_lock_irqsave(&cb->recv_queue_lock, flags);
	list_add_tail(&msg->list, &cb->recv_msg_queue);
	atomic64_inc(&cb->recv_seq);
	spin_unlock_irqrestore(&cb->recv_queue_lock, flags);
	krdma_wake_message_waiters(cb, txid);
	return ret;
}

static int krdma_post_recv(struct krdma_cb *cb)
{
	int ret = 0;
	int slot;
	krdma_recv_trans_t *recv_trans;

	while ((slot = search_empty_recv_buf(cb, &recv_trans)) != -ENOENT) {
		ret = krdma_repost_recv_slot(cb, slot);
		if (ret)
			return ret;
	}

	return ret;
}

/* Drain at most one RQ's worth so reposting cannot starve message consumers. */
static int krdma_drain_recv_cq(struct krdma_cb *cb)
{
	unsigned int count;

	for (count = 0; count < RDMA_RECV_QUEUE_DEPTH; count++) {
		size_t length;
		imm_t imm;
		int slot;
		int ret;

		slot = krdma_poll_recv(cb, &imm, &length);
		if (slot == -EAGAIN)
			return count;
		if (slot < 0)
			return slot;
		ret = krdma_queue_recv_completion(cb, slot, imm, length);
		if (ret < 0)
			return ret;
	}
	return count;
}

static int krdma_drain_send_cq(struct krdma_cb *cb)
{
	unsigned int count;

	for (count = 0; count < RDMA_SEND_QUEUE_DEPTH; count++) {
		int ret = krdma_poll_send_cq(cb);

		if (ret == -EAGAIN)
			return count;
		if (ret < 0)
			return ret;
	}
	return count;
}

#define KRDMA_CQ_NOTIFY_FLAGS \
	(IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS)
#define KRDMA_CQ_ACTIVE_EMPTY_POLLS 128

static void krdma_set_io_error(struct krdma_cb *cb, int error)
{
	WRITE_ONCE(cb->recv_error, error);
	cmpxchg(&cb->state, KRDMA_CONNECTED, KRDMA_ERROR);
	krdma_wake_all_message_waiters(cb);
	wake_up_all(&cb->recv_cq_wait);
	wake_up_all(&cb->send_cq_wait);
}

/*
 * cb owns the task_struct pointer until krdma_stop_cq_pumps() consumes it.
 * A pump must therefore not return merely because the QP disconnected or an
 * I/O error occurred: after a natural kthread exit that pointer can become
 * stale before DSM teardown reaches kthread_stop().
 */
static void krdma_wait_for_pump_stop(wait_queue_head_t *waitq)
{
	wait_event(*waitq, kthread_should_stop());
}

static int krdma_rx_pump(void *data)
{
	struct krdma_cb *cb = data;
	s64 seq;
	unsigned int empty_polls = 0;
	int ret;

	while (!kthread_should_stop()) {
		if (READ_ONCE(cb->state) != KRDMA_CONNECTED)
			break;

		ret = krdma_drain_recv_cq(cb);
		if (ret < 0) {
			krdma_set_io_error(cb, ret);
			krdma_fail_pending_sends(cb, ret);
			break;
		}
		if (ret == RDMA_RECV_QUEUE_DEPTH) {
			empty_polls = 0;
			cond_resched();
			continue;
		}
		if (ret) {
			empty_polls = 0;
			continue;
		}
		if (empty_polls++ < KRDMA_CQ_ACTIVE_EMPTY_POLLS) {
			cpu_relax();
			continue;
		}

		seq = atomic64_read(&cb->recv_cq_seq);
		ret = ib_req_notify_cq(cb->recv_cq, KRDMA_CQ_NOTIFY_FLAGS);
		if (ret < 0) {
			krdma_set_io_error(cb, ret);
			krdma_fail_pending_sends(cb, ret);
			break;
		}
		if (ret > 0) {
			empty_polls = 0;
			continue;
		}

		wait_event(cb->recv_cq_wait,
			atomic64_read(&cb->recv_cq_seq) != seq ||
			READ_ONCE(cb->state) != KRDMA_CONNECTED ||
			kthread_should_stop());
		empty_polls = 0;
	}

	krdma_wake_all_message_waiters(cb);
	krdma_wait_for_pump_stop(&cb->recv_cq_wait);
	return 0;
}

static int krdma_tx_pump(void *data)
{
	struct krdma_cb *cb = data;
	s64 seq;
	unsigned int empty_polls = 0;
	int ret;

	while (!kthread_should_stop()) {
		if (READ_ONCE(cb->state) != KRDMA_CONNECTED)
			break;

		ret = krdma_drain_send_cq(cb);
		if (ret < 0) {
			krdma_set_io_error(cb, ret);
			krdma_fail_pending_sends(cb, ret);
			break;
		}
		if (ret == RDMA_SEND_QUEUE_DEPTH) {
			empty_polls = 0;
			cond_resched();
			continue;
		}
		if (ret) {
			empty_polls = 0;
			continue;
		}
		if (empty_polls++ < KRDMA_CQ_ACTIVE_EMPTY_POLLS) {
			cpu_relax();
			continue;
		}

		seq = atomic64_read(&cb->send_cq_seq);
		ret = ib_req_notify_cq(cb->send_cq, KRDMA_CQ_NOTIFY_FLAGS);
		if (ret < 0) {
			krdma_set_io_error(cb, ret);
			krdma_fail_pending_sends(cb, ret);
			break;
		}
		if (ret > 0) {
			empty_polls = 0;
			continue;
		}

		wait_event(cb->send_cq_wait,
			atomic64_read(&cb->send_cq_seq) != seq ||
			READ_ONCE(cb->state) != KRDMA_CONNECTED ||
			kthread_should_stop());
		empty_polls = 0;
	}

	ret = READ_ONCE(cb->recv_error);
	if (!ret)
		ret = READ_ONCE(cb->state) == KRDMA_ERROR ?
			-STATE_ERROR : -EPIPE;
	krdma_fail_pending_sends(cb, ret);
	krdma_wait_for_pump_stop(&cb->send_cq_wait);
	return 0;
}

static int krdma_start_cq_pumps(struct krdma_cb *cb)
{
	struct task_struct *rx_task;
	struct task_struct *tx_task;

	if (WARN_ON(cb->rx_task || cb->tx_task))
		return -EBUSY;

	WRITE_ONCE(cb->recv_error, 0);
	rx_task = kthread_create(krdma_rx_pump, cb, "krdma-rx/%u",
				 cb->qp->qp_num);
	if (IS_ERR(rx_task))
		return PTR_ERR(rx_task);
	tx_task = kthread_create(krdma_tx_pump, cb, "krdma-tx/%u",
				 cb->qp->qp_num);
	if (IS_ERR(tx_task)) {
		kthread_stop(rx_task);
		return PTR_ERR(tx_task);
	}

	WRITE_ONCE(cb->rx_task, rx_task);
	WRITE_ONCE(cb->tx_task, tx_task);
	wake_up_process(rx_task);
	wake_up_process(tx_task);
	return 0;
}

static void krdma_stop_cq_pumps(struct krdma_cb *cb)
{
	struct task_struct *rx_task;
	struct task_struct *tx_task;

	/* Keep concurrent DSM shutdown paths from splitting RX/TX ownership. */
	mutex_lock(&cb->cq_pump_lock);
	rx_task = xchg(&cb->rx_task, NULL);
	tx_task = xchg(&cb->tx_task, NULL);

	wake_up_all(&cb->recv_cq_wait);
	wake_up_all(&cb->send_cq_wait);
	if (rx_task)
		kthread_stop(rx_task);
	if (tx_task)
		kthread_stop(tx_task);
	mutex_unlock(&cb->cq_pump_lock);
}

/*
 * @param tx_add the txid field is an input selector.  DSM_TXID_ANY accepts
 * the oldest software-queued message; a concrete txid waits for that response.
 */
int krdma_receive(struct krdma_cb *cb, char *buffer, size_t buffer_len, unsigned long flag,
		tx_add_t *tx_add)
{
	struct krdma_recv_msg *msg;
	wait_queue_head_t *waitq;
	s64 seq;
	int ret;
	uint32_t txid;

	BUILD_BUG_ON(sizeof(tx_add_t) < sizeof(imm_t));

	if (!cb || !buffer || !tx_add)
		return -EINVAL;
	txid = tx_add->txid;
	waitq = krdma_recv_tx_waitq(cb, txid);

	for (;;) {
		if (krdma_current_should_stop())
			return -ERESTARTSYS;

		/* Sample before searching so an enqueue cannot race with sleeping. */
		seq = atomic64_read(&cb->recv_seq);
		msg = krdma_find_recv_msg(cb, txid);
		if (msg)
			return build_krdma_recv_output(msg, buffer, buffer_len,
						       tx_add);

		if (READ_ONCE(cb->state) != KRDMA_CONNECTED) {
			ret = READ_ONCE(cb->recv_error);
			return ret ? ret : -EPIPE;
		}
		if (flag & SOCK_NONBLOCK)
			return -EAGAIN;

		if (txid == DSM_TXID_ANY)
			ret = wait_event_interruptible_exclusive(
					cb->recv_any_wait,
					atomic64_read(&cb->recv_seq) != seq ||
					READ_ONCE(cb->state) != KRDMA_CONNECTED ||
					krdma_current_should_stop());
		else
			ret = wait_event_interruptible(
					*waitq,
					atomic64_read(&cb->recv_seq) != seq ||
					READ_ONCE(cb->state) != KRDMA_CONNECTED ||
					krdma_current_should_stop());
		if (ret)
			return ret;
	}
}

/* TODO: make krdma_send unsigned when flag is SOCK_UNBLOCKED. */
int krdma_send(struct krdma_cb *cb, const char *buffer, size_t length,
		unsigned long flag, const tx_add_t *tx_add)
{
	int ret;
	const struct ib_send_wr *bad_wr;
	imm_t imm;
	krdma_send_trans_t *send_trans;
	uint32_t txid;
	int slot;

	if (!cb || !tx_add || (!buffer && length))
		return -EINVAL;
	txid = tx_add->txid;
	if (length > RDMA_SEND_BUF_LEN - (sizeof(tx_add_t) - sizeof(imm_t)))
		return -EMSGSIZE;
	if (READ_ONCE(cb->state) != KRDMA_CONNECTED)
		return -EPIPE;
	if (down_interruptible(&cb->send_slots))
		return -ERESTARTSYS;

	mutex_lock(&cb->slock);
	if (READ_ONCE(cb->state) != KRDMA_CONNECTED) {
		mutex_unlock(&cb->slock);
		up(&cb->send_slots);
		return -EPIPE;
	}

	slot = search_empty_send_buf(cb, &send_trans);
	if (unlikely(slot < 0)) {
		mutex_unlock(&cb->slock);
		up(&cb->send_slots);
		return slot;
	}
	build_posted_send_trans(send_trans, true);

	cb->send_trans_buf[slot].send_sge.length = length + (sizeof(tx_add_t) - sizeof(imm_t));
	/*
	 * Use the ring slot as wr_id.  txid is 32-bit and can legally exceed
	 * INT_MAX. DSM transaction matching still uses the txid carried in
	 * tx_add.
	 */
	cb->send_trans_buf[slot].sq_wr.wr_id = slot;
	/*
	 * First 32 bits of tx_add ride in immediate data; the remaining bytes
	 * are appended to the payload.  This keeps one RDMA Send as one DSM
	 * message while preserving the existing ktcp tx_add contract.
	 */
	memcpy(&imm, tx_add, sizeof(imm));
	cb->send_trans_buf[slot].sq_wr.ex.imm_data = htonl(imm);
	memcpy(cb->send_trans_buf[slot].send_buf + length, (((const char *)tx_add) + sizeof(imm_t)),
			sizeof(tx_add_t) - sizeof(imm_t));
	memcpy(cb->send_trans_buf[slot].send_buf, buffer, length);

	ret = ib_post_send(cb->qp, &cb->send_trans_buf[slot].sq_wr, &bad_wr);
	if (ret) {
		send_trans->state = INVALID;
		mutex_unlock(&cb->slock);
		up(&cb->send_slots);
		printk(KERN_ERR "ib_post_send failed, ret %d\n", ret);
		return ret;
	}
	mutex_unlock(&cb->slock);

	/* The TX CQ pump owns and reclaims this immutable slot. */

	pgprintk("%s: cb %p sent 0x%x\n", __func__, cb, txid);

	return length;
}

/*
 * Copy into an already DMA-coherent send slot, then issue a signalled RC
 * RDMA Write.  The caller posts its Send completion ACK only after this
 * function returns, preserving Write-before-ACK ordering on the QP.
 */
int krdma_write(struct krdma_cb *cb, const char *buffer, size_t length,
		u64 remote_addr, u32 rkey)
{
	struct ib_rdma_wr wr = {};
	const struct ib_send_wr *bad_wr;
	krdma_send_trans_t *trans;
	int slot, ret;

	if (!cb || !buffer || !length || length > RDMA_SEND_BUF_LEN)
		return -EINVAL;
	if (READ_ONCE(cb->state) != KRDMA_CONNECTED)
		return -EPIPE;
	if (down_interruptible(&cb->send_slots))
		return -ERESTARTSYS;

	mutex_lock(&cb->slock);
	if (READ_ONCE(cb->state) != KRDMA_CONNECTED) {
		mutex_unlock(&cb->slock);
		up(&cb->send_slots);
		return -EPIPE;
	}
	slot = search_empty_send_buf(cb, &trans);
	if (unlikely(slot < 0)) {
		mutex_unlock(&cb->slock);
		up(&cb->send_slots);
		return slot;
	}
	build_posted_send_trans(trans, false);
	memcpy(trans->send_buf, buffer, length);
	trans->send_sge.length = length;
	wr.wr.wr_id = slot;
	wr.wr.sg_list = &trans->send_sge;
	wr.wr.num_sge = 1;
	wr.wr.opcode = IB_WR_RDMA_WRITE;
	wr.wr.send_flags = IB_SEND_SIGNALED;
	wr.remote_addr = remote_addr;
	wr.rkey = rkey;

	ret = ib_post_send(cb->qp, &wr.wr, &bad_wr);
	if (ret) {
		trans->state = INVALID;
		mutex_unlock(&cb->slock);
		up(&cb->send_slots);
		return ret;
	}
	mutex_unlock(&cb->slock);

	ret = krdma_wait_send(cb, trans);
	mutex_lock(&cb->slock);
	trans->state = INVALID;
	mutex_unlock(&cb->slock);
	up(&cb->send_slots);
	return ret < 0 ? ret : length;
}
