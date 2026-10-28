/*
 * Support KVM software distributed memory (Ivy Protocol)
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 *
 * Authors:
 *   Chen Yubin <i@binss.me>
 *   Ding Zhuocheng <tcbbdddd@gmail.com>
 *   Zhang Jin <437629012@qq.com>
 *   Xiong Tianlei <qmyyxtl@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

/************************
 **DEADLOCK DELENDA EST**
 ************************/

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm-util.h"
#include "ivy.h"

#include <linux/kthread.h>
#include <linux/mmu_context.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>

static uint64_t dsm_page_fault_counter = 0;
static u64 total_time=0;
static uint64_t write_req_counter = 0;
static uint64_t read_req_counter = 0;
static atomic_t gvm_ivy_pf_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_ivy_req_log_count[DSM_MAX_INSTANCES];

static inline bool dsm_current_should_stop(void)
{
	return (current->flags & PF_KTHREAD) && kthread_should_stop();
}

static inline bool dsm_network_is_down(int ret)
{
	return ret == -ECONNRESET || ret == -EPIPE || ret == -ESHUTDOWN ||
	       ret == -ENOTCONN || ret == -ECONNREFUSED;
}

static void kvm_dsm_mark_stopped(struct kvm *kvm, int peer, int ret)
{
	if (!READ_ONCE(kvm->arch.dsm_stopped))
		printk_ratelimited(KERN_WARNING
		       "kvm-dsm: node-%u stopping DSM after peer-%d network error %d\n",
		       READ_ONCE(kvm->arch.dsm_id), peer, ret);

	WRITE_ONCE(kvm->arch.dsm_stopped, true);
	smp_mb();
}

static unsigned int gvm_ivy_log_node(struct kvm *kvm)
{
	u32 node = READ_ONCE(kvm->arch.dsm_id);

	return node < DSM_MAX_INSTANCES ? node : 0;
}

enum kvm_dsm_request_type {
	DSM_REQ_INVALIDATE,
	DSM_REQ_READ,
	DSM_REQ_WRITE,
};
static char* req_desc[3] = {"INV", "READ", "WRITE"};
static copyset_t dsm_dummy_copyset;

static inline copyset_t *dsm_get_copyset(
		struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return &dsm_dummy_copyset;

	return slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].copyset;
}

static inline void dsm_add_to_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn, int id)
{
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	set_bit(id, slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].copyset);
}

static inline void dsm_clear_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	bitmap_zero(dsm_get_copyset(slot, vfn), DSM_MAX_INSTANCES);
}

/*
 * @requester:	the requester (real message sender or manager or probOwner) of
 * this invalidate request.
 * @msg_sender: the real message sender.
 */
struct dsm_request {
	unsigned char requester;
	unsigned char msg_sender;
	gfn_t gfn;
	unsigned char req_type;
	bool is_smm;

	/*
	 * If version of two pages in different nodes are the same, the contents
	 * are the same.
	 */
	uint16_t version;
};

struct dsm_response {
	copyset_t inv_copyset;
	uint16_t version;
};

/*
 * @msg_sender: the message may be delegated by manager (or other probOwners)
 * (kvm->arch.dsm_id) and real sender can be appointed here.
 * @inv_copyset: if req_type = DSM_REQ_WRITE, the requester becomes owner and has duty
 * to broadcast invalidate.
 * @return: the length of response
 */
static int kvm_dsm_fetch(struct kvm *kvm, uint16_t dest_id, bool from_server,
		const struct dsm_request *req, void *data, struct dsm_response *resp)
{
	kconnection_t **conn_sock;
	int ret;
	tx_add_t tx_add = {
		.txid = generate_txid(kvm, dest_id),
	};
	int retry_cnt = 0;

	if (READ_ONCE(kvm->arch.dsm_stopped))
		return -EINVAL;
	if (!kvm->arch.dsm_conn_socks)
		return -EINVAL;

	if (!from_server)
		conn_sock = &kvm->arch.dsm_conn_socks[dest_id];
	else {
		conn_sock = &kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + dest_id];
	}

	/*
	 * Mutiple vCPUs/servers may connect to a remote node simultaneously.
	 */
	if (*conn_sock == NULL) {
		mutex_lock(&kvm->arch.conn_init_lock);
		if (*conn_sock == NULL) {
			ret = kvm_dsm_connect(kvm, dest_id, conn_sock);
			if (ret < 0) {
				mutex_unlock(&kvm->arch.conn_init_lock);
				return ret;
			}
		}
		mutex_unlock(&kvm->arch.conn_init_lock);
	}

	dsm_debug_v("kvm[%d] sent request[0x%x] to kvm[%d] req_type[%s] gfn[0x%llx,%d]",
			kvm->arch.dsm_id, tx_add.txid, dest_id, req_desc[req->req_type],
			req->gfn, req->is_smm);
	// printk("kvm[%d] sent request[0x%x] to kvm[%d] req_type[%s] gfn[0x%llx,%d]",
		// kvm->arch.dsm_id, tx_add.txid, dest_id, req_desc[req->req_type],
		// req->gfn, req->is_smm);
//
	ret = network_ops.send(*conn_sock, (const char *)req, sizeof(struct
				dsm_request), 0, &tx_add);
	if (ret < 0) {
		dsm_debug_v("send request to kvm %d failed\n", dest_id);
		if (dsm_network_is_down(ret))
			kvm_dsm_mark_stopped(kvm, dest_id, ret);
		goto done;
	}

	retry_cnt = 0;
	if (req->req_type == DSM_REQ_INVALIDATE) {
		char *ack_buf;

		/*
		 * The invalidate acknowledgement is one byte, but ktcp_receive()
		 * has no destination-size argument and may copy a complete framed
		 * payload before returning its length.  Never receive directly into
		 * the caller's small stack object.
		 */
		ack_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!ack_buf)
			return -ENOMEM;

		ret = network_ops.receive(*conn_sock, ack_buf, PAGE_SIZE, 0, &tx_add);
		if (ret == 1 && data)
			*(char *)data = ack_buf[0];
		else if (ret > 0)
			printk_ratelimited(KERN_ERR
			       "GVM DSM invalid ack length: node=%u dest=%u len=%d txid=0x%x\n",
			       READ_ONCE(kvm->arch.dsm_id), dest_id, ret, tx_add.txid);
		kfree(ack_buf);
	}
	else {
retry:
		ret = network_ops.receive(*conn_sock, data, PAGE_SIZE, SOCK_NONBLOCK, &tx_add);
		if (ret == -EAGAIN) {
			retry_cnt++;
				if (fatal_signal_pending(current) ||
				    dsm_current_should_stop() ||
				    READ_ONCE(kvm->arch.dsm_stopped))
					return -ERESTARTSYS;
			if (retry_cnt > 100000) {
				printk_ratelimited(KERN_WARNING "GVM DSM fetch_wait: node=%u dest=%u from_server=%u txid=0x%x type=%s gfn=0x%llx smm=%u retry=%d\n",
						   READ_ONCE(kvm->arch.dsm_id),
						   dest_id, from_server,
						   tx_add.txid,
						   req_desc[req->req_type],
						   (unsigned long long)req->gfn,
						   req->is_smm, retry_cnt);
				retry_cnt = 0;
			}
			cond_resched();
			usleep_range(1, 10);
			goto retry;
		}
			resp->inv_copyset = tx_add.inv_copyset;
			resp->version = tx_add.version;
#ifndef KVM_DSM_DIFF
			if (ret > 0 && ret != PAGE_SIZE) {
				printk_ratelimited(KERN_ERR
				       "GVM DSM fetch: invalid page response node=%u dest=%u type=%s gfn=0x%llx len=%d txid=0x%x\n",
				       READ_ONCE(kvm->arch.dsm_id), dest_id,
				       req_desc[req->req_type],
				       (unsigned long long)req->gfn, ret, tx_add.txid);
				ret = -EPROTO;
			}
#endif
		}
	if (ret < 0)
	{
		dsm_debug_v("receive response from kvm %d failed\n", dest_id);
		if (dsm_network_is_down(ret))
			kvm_dsm_mark_stopped(kvm, dest_id, ret);
		goto done;
	}

done:
	if (ret > 0 && ret <= PAGE_SIZE) {
		dsm_debug_v("kvm[%d] received response[0x%x] from kvm[%d] req_type[%s] gfn[0x%llx,%d] hash: 0x%x, ret=%d",
			kvm->arch.dsm_id, tx_add.txid, dest_id, req_desc[req->req_type],
			req->gfn, req->is_smm, jhash(data, ret, JHASH_INITVAL), ret);
		if (ret >= 8) {
			const u8 *data_u8 = data;
			dsm_debug_v("data content: %02x %02x %02x %02x %02x %02x %02x %02x\n",
				    data_u8[0], data_u8[1], data_u8[2], data_u8[3],
				    data_u8[4], data_u8[5], data_u8[6], data_u8[7]);
		}
	}
	return ret;
}

/*
 * kvm_dsm_invalidate - issued by owner of a page to invalidate all of its copies
 * @cpyset: given copyset. NULL means using its own copyset.
 */
static int kvm_dsm_invalidate(struct kvm *kvm, gfn_t gfn, bool is_smm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn, copyset_t *cpyset, int req)
{
	int holder;
	int ret = 0;
	char r = 1;
	copyset_t *copyset;
	struct dsm_response resp;

	copyset = cpyset ? cpyset : dsm_get_copyset(slot, vfn);

	/*
	 * A given copyset has been properly tailored so that no redundant INVs will
	 * be sent to invalid nodes (nodes in the call-chain).
	 */
	for_each_set_bit(holder, copyset, DSM_MAX_INSTANCES) {
		struct dsm_request req = {
			.req_type = DSM_REQ_INVALIDATE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
		if (kvm->arch.dsm_id == holder)
			continue;
		/* Santiy check on copyset consistency. */
		BUG_ON(holder >= kvm->arch.cluster_iplist_len);

		ret = kvm_dsm_fetch(kvm, holder, false, &req, &r, &resp);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int dsm_handle_invalidate_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0;
	char r;
	dsmpf_debug("%d invalid %llu by %d done", kvm->arch.dsm_id,
		    (unsigned long long)req->gfn, req->msg_sender);
	if (dsm_is_pinned(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_INV blocked by pinned gfn[%llu,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	/*
	 * The vfn->gfn rmap can be inconsistent with kvm_memslots when
	 * we're setting memslot, but this will not affect the correctness.
	 * If the old memslot is deleted, then the sptes will be zapped
	 * anyway, so nothing should be done with this case. On the other
	 * hand, if the new memslot is inserted (freshly created or moved),
	 * its sptes are yet to be constructed in tdp_page_fault, and that
	 * is protected by dsm_lock and cannot happen concurrently with the
	 * server side transaction, so the correct DSM state will be seen
	 * in spte construction.
	 *
	 * For usual cases, order between these two operations (change DSM state and
	 * modify page table right) counts. After spte is zapped, DSM software
	 * should make sure that #PF handler read the correct DSM state.
	 */
	BUG_ON(dsm_is_modified(slot, vfn));

	dsm_lock_fast_path(slot, vfn, true);

	dsm_change_state(slot, vfn, DSM_INVALID);
	kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID,memslot);
	unsigned char old_owner = dsm_get_prob_owner(slot, vfn);
	dsm_set_prob_owner(slot, vfn, req->msg_sender);
	dsm_debug_v("kvm[%d](INV) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, old_owner, req->msg_sender);
	dsm_clear_copyset(slot, vfn);
	ret = network_ops.send(conn_sock, &r, 1, 0, tx_add);

	dsm_unlock_fast_path(slot, vfn, true);
	return ret < 0 ? ret : 0;
}

static int dsm_handle_write_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0, length = 0;
	int owner = -1;

	bool is_owner = false;
	struct dsm_response resp;

	if (dsm_is_pinned(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_WRITE blocked by pinned gfn[%llu,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	if ((is_owner = dsm_is_owner(slot, vfn))) {
		BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);

		/* I'm owner */
		int old_owner = dsm_get_prob_owner(slot, vfn);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](M1) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, old_owner, req->msg_sender);
		// printk("kvm[%d](M1) changed owner of gfn[%llu,%d] "
		// "from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
		// req->is_smm, kvm->arch.dsm_id, req->msg_sender);
		dsm_change_state(slot, vfn, DSM_INVALID);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID,memslot);
		/* Send back copyset to new owner. */
		resp.inv_copyset = *dsm_get_copyset(slot, vfn);
		resp.version = dsm_get_version(slot, vfn);
		clear_bit(kvm->arch.dsm_id, &resp.inv_copyset);
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0)
			return ret;
	}
	else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
		/* Send back a dummy copyset. */
		resp.inv_copyset = 0;
		resp.version = dsm_get_version(slot, vfn);
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0)
			return ret;
		int old_owner = dsm_get_prob_owner(slot, vfn);
		length = PAGE_SIZE;
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](303) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", old_owner, req->gfn,
				req->is_smm, kvm->arch.dsm_id, req->msg_sender);
		dsm_change_state(slot, vfn, DSM_INVALID);
	}
	else {
		struct dsm_request new_req = {
			.req_type = DSM_REQ_WRITE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = req->msg_sender,
			.gfn = req->gfn,
			.is_smm = req->is_smm,
			.version = req->version,
		};
		owner = dsm_get_prob_owner(slot, vfn);
		if (owner == req->msg_sender || owner == req->requester) {
			printk_ratelimited(KERN_WARNING
			       "GVM DSM write_req: stale owner hint node=%u gfn=0x%llx owner=%d requester=%u sender=%u state=0x%x version=%u, ack-only\n",
			       READ_ONCE(kvm->arch.dsm_id),
			       (unsigned long long)req->gfn, owner,
			       req->requester, req->msg_sender,
			       slot->vfn_dsm_state[vfn - slot->base_vfn].state,
			       dsm_get_version(slot, vfn));
			resp.inv_copyset = 0;
			resp.version = dsm_get_version(slot, vfn);
			dsm_set_prob_owner(slot, vfn, req->msg_sender);
			dsm_change_state(slot, vfn, DSM_INVALID);
			kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID, memslot);
			length = 0;
			goto send_write_resp;
		}
		ret = length = kvm_dsm_fetch(kvm, owner, true, &new_req, page, &resp);
		if (ret < 0)
			return ret;

		dsm_change_state(slot, vfn, DSM_INVALID);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID,memslot);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](M3) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, owner, req->msg_sender);
		dsm_debug_v("kvm[%d](M3) changed owner of gfn[%llu,%d] "
		"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
		req->is_smm, owner, req->msg_sender);

		clear_bit(kvm->arch.dsm_id, &resp.inv_copyset);
	}

	if (is_owner) {
		length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot,
				req->gfn, req->version);
	}

send_write_resp:
	tx_add->inv_copyset = resp.inv_copyset;
	tx_add->version = resp.version;
	ret = network_ops.send(conn_sock, page, length, 0, tx_add);
	if (ret < 0)
		return ret;
	dsm_debug_v("kvm[%d] sent page[%llu,%d] to kvm[%d] length %d hash: 0x%x\n",
			kvm->arch.dsm_id, req->gfn, req->is_smm, req->requester, length,
			jhash(page, length, JHASH_INITVAL));
	// printk("kvm[%d] sent page[%llu,%d] to kvm[%d] length %d hash: 0x%x\n",
		// kvm->arch.dsm_id, req->gfn, req->is_smm, req->requester, length,
		// jhash(page, length, JHASH_INITVAL));
	return 0;
}

/*
 * A read fault causes owner transmission, too. It's different from original MSI
 * protocol. It mainly addresses a subtle data-race that *AFTER* DSM page fault
 * and *BEFORE* setting appropriate right a write requests (invalidation
 * request) issued by owner will be 'swallowed'. Specifically, in
 * mmu.c:tdp_page_fault:
 * // A read fault
 * [pf handler] dsm_access = kvm_dsm_vcpu_acquire_page()
 * .
 * . [server] dsm_handle_invalidate_req()
 * .
 * [pf handler] __direct_map(dsm_access)
 * [pf handler] kvm_dsm_vcpu_release_page()
 * dsm_handle_invalidate_req() takes no effects then (Note that invalidate
 * handler is lock-free). And if a read fault changes owner too, others write
 * faults will be synchronized by this node.
 */
static int dsm_handle_read_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0, length = 0;
	int owner = -1;
	bool is_owner = false;
	struct dsm_response resp = {
		.version = 0,
	};

	if (dsm_is_pinned(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_READ blocked by pinned gfn[0x%llx,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	is_owner = dsm_is_owner(slot, vfn);
	dsm_debug_v("kvm[%d] dsm_is_owner(slot={base_vfn=0x%llx, npages=0x%llx}, vfn=0x%llx)=%d\n", kvm->arch.dsm_id,
			(u64)slot->base_vfn, (u64)slot->npages, (u64)vfn, is_owner);
	if (is_owner) {
		BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);
		int old_owner = dsm_get_prob_owner(slot, vfn);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](S1) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, old_owner, req->msg_sender);
		// printk("kvm[%d](S1) changed owner of gfn[%llu,%d] "
		// "from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
		// req->is_smm, kvm->arch.dsm_id, req->msg_sender);
		/* TODO: if modified */
		dsm_change_state(slot, vfn, DSM_SHARED);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_SHARED,memslot);

		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0)
			goto out;
		/*
		 * read fault causes owner transmission, too. Send copyset back to new
		 * owner.
		 */
		resp.inv_copyset = *dsm_get_copyset(slot, vfn);
		BUG_ON(!(test_bit(kvm->arch.dsm_id, &resp.inv_copyset)));
		resp.version = dsm_get_version(slot, vfn);
	}
	else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		dsm_debug_v("kvm_read_guest_page_nonlocal = %d\n", ret);
		if (ret < 0)
			goto out;
		dsm_debug_v("page content: %02x %02x %02x %02x %02x %02x %02x %02x\n",
				page[0], page[1], page[2], page[3], page[4], page[5], page[6], page[7]);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](read_handle) changed owner of gfn[%llu,%d] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, 0, req->msg_sender);
		dsm_change_state(slot, vfn, DSM_SHARED);
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
		length = PAGE_SIZE;
		resp.inv_copyset = *dsm_get_copyset(slot, vfn);
		resp.version = dsm_get_version(slot, vfn);
	}
	else {
		struct dsm_request new_req = {
			.req_type = DSM_REQ_READ,
			.requester = kvm->arch.dsm_id,
			.msg_sender = req->msg_sender,
			.gfn = req->gfn,
			.is_smm = req->is_smm,
			.version = req->version,
		};
		owner = dsm_get_prob_owner(slot, vfn);
		if (owner == req->msg_sender || owner == req->requester) {
			printk_ratelimited(KERN_WARNING
			       "GVM DSM read_req: stale owner hint node=%u gfn=0x%llx owner=%d requester=%u sender=%u state=0x%x version=%u, ack-only\n",
			       READ_ONCE(kvm->arch.dsm_id),
			       (unsigned long long)req->gfn, owner,
			       req->requester, req->msg_sender,
			       slot->vfn_dsm_state[vfn - slot->base_vfn].state,
			       dsm_get_version(slot, vfn));
			resp.inv_copyset = 0;
			resp.version = dsm_get_version(slot, vfn);
			dsm_set_prob_owner(slot, vfn, req->msg_sender);
			dsm_change_state(slot, vfn, DSM_INVALID);
			kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID, memslot);
			length = 0;
			goto send_read_resp;
		}
		ret = length = kvm_dsm_fetch(kvm, owner, true, &new_req, page, &resp);
		if (ret < 0)
			goto out;
		BUG_ON(dsm_is_readable(slot, vfn) && !(test_bit(kvm->arch.dsm_id,
						&resp.inv_copyset)));
		/* Even read fault changes owner now. May the force be with you. */
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_debug_v("kvm[%d](S3) changed owner of gfn[%llu,%d] vfn[%llu] "
				"from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
				req->is_smm, vfn, owner, req->msg_sender);
		// printk("kvm[%d](S3) changed owner of gfn[%llu,%d] vfn[%llu] "
		// "from kvm[%d] to kvm[%d]\n", kvm->arch.dsm_id, req->gfn,
		// req->is_smm, vfn, owner, req->msg_sender);
	}

	if (is_owner) {
		length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot,
				req->gfn, req->version);
		// printk("gvmdebug kvm[%d] encode diff (len=%d)\n", kvm->arch.dsm_id, length);
	}

send_read_resp:
	tx_add->inv_copyset = resp.inv_copyset;
	tx_add->version = resp.version;
	ret = network_ops.send(conn_sock, page, length, 0, tx_add);
	if (ret < 0)
		goto out;
	dsm_debug_v("kvm[%d] sent page[%llu,%d] to kvm[%d] length %d hash: 0x%x,network_sent %d\n",
			kvm->arch.dsm_id, req->gfn, req->is_smm, req->requester, length,
			jhash(page, length, JHASH_INITVAL),ret);
	// printk("kvm[%d] sent page[%llu,%d] to kvm[%d] length %d hash: 0x%x\n",
		// kvm->arch.dsm_id, req->gfn, req->is_smm, req->requester, length,
		// jhash(page, length, JHASH_INITVAL));
out:
	return ret;
}

int ivy_kvm_dsm_handle_req(void *data)
{
	int ret = 0, idx;

	struct dsm_conn *conn = (struct dsm_conn *)data;
	struct kvm *kvm = conn->kvm;
	kconnection_t *conn_sock = conn->sock;

	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *slot;
	struct dsm_request req;
	bool retry = false;
	bool locked = false;
	int lock_retry_cnt = 0;
	hfn_t vfn;
	char comm[TASK_COMM_LEN];

	char *page;
	char *req_buf;
	int len;

	/* Size of the maximum buffer is PAGE_SIZE */
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page == NULL)
		return -ENOMEM;
	req_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (req_buf == NULL) {
		kfree(page);
		return -ENOMEM;
	}

	while (1) {
		tx_add_t tx_add = {
			/* Accept any incoming requests. */
			.txid = DSM_TXID_ANY,
		};

		if (kthread_should_stop()) {
			ret = -EPIPE;
			goto out;
		}

		len = network_ops.receive(conn_sock, req_buf, PAGE_SIZE, 0, &tx_add);

		if (len <= 0) {
			ret = len;
			goto out;
		}
		if (len != sizeof(struct dsm_request)) {
			printk_ratelimited(KERN_ERR
			       "GVM DSM bad request length: node=%u len=%d txid=0x%x\n",
			       READ_ONCE(kvm->arch.dsm_id), len, tx_add.txid);
			ret = -EPROTO;
			goto out;
		}
		memcpy(&req, req_buf, sizeof(req));

		BUG_ON(req.requester == kvm->arch.dsm_id);
		locked = false;
		lock_retry_cnt = 0;

retry_handle_req:
		idx = srcu_read_lock(&kvm->srcu);
		memslot = __gfn_to_memslot(__kvm_memslots(kvm, req.is_smm), req.gfn);
		/*
		 * We should ignore private memslots since they are not really visible
		 * to guest and thus are not part of guest state that should be
		 * distributedly shared.
		 */
		if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
				memslot->flags & KVM_MEMSLOT_INVALID) {
			printk(KERN_WARNING "%s: kvm %d invalid gfn 0x%llx!\n",
					__func__, kvm->arch.dsm_id, req.gfn);
			srcu_read_unlock(&kvm->srcu, idx);
			schedule();
			goto retry_handle_req;
		}

		vfn = __gfn_to_vfn_memslot(memslot, req.gfn);
		slot = gfn_to_hvaslot(kvm, memslot, req.gfn);
		if (!slot) {
			printk(KERN_WARNING "%s: kvm %d slot of gfn 0x%llx doesn't exist!\n",
					__func__, kvm->arch.dsm_id, req.gfn);
			srcu_read_unlock(&kvm->srcu, idx);
			schedule();
			goto retry_handle_req;
		}
		if (!kvm_dsm_hvaslot_matches_gfn(slot, memslot, req.gfn)) {
			printk_ratelimited(KERN_ERR
			       "GVM DSM ivy_req: hvaslot mismatch node=%u from=%u type=%s gfn=0x%llx vfn=0x%llx slot_base_gfn=0x%llx slot_base_vfn=0x%llx npages=%lu txid=0x%x\n",
			       READ_ONCE(kvm->arch.dsm_id), req.msg_sender,
			       req_desc[req.req_type],
			       (unsigned long long)req.gfn,
			       (unsigned long long)vfn,
			       (unsigned long long)slot->base_gfn,
			       (unsigned long long)slot->base_vfn,
			       slot->npages, tx_add.txid);
			srcu_read_unlock(&kvm->srcu, idx);
			ret = -EFAULT;
			goto out;
		}

		if (dsm_trace_enabled() &&
		    atomic_inc_return(&gvm_ivy_req_log_count[gvm_ivy_log_node(kvm)]) <= 256)
			printk(KERN_INFO "GVM DSM ivy_req: node=%u from=%u requester=%u type=%s gfn=0x%llx smm=%u vfn=0x%llx state=0x%x owner=%d version=%u txid=0x%x\n",
			       READ_ONCE(kvm->arch.dsm_id), req.msg_sender,
			       req.requester, req_desc[req.req_type],
			       (unsigned long long)req.gfn, req.is_smm,
			       (unsigned long long)vfn,
			       slot->vfn_dsm_state[vfn - slot->base_vfn].state,
			       dsm_get_prob_owner(slot, vfn),
			       dsm_get_version(slot, vfn), tx_add.txid);

		dsm_debug_v("kvm[%d] received request[0x%x] from kvm[%d->%d] req_type[%s] "
				"gfn[%llu,%d] vfn[%llu] version %d myversion %d\n",
				kvm->arch.dsm_id, tx_add.txid, req.msg_sender, req.requester,
				req_desc[req.req_type], req.gfn, req.is_smm, vfn, req.version,
				dsm_get_version(slot, vfn));
		// printk("kvm[%d] received request[0x%x] from kvm[%d->%d] req_type[%s] "
		// "gfn[%llu,%d] vfn[%llu] version %d myversion %d\n",
		// kvm->arch.dsm_id, tx_add.txid, req.msg_sender, req.requester,
		// req_desc[req.req_type], req.gfn, req.is_smm, vfn, req.version,
		// dsm_get_version(slot, vfn));


		BUG_ON(dsm_is_initial(slot, vfn) && dsm_get_prob_owner(slot, vfn) != 0);
		/*
		 * All #PF transactions begin with acquiring owner's (global visble)
		 * dsm_lock. Since only owner can issue DSM_REQ_INVALIDATE, there's no
		 * need to acquire lock. And locking here is prone to cause deadlock.
		 *
		 * If the thread waits for the lock for too long, just buffer the
		 * request and finds whether there's some more requests.
		 */
		if (req.req_type != DSM_REQ_INVALIDATE) {
			ret = dsm_trylock_timeout(kvm, slot, vfn,
						  &lock_retry_cnt, memslot);
			if (ret == -EAGAIN) {
				srcu_read_unlock(&kvm->srcu, idx);
				cond_resched();
				goto retry_handle_req;
			}
			if (ret < 0) {
				srcu_read_unlock(&kvm->srcu, idx);
				goto out;
			}
			locked = true;
		}

		switch (req.req_type) {
		case DSM_REQ_INVALIDATE:
			ret = dsm_handle_invalidate_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);

			if (ret < 0)
				goto out_unlock;
			break;

		case DSM_REQ_WRITE:
			// printk("write req");
			ret = dsm_handle_write_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		case DSM_REQ_READ:
			ret = dsm_handle_read_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		default:
			BUG();
		}

		/* Once a request has been completed, this node isn't owner then. */
		if (req.req_type != DSM_REQ_INVALIDATE && !retry)
			dsm_clear_copyset(slot, vfn);

		if (dsm_trace_enabled() &&
		    atomic_inc_return(&gvm_ivy_req_log_count[gvm_ivy_log_node(kvm)]) <= 256)
			printk(KERN_INFO "GVM DSM ivy_req_done: node=%u from=%u requester=%u type=%s gfn=0x%llx retry=%u ret=%d state=0x%x owner=%d\n",
			       READ_ONCE(kvm->arch.dsm_id), req.msg_sender,
			       req.requester, req_desc[req.req_type],
			       (unsigned long long)req.gfn, retry, ret,
			       slot->vfn_dsm_state[vfn - slot->base_vfn].state,
			       dsm_get_prob_owner(slot, vfn));

		if (locked) {
			dsm_unlock(kvm, slot, vfn,NULL);
			locked = false;
		}

		srcu_read_unlock(&kvm->srcu, idx);

		if (retry) {
			retry = false;
			schedule();
			goto retry_handle_req;
		}
	}
out_unlock:
	if (locked)
		dsm_unlock(kvm, slot, vfn,NULL);
	srcu_read_unlock(&kvm->srcu, idx);
out:
	kfree(req_buf);
	kfree(page);
	/* return zero since we quit voluntarily */
	if (kvm->arch.dsm_stopped) {
		ret = 0;
	}
	else {
		get_task_comm(comm, current);
		dsm_debug("kvm[%d] %s exited server loop, error %d\n",
				kvm->arch.dsm_id, comm, ret);
	}

	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return ret;
}

/*
 * A faulting vCPU can fill in the EPT correctly without network operations.
 * There're two scenerios:
 * 1. spte is dropped (swap, ksm, etc.)
 * 2. The faulting page has been updated by another vCPU.
 */
static bool is_fast_path(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool write)
{
	/*
	 * DCL is required here because the invalidation server may change the DSM
	 * state too.
	 * Futher, a data race ocurrs when an invalidation request
	 * arrives, the client is between kvm_dsm_page_fault and __direct_map (see
	 * the comment of dsm_handle_read_req). By then EPT is readable while DSM
	 * state is invalid. This causes invalidation request, i.e., a remote write
	 * is omitted.
	 * All transactions should be synchorized by the owner, which is a basic
	 * rule of IVY. But the fast path breaks it. To keep consistency, the fast
	 * path should not be interrupted by an invalidation request. So both fast
	 * path and dsm_handle_invalidate_req should hold a per-page fast_path_lock.
	 */
	if (write && dsm_is_modified(slot, vfn)) {
		dsm_lock_fast_path(slot, vfn, false);
		if (write && dsm_is_modified(slot, vfn)) {
			return true;
		}
		else {
			dsm_unlock_fast_path(slot, vfn, false);
			return false;
		}
	}
	if (!write && dsm_is_readable(slot, vfn)) {
		dsm_lock_fast_path(slot, vfn, false);
		if (!write && dsm_is_readable(slot, vfn)) {
			return true;
		}
		else {
			dsm_unlock_fast_path(slot, vfn, false);
			return false;
		}
	}
	return false;
}
void clean_couter(void) {
	dsm_page_fault_counter = 0;
	total_time=0;
}

/*
 * copyset rules:
 * 1. Only copyset residing on the owner side is valid, so when owner
 * transmission occurs, copyset of the old one should be cleared.
 * 2. Copyset of a fresh write fault owner is zero.
 * 3. Every node can only operate its own bit of a copyset. For example, in a
 * typical msg_sender->manager->owner (write fault) chain, both owner and
 * manager should clear their own bit in the copyset sent back to the new
 * owner (msg_sender). In the current implementation, the chain may becomes
 * msg_sender->probOwner0->probOwner1->...->requester->owner, each probOwner
 * should clear their own bit.
 *
 * version rules:
 * Overview: Each page (gfn) has a version. If versions of two pages on different
 * nodes are the same, the data of two pages are the same.
 * 1. Upon a write fault, the version of requster is resp.version (old owner) + 1
 * 2. Upon a read fault, the version of requester is the same as resp.version
 */
int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write)
{

	int ret, resp_len = 0;
	struct kvm_dsm_memory_slot *slot;
	hfn_t vfn;
	char *page = NULL;
	struct dsm_response resp;
	int owner;
	u32 log_node = gvm_ivy_log_node(kvm);

	ret = 0;
	if (READ_ONCE(kvm->arch.dsm_stopped))
		return KVM_DSM_ACCESS_RW;

	if (!memslot) {
		printk(KERN_ERR "GVM DSM ivy_pf: missing memslot node=%u gfn=0x%llx write=%d\n",
		       READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn, write);
		return -EFAULT;
	}
	if (!kvm_dsm_memslot_is_ram(memslot))
		return KVM_DSM_ACCESS_RW;

	vfn = __gfn_to_vfn_memslot(memslot, gfn);
	slot = gfn_to_hvaslot(kvm, memslot, gfn);
	if (!slot) {
		printk(KERN_ERR "GVM DSM ivy_pf: missing hvaslot node=%u slot=%d gfn=0x%llx vfn=0x%llx base_gfn=0x%llx npages=%lu hva=0x%llx write=%d\n",
		       READ_ONCE(kvm->arch.dsm_id), memslot->id,
		       (unsigned long long)gfn,
		       (unsigned long long)vfn,
		       (unsigned long long)memslot->base_gfn,
		       memslot->npages,
		       (unsigned long long)memslot->userspace_addr, write);
		return -EFAULT;
	}

	if (is_fast_path(kvm, slot, vfn, write)) {
		if (dsm_trace_enabled() &&
		    atomic_inc_return(&gvm_ivy_pf_log_count[log_node]) <= 256)
			printk(KERN_INFO "GVM DSM ivy_pf: node=%u gfn=0x%llx vfn=0x%llx write=%d fast=1 state=0x%x owner=%d ret=0x%x\n",
			       READ_ONCE(kvm->arch.dsm_id),
			       (unsigned long long)gfn,
			       (unsigned long long)vfn, write,
			       slot->vfn_dsm_state[vfn - slot->base_vfn].state,
			       dsm_get_prob_owner(slot, vfn),
			       (unsigned int)(write ? KVM_DSM_ACCESS_RW :
				       KVM_DSM_ACCESS_READ));
		if (write) {
			return KVM_DSM_ACCESS_RW;
		}
		else {
			return KVM_DSM_ACCESS_READ;
		}
	}

	BUG_ON(dsm_is_initial(slot, vfn) && dsm_get_prob_owner(slot, vfn) != 0);

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page == NULL) {
		ret = -ENOMEM;
		printk(KERN_WARNING "%s: kvm %d failed to allocate page buffer 719\n",
				__func__, kvm->arch.dsm_id);
		goto out_error;
	}
	dsm_page_fault_counter++;
	dsmpf_debug("dsm_pf_total: %llu\n",dsm_page_fault_counter);

	ktime_t handle_start,handle_end;
	s64 handle_time;
	handle_start = ktime_get();
	/*
	 * If #PF is owner write fault, then issue invalidate by itself.
	 * Or this node will be owner after #PF, it still issue invalidate by
	 * receiving copyset from old owner.
	 */
	if (write) {
		write_req_counter++;
		struct dsm_request req = {
			.req_type = DSM_REQ_WRITE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
		if (dsm_is_owner(slot, vfn)) {
			BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);

			dsmpf_debug("w_inv %llu %llu %d\n",write_req_counter,gfn,kvm->arch.dsm_id);
			ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn, NULL, kvm->arch.dsm_id);
			if (ret < 0){
				dsm_debug_v("kvm invalidate error");
				goto out_error;
			}
			resp.version = dsm_get_version(slot, vfn);
			resp_len = PAGE_SIZE;

			dsm_incr_version(slot, vfn);
		}
		else {
			owner = dsm_get_prob_owner(slot, vfn);
			/* Owner of all pages is 0 on init. */
			if (unlikely(dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0)) {
				dsmpf_debug("w_init %llu %llu %d\n",write_req_counter,gfn,kvm->arch.dsm_id);
				dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
				dsm_debug_v("kvm[%d](init 773) init owner of gfn[%llu,%d] "
						"to kvm[%d]\n", kvm->arch.dsm_id, gfn,
						is_smm, kvm->arch.dsm_id);
				dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
				dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
				ret = KVM_DSM_ACCESS_RW;
				goto out;
			}
			/*
			 * Ask the probOwner. The prob(ably) owner is probably true owner,
			 * or not. If not, forward the request to next probOwner until find
			 * the true owner.
			 */
			dsmpf_debug("w_fet %llu %llu %d\n",write_req_counter,gfn,kvm->arch.dsm_id);
			ktime_t fetch_start,fetch_end;
			s64 fetch_time;
			fetch_start = ktime_get();
			ret = resp_len = kvm_dsm_fetch(kvm, owner, false, &req, page,
					&resp);
			fetch_end = ktime_get();
			fetch_time = ktime_to_ns(ktime_sub(fetch_end, fetch_start));
			total_time+=fetch_time;
			dsmpf_debug("w_fet %llu cost %lld \n",write_req_counter,fetch_time);
			if (ret < 0){
				dsm_debug_v("kvm fetch error");
				goto out_error;
			}
			ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn,
					&resp.inv_copyset, owner);
			if (ret < 0) {
				dsm_debug_v("kvm invalidate error");
				goto out_error;
			}

			dsm_set_version(slot, vfn, resp.version + 1);
		}

		dsm_clear_copyset(slot, vfn);
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);

		dsm_decode_diff(kvm, page, resp_len, memslot, gfn);
		dsm_set_twin_conditionally(kvm, slot, vfn, page, memslot, gfn,
				dsm_is_owner(slot, vfn), resp.version);

		if (!dsm_is_owner(slot, vfn) && resp_len > 0) {
			ret = kvm_dsm_write_guest_page(kvm, memslot, gfn, page, 0, PAGE_SIZE);
			if (ret < 0) {
				dsm_debug_v("kvm write guest page error");
				goto out_error;
			}
		}
// printk("ivy_page_fault 790 test hvaslot, %llx",gfn_to_hvaslot(kvm, memslot, gfn)->base_vfn);
		dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
		dsm_debug_v("kvm[%d](page_fault_handle 818) changed owner of gfn[%llu,%d] "
						"to kvm[%d]\n", kvm->arch.dsm_id, gfn,
						is_smm, kvm->arch.dsm_id);
		dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
		ret = KVM_DSM_ACCESS_RW;
	} else {
		read_req_counter++;
		struct dsm_request req = {
			.req_type = DSM_REQ_READ,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
		owner = dsm_get_prob_owner(slot, vfn);
		/*
		 * If I'm the owner, then I would have already been in Shared or
		 * Modified state.
		 */
		BUG_ON(dsm_is_owner(slot, vfn));
		/* Owner of all pages is 0 on init. */
		if (unlikely(dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0)) {
			dsmpf_debug("r_inv %llu %llu %d\n",read_req_counter,gfn,kvm->arch.dsm_id);
			dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
			dsm_debug_v("kvm[%d](init 841) init owner of gfn[%llu,%d] "
						"to kvm[%d]\n", kvm->arch.dsm_id, gfn,
						is_smm, kvm->arch.dsm_id);
			dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
			dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
			ret = KVM_DSM_ACCESS_READ;
			goto out;
		}
		/* Ask the probOwner */
		dsmpf_debug("r_fet %llu %llu %d\n",read_req_counter,gfn,kvm->arch.dsm_id);
		ktime_t fetch_start,fetch_end;
		s64 fetch_time;
		fetch_start = ktime_get();
		ret = resp_len = kvm_dsm_fetch(kvm, owner, false, &req, page, &resp);
		fetch_end = ktime_get();
		fetch_time = ktime_to_ns(ktime_sub(fetch_end, fetch_start));
		total_time+=fetch_time;
		dsmpf_debug("r_fet %llu cost %lld \n",read_req_counter,fetch_time);
		if (ret < 0){
			dsm_debug_v("kvm fetch error");
			goto out_error;
		}
		dsm_set_version(slot, vfn, resp.version);
		memcpy(dsm_get_copyset(slot, vfn), &resp.inv_copyset, sizeof(copyset_t));
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);

		dsm_decode_diff(kvm, page, resp_len, memslot, gfn);
		if (resp_len > 0) {
			ret = kvm_dsm_write_guest_page(kvm, memslot, gfn, page, 0, PAGE_SIZE);
			if (ret < 0) {
				dsm_debug_v("kvm write guest page error");
				goto out_error;
			}
		} else if (dsm_trace_enabled() &&
			   atomic_inc_return(&gvm_ivy_pf_log_count[log_node]) <= 256) {
			printk(KERN_INFO "GVM DSM ivy_pf: node=%u gfn=0x%llx read response ack-only version=%u\n",
			       READ_ONCE(kvm->arch.dsm_id),
			       (unsigned long long)gfn, resp.version);
		}
		dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
		dsm_debug_v("kvm[%d](after __kvm_write_guest_page) change owner of gfn[%llu,%d] "
						"to kvm[%d]\n", kvm->arch.dsm_id, gfn,
						is_smm, kvm->arch.dsm_id);
		/*
		 * The node becomes owner after read fault because of data locality,
		 * i.e. a write fault may occur soon. It's not designed to avoid annoying
		 * bugs, right? See comments of dsm_handle_read_req.
		 */
		dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
		ret = KVM_DSM_ACCESS_READ;
	}

out:
	handle_end = ktime_get();
	handle_time = ktime_to_ns(ktime_sub(handle_end,handle_start));


	dsmpf_debug("handle cost: %lld \n",handle_time);
	dsmpf_debug("avg cost: %lld \n",total_time/dsm_page_fault_counter);
	if (dsm_trace_enabled() &&
	    atomic_inc_return(&gvm_ivy_pf_log_count[log_node]) <= 256)
		printk(KERN_INFO "GVM DSM ivy_pf: node=%u gfn=0x%llx vfn=0x%llx write=%d fast=0 state=0x%x owner=%d resp_len=%d ret=0x%x handle_ns=%lld\n",
		       READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn,
		       (unsigned long long)vfn, write,
		       slot->vfn_dsm_state[vfn - slot->base_vfn].state,
		       dsm_get_prob_owner(slot, vfn),
		       resp_len, ret, handle_time);
#ifdef KVM_DSM_PF_PROFILE
	kvm_dsm_pf_trace(kvm, slot, vfn, write, resp_len);
#endif
	kfree(page);

	return ret;

out_error:
	if (READ_ONCE(kvm->arch.dsm_stopped) ||
	    ret == -ERESTARTSYS || ret == -EINTR ||
	    ret == -EPIPE || ret == -ESHUTDOWN) {
		kfree(page);
		return KVM_DSM_ACCESS_RW;
	}
	dump_stack();
	printk(KERN_ERR "kvm-dsm: node-%d failed to handle page fault on gfn[%llu,%d], "
			"error: %d\n", kvm->arch.dsm_id, gfn, is_smm, ret);
	kfree(page);
	return ret;
}
