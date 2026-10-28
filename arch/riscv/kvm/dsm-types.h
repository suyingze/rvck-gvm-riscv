/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RISCV_KVM_DSM_TYPES_H__
#define __RISCV_KVM_DSM_TYPES_H__

#include <linux/bitmap.h>
#include <linux/kvm_types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

/* The initial RISC-V port intentionally supports only the TCP transport. */
#define USE_KTCP_NETWORK
#define IVY_KVM_DSM
#define KVM_DSM_W_SHARED

/* Enable useful bring-up logs without enabling the expensive PF profiler. */
#define KVM_DSM_DEBUG

#define DSM_MAX_INSTANCES	16
#define DSM_TXID_ANY		(~0U)
#define KVM_DSM_MAX_MEMSLOTS	512

/* Architecture-neutral result returned by the Ivy fault handler. */
#define KVM_DSM_ACCESS_READ	BIT(0)
#define KVM_DSM_ACCESS_WRITE	BIT(1)
#define KVM_DSM_ACCESS_RW	(KVM_DSM_ACCESS_READ | KVM_DSM_ACCESS_WRITE)

struct ktcp_cb;
typedef struct ktcp_cb kconnection_t;

/* This RISC-V tree has no hfn_t; keep the DSM HVA-page type local. */
typedef u64 hfn_t;

/*
 * Metadata carried next to every DSM transaction.  The wire layout matches
 * the ARM TCP/Ivy reference implementation.
 */
typedef struct tx_add {
	u16 inv_copyset;
	u16 version;
	u32 txid;
} tx_add_t;

typedef unsigned long copyset_t;
typedef u32 version_t;
typedef u32 timestamp_t;

struct kvm_dsm_info {
	unsigned int state;
	DECLARE_BITMAP(copyset, DSM_MAX_INSTANCES);
	struct mutex fast_path_lock;
	atomic_t fast_path_locked;
	atomic_t pinned_read;
	atomic_t pinned_write;
	struct mutex lock;
	version_t version;
};

struct kvm_dsm_memory_slot {
	hfn_t base_vfn;
	gfn_t base_gfn;
	unsigned long npages;
	struct hlist_head *rmap;
	struct hlist_head *backup_rmap;
	struct mutex *rmap_lock;
	struct kvm_dsm_info *vfn_dsm_state;
};

struct kvm_dsm_memslots {
	struct kvm_dsm_memory_slot memslots[KVM_DSM_MAX_MEMSLOTS];
	atomic_t lru_slot;
	int used_slots;
};

static inline void *dsm_kvzalloc(unsigned long size)
{
	return kvzalloc(size, GFP_KERNEL_ACCOUNT);
}

#endif /* __RISCV_KVM_DSM_TYPES_H__ */
