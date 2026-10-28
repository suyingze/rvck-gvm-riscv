#ifndef ARCH_RISCV_KVM_DSM_UTIL_H
#define ARCH_RISCV_KVM_DSM_UTIL_H

#include "dsm-types.h"

#include <linux/kvm_host.h>
#include <linux/jhash.h>

#define DSM_INITIAL     0
#define DSM_INVALID     1
#define DSM_SHARED      2
#define DSM_MODIFIED    3
#define DSM_OWNER       (1 << 2)

#define DSM_STATE_SHIFT     16
#define DSM_STATE_MASK      ((1 << DSM_STATE_SHIFT) - 1)
#define DSM_MSI_STATE_MASK  3

#define GFN_PRESENT_MASK    (1ULL << 63)
#define GFN_SMM_MASK        (1ULL << 62)

/*
 * RISC-V virt places System RAM at 0x80000000.  Lower regions are firmware
 * and MMIO windows and are deliberately excluded from DSM page coherence.
 */
#define KVM_DSM_RISCV_VIRT_RAM_BASE_GFN	(0x80000000ULL >> PAGE_SHIFT)

static inline bool kvm_dsm_memslot_is_ram(const struct kvm_memory_slot *slot)
{
	if (!slot || slot->id >= KVM_USER_MEM_SLOTS ||
	    (slot->flags & KVM_MEMSLOT_INVALID))
		return false;

	return slot->base_gfn >= KVM_DSM_RISCV_VIRT_RAM_BASE_GFN;
}

static inline gfn_t kvm_dsm_encode_rmap_gfn(gfn_t gfn, bool is_smm)
{
	return (gfn << 1) | GFN_PRESENT_MASK |
	       (is_smm ? GFN_SMM_MASK : 0);
}

#ifdef KVM_DSMPF_DEBUG
#define dsmpf_debug(fmt, ...) printk(KERN_DEBUG "%s: " fmt,		\
	__func__, ##__VA_ARGS__)
#else
#define dsmpf_debug(fmt, ...) no_printk(KERN_DEBUG "%s: " fmt,		\
	__func__, ##__VA_ARGS__)
#endif

#ifdef KVM_DSM_DEBUG
extern bool kvm_dsm_dbg_verbose;
#define dsm_debug(fmt, ...) printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#define dsm_debug_v(fmt, ...) do {					\
		if (kvm_dsm_dbg_verbose) printk(KERN_DEBUG "%s(%s:%d): " fmt,	\
		__func__, __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define dsm_trace_enabled()	(kvm_dsm_dbg_verbose)
#define dsm_trace_info(fmt, ...) do {					\
		if (kvm_dsm_dbg_verbose)					\
			printk(KERN_INFO fmt, ##__VA_ARGS__);		\
	} while (0)
#else
#define dsm_debug(fmt, ...) no_printk(KERN_DEBUG "%s(L%d): " fmt,		\
		__func__, __LINE__, ##__VA_ARGS__)
#define dsm_debug_v(fmt, ...) no_printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#define dsm_trace_enabled()	false
#define dsm_trace_info(fmt, ...) no_printk(KERN_INFO fmt, ##__VA_ARGS__)
#endif



struct kvm_network_ops {
	int (*send)(kconnection_t *, const char *, size_t, unsigned long,
			const tx_add_t*);
	int (*receive)(kconnection_t *, char *, size_t, unsigned long, tx_add_t*);
	// int (*send)(kconnection_t *, const char *, size_t, unsigned long,
			// const uint32_t);
	// int (*receive)(kconnection_t *, char *, unsigned long, uint32_t*);
	int (*connect)(const char *, const char *, kconnection_t **);
	int (*listen)(const char *, const char *, kconnection_t **);
	// int (*accept)(kconnection_t *, kconnection_t **, unsigned long);
	int (*accept)(kconnection_t *, kconnection_t **, unsigned long);
	int (*shutdown)(kconnection_t *);
	int (*release)(kconnection_t *);
};

extern struct kvm_network_ops network_ops;

struct dsm_address {
	const char *host;
	char port[8];
};

extern void kvm_riscv_gstage_set_dsm_access(struct kvm *kvm, gfn_t gfn,
					     unsigned long dsm_access);

#define NDSM_CONN_THREADS 8
struct dsm_conn {
	struct list_head link;
	struct kvm *kvm;
	kconnection_t *sock;
	struct task_struct *threads[NDSM_CONN_THREADS];
};

/* mmu.c */
extern gfn_t __kvm_dsm_vfn_to_gfn(struct kvm_dsm_memory_slot *slot,
		bool backup, hfn_t vfn, bool *is_smm, int *iter_idx,
		struct kvm_memory_slot *memslot);
extern int kvm_dsm_rmap_add(struct kvm *kvm,
		struct kvm_dsm_memory_slot *slot, bool backup,
		gfn_t gfn, hfn_t vfn, unsigned long npages);
extern void kvm_dsm_rmap_remove(struct kvm *kvm,
		struct kvm_dsm_memory_slot *slot, bool backup,
		gfn_t gfn, hfn_t vfn, unsigned long npages);
extern void kvm_dsm_free_rmap(struct kvm *kvm,
		struct kvm_dsm_memory_slot *slot);
extern void kvm_dsm_apply_access_right(struct kvm *kvm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		unsigned long dsm_access, struct kvm_memory_slot *memslot);

static inline uint32_t generate_txid(struct kvm *kvm, uint16_t dest_id)
{
	static atomic_t id[DSM_MAX_INSTANCES * DSM_MAX_INSTANCES] = { ATOMIC_INIT(0) };
	u32 idx = kvm->arch.dsm_id * DSM_MAX_INSTANCES + dest_id;
	u32 r;

	do {
		r = (u32)atomic_inc_return(&id[idx]);
	} while (!r || r == DSM_TXID_ANY);

	return r;
}

static inline uint32_t jhash32(const void *s, int n)
{
	return jhash(s, n, JHASH_INITVAL);
}

static inline struct kvm_dsm_memslots *__kvm_hvaslots(struct kvm *kvm)
{
	return rcu_dereference_check(kvm->arch.dsm_hvaslots,
			srcu_read_lock_held(&kvm->srcu)
			|| lockdep_is_held(&kvm->slots_lock));
}

static inline hfn_t __gfn_to_vfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn)
{
	return (slot->userspace_addr >> PAGE_SHIFT) + (gfn - slot->base_gfn);
}

static inline struct kvm_dsm_memory_slot *
search_hvaslots(struct kvm_dsm_memslots *slots, hfn_t vfn)
{
	int start = 0, end = slots->used_slots - 1;
	int slot = atomic_read(&slots->lru_slot);
	struct kvm_dsm_memory_slot *memslots = slots->memslots;

	if (slots->used_slots == 0)
		return NULL;

	if (vfn >= memslots[slot].base_vfn &&
	    vfn < memslots[slot].base_vfn + memslots[slot].npages)
		return &memslots[slot];

	while (start < end) { //?
		slot = start + (end - start + 1) / 2;

		if (vfn >= memslots[slot].base_vfn)
			start = slot;
		else
			end = slot - 1;
	}

	if (vfn >= memslots[start].base_vfn &&
	    vfn < memslots[start].base_vfn + memslots[start].npages) {
		atomic_set(&slots->lru_slot, start);
		return &memslots[start];
	}

	return NULL;
}

static inline struct kvm_dsm_memory_slot *
gfn_to_hvaslot(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn)
{
	return search_hvaslots(__kvm_hvaslots(kvm), __gfn_to_vfn_memslot(slot, gfn));
}

static inline bool kvm_dsm_hvaslot_matches_gfn(struct kvm_dsm_memory_slot *hvaslot,
					       struct kvm_memory_slot *slot,
					       gfn_t gfn)
{
	hfn_t vfn;

	if (!hvaslot || !slot)
		return false;

	vfn = __gfn_to_vfn_memslot(slot, gfn);
	if (vfn < hvaslot->base_vfn ||
	    vfn >= hvaslot->base_vfn + hvaslot->npages)
		return false;

	return hvaslot->base_gfn + (vfn - hvaslot->base_vfn) == gfn;
}

static inline struct kvm_dsm_memory_slot *
vfn_to_hvaslot(struct kvm *kvm, hfn_t vfn)
{
	return search_hvaslots(__kvm_hvaslots(kvm), vfn);
}

int get_dsm_address(struct kvm *kvm, int dsm_id, struct dsm_address *addr);
int dsm_create_memslot(struct kvm_dsm_memory_slot *slot,
		unsigned long npages);
int insert_hvaslot(struct kvm_dsm_memslots *slots, int pos, hfn_t start,
		gfn_t base_gfn, unsigned long npages);

void dsm_lock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn,struct kvm_memory_slot *memslot);
void dsm_unlock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn,struct kvm_memory_slot *memslot);
int dsm_trylock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn);
int dsm_trylock_timeout(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn,
               int *retry_cnt,struct kvm_memory_slot *memslot);

static inline bool dsm_vfn_valid(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
				 const char *where)
{
	if (likely(slot && slot->vfn_dsm_state &&
		   vfn >= slot->base_vfn &&
		   vfn < slot->base_vfn + slot->npages))
		return true;

	printk_ratelimited(KERN_ERR
		"GVM DSM vfn bounds: where=%s slot=%px vfn=0x%llx base_vfn=0x%llx npages=%lu state=%px\n",
		where, slot, (unsigned long long)vfn,
		slot ? (unsigned long long)slot->base_vfn : 0,
		slot ? slot->npages : 0,
		slot ? slot->vfn_dsm_state : NULL);
	return false;
}

static inline unsigned long dsm_vfn_index(struct kvm_dsm_memory_slot *slot,
					  hfn_t vfn)
{
	return vfn - slot->base_vfn;
}

static inline bool dsm_is_pinned(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return false;

	index = dsm_vfn_index(slot, vfn);
	return atomic_read_acquire(&slot->vfn_dsm_state[index].pinned_read) ||
		atomic_read_acquire(&slot->vfn_dsm_state[index].pinned_write);
}

static inline bool dsm_is_pinned_read(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return false;

	index = dsm_vfn_index(slot, vfn);
	return atomic_read_acquire(&slot->vfn_dsm_state[index].pinned_read) &&
		(atomic_read_acquire(&slot->vfn_dsm_state[index].pinned_write) == 0);
}

static inline void dsm_pin(struct kvm_dsm_memory_slot *slot, hfn_t vfn, bool write)
{
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	if (write) {
		atomic_add(1, &slot->vfn_dsm_state[index].pinned_write);
		WARN_ON(atomic_read(&slot->vfn_dsm_state[index].pinned_write) == 0);
	} else {
		atomic_add(1, &slot->vfn_dsm_state[index].pinned_read);
		WARN_ON(atomic_read(&slot->vfn_dsm_state[index].pinned_read) == 0);
	}
}

static inline void dsm_unpin(struct kvm_dsm_memory_slot *slot, hfn_t vfn, bool write)
{
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	if (write)
		atomic_fetch_sub_release(1, &slot->vfn_dsm_state[index].pinned_write);
	else
		atomic_fetch_sub_release(1, &slot->vfn_dsm_state[index].pinned_read);
}

#ifdef IVY_KVM_DSM
static inline bool dsm_is_initial(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return false;

	return (slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].state &
			DSM_MSI_STATE_MASK) == DSM_INITIAL;
}

static inline bool dsm_is_readable(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	unsigned long val;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return false;

	val = slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].state & DSM_MSI_STATE_MASK;
	return (val == DSM_SHARED) || (val == DSM_MODIFIED);
}

static inline bool dsm_is_modified(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return false;

	return (slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].state &
			DSM_MSI_STATE_MASK) == DSM_MODIFIED;
}

static inline void dsm_change_state(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		unsigned state)
{
	unsigned long index;
	unsigned owner;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	owner = slot->vfn_dsm_state[index].state >> DSM_STATE_SHIFT;
	slot->vfn_dsm_state[index].state = (owner << DSM_STATE_SHIFT) | state;
}

static inline int dsm_get_prob_owner(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return 0;

	return slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].state >> DSM_STATE_SHIFT;
}

static inline void dsm_set_prob_owner(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, int owner)
{
	unsigned long index;
	unsigned state;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	state = slot->vfn_dsm_state[index].state & DSM_STATE_MASK;
	slot->vfn_dsm_state[index].state = (owner << DSM_STATE_SHIFT) | state;

}

static inline bool dsm_is_owner(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return false;

	return slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].state & DSM_OWNER;
}

#endif
static inline void dsm_set_twin(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		char *twin)
{
#ifdef KVM_DSM_DIFF
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].diff.twin = twin;
#else
	BUG();
#endif
}

static inline char *dsm_get_twin(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
#ifdef KVM_DSM_DIFF
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return NULL;

	return slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].diff.twin;
#else
	BUG();
#endif
}

static inline version_t dsm_get_version(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn)
{
#ifdef IVY_KVM_DSM
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return 0;

	return slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].version;
#elif defined(TARDIS_KVM_DSM)
	BUG();
#endif
}

static inline version_t dsm_get_twin_version(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn)
{
#ifdef KVM_DSM_DIFF
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return 0;

	return slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].diff.version;
#else
	BUG();
#endif
}

static inline void dsm_incr_version(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	/* dsm_lock should be held. */
#ifdef IVY_KVM_DSM
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].version++;
#elif defined(TARDIS_KVM_DSM)
	BUG();
#endif
}

static inline void dsm_incr_twin_version(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
#ifdef KVM_DSM_DIFF
	/* dsm_lock should be held. */
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].diff.version++;
#else
	BUG();
#endif
}

static inline void dsm_set_version(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		version_t version)
{
#ifdef IVY_KVM_DSM
	/* dsm_lock should be held. */
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].version = version;
#elif defined(TARDIS_KVM_DSM)
	BUG();
#endif
}

static inline void dsm_set_twin_version(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		version_t version)
{
#ifdef KVM_DSM_DIFF
	/* dsm_lock should be held. */
	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].diff.version = version;
#else
	BUG();
#endif
}

int dsm_encode_diff(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		int msg_sender, char *page, struct kvm_memory_slot *memslot, gfn_t gfn,
		uint16_t version);
void dsm_decode_diff(struct kvm *kvm, char *page, int resp_len,
		struct kvm_memory_slot *memslot, gfn_t gfn);
void dsm_set_twin_conditionally(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, char *page, struct kvm_memory_slot *memslot, gfn_t gfn,
		bool is_owner, version_t version);
int kvm_dsm_connect(struct kvm *kvm, int dest_id, kconnection_t **conn_sock);
int kvm_read_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		void *data, int offset, int len);
int kvm_write_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		const void *data, int offset, int len);
int kvm_dsm_read_guest_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn, void *data, int offset, int len);
int kvm_dsm_write_guest_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn, const void *data, int offset, int len);

/*
 * kvm_dsm_release_page must know whether a kvm_dsm_acquire_* is coped with fast
 * path. An alternative is to change the interfaces of these routines, which
 * pass a boolean value to kvm_dsm_release_page to indicate whether it should
 * release the fast_path lock.
 */
static inline void dsm_lock_fast_path(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool is_server)
{
#ifdef IVY_KVM_DSM
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	mutex_lock(&slot->vfn_dsm_state[index].fast_path_lock);
	if (!is_server) {
		/*
		 * Only one vCPU can modify this value hence here is no data race.
		 */
		atomic_set_release(&slot->vfn_dsm_state[index].fast_path_locked, true);
	}
#endif
}

static inline void dsm_unlock_fast_path(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool is_server)
{
#ifdef IVY_KVM_DSM
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	if (!is_server && !atomic_read(&slot->vfn_dsm_state[index].fast_path_locked)) {
		return;
	}
	mutex_unlock(&slot->vfn_dsm_state[index].fast_path_lock);
	if (!is_server) {
		atomic_set_release(&slot->vfn_dsm_state[index].fast_path_locked, false);
	}
#endif
}

#ifdef KVM_DSM_PF_PROFILE
void kvm_dsm_pf_trace(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool write, int resp_len);
void kvm_dsm_report_profile(struct kvm *kvm);
#endif

#endif /* ARCH_RISCV_KVM_DSM_UTIL_H */
