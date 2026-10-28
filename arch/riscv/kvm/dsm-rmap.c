// SPDX-License-Identifier: GPL-2.0
/*
 * Reverse mappings used by the RISC-V KVM DSM port.
 *
 * A userspace virtual page can be visible through more than one KVM memslot.
 * Ivy changes ownership per host virtual page, so all corresponding guest
 * mappings must be invalidated or write-protected together.
 */

#include <linux/kvm_host.h>

#include "dsm.h"

struct kvm_dsm_rmap_entry {
	gfn_t encoded_gfn;
	struct hlist_node node;
};

static struct hlist_head *kvm_dsm_rmap_head(
		struct kvm_dsm_memory_slot *slot, bool backup, hfn_t vfn)
{
	unsigned long index;

	if (!slot || vfn < slot->base_vfn ||
	    vfn >= slot->base_vfn + slot->npages)
		return NULL;

	index = vfn - slot->base_vfn;
	if (backup && !slot->backup_rmap)
		return NULL;
	if (!backup && !slot->rmap)
		return NULL;

	return backup ? &slot->backup_rmap[index] : &slot->rmap[index];
}

static gfn_t kvm_dsm_decode_gfn(gfn_t encoded_gfn, bool *is_smm)
{
	if (is_smm)
		*is_smm = !!(encoded_gfn & GFN_SMM_MASK);

	return (encoded_gfn & ~(GFN_PRESENT_MASK | GFN_SMM_MASK)) >> 1;
}

static int kvm_dsm_gfn_list_add(gfn_t encoded_gfn,
				struct hlist_head *head)
{
	struct kvm_dsm_rmap_entry *entry;

	hlist_for_each_entry(entry, head, node) {
		if (entry->encoded_gfn == encoded_gfn)
			return 0;
	}

	entry = dsm_kvzalloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	entry->encoded_gfn = encoded_gfn;
	hlist_add_head(&entry->node, head);
	return 0;
}

static void kvm_dsm_gfn_list_remove(gfn_t encoded_gfn,
				    struct hlist_head *head)
{
	struct kvm_dsm_rmap_entry *entry;
	struct hlist_node *tmp;

	hlist_for_each_entry_safe(entry, tmp, head, node) {
		if (entry->encoded_gfn != encoded_gfn)
			continue;

		hlist_del(&entry->node);
		kvfree(entry);
		return;
	}
}

int kvm_dsm_rmap_add(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		     bool backup, gfn_t encoded_gfn, hfn_t vfn,
		     unsigned long npages)
{
	struct hlist_head *head;
	unsigned long i;
	int ret = 0;

	if (!slot || !slot->rmap_lock)
		return -EINVAL;

	mutex_lock(slot->rmap_lock);
	for (i = 0; i < npages; i++, encoded_gfn += 2, vfn++) {
		head = kvm_dsm_rmap_head(slot, backup, vfn);
		if (!head) {
			ret = -EINVAL;
			break;
		}

		ret = kvm_dsm_gfn_list_add(encoded_gfn, head);
		if (ret)
			break;
	}

	if (ret) {
		while (i--) {
			encoded_gfn -= 2;
			vfn--;
			head = kvm_dsm_rmap_head(slot, backup, vfn);
			if (head)
				kvm_dsm_gfn_list_remove(encoded_gfn, head);
		}
	}
	mutex_unlock(slot->rmap_lock);

	return ret;
}

void kvm_dsm_rmap_remove(struct kvm *kvm,
			 struct kvm_dsm_memory_slot *slot, bool backup,
			 gfn_t encoded_gfn, hfn_t vfn,
			 unsigned long npages)
{
	struct hlist_head *head;
	unsigned long i;

	if (!slot || !slot->rmap_lock)
		return;

	mutex_lock(slot->rmap_lock);
	for (i = 0; i < npages; i++, encoded_gfn += 2, vfn++) {
		head = kvm_dsm_rmap_head(slot, backup, vfn);
		if (head)
			kvm_dsm_gfn_list_remove(encoded_gfn, head);
	}
	mutex_unlock(slot->rmap_lock);
}

void kvm_dsm_free_rmap(struct kvm *kvm,
		       struct kvm_dsm_memory_slot *slot)
{
	struct kvm_dsm_rmap_entry *entry;
	struct hlist_node *tmp;
	unsigned long i;

	if (!slot)
		return;

	for (i = 0; i < slot->npages; i++) {
		if (slot->rmap) {
			hlist_for_each_entry_safe(entry, tmp,
						  &slot->rmap[i], node) {
				hlist_del(&entry->node);
				kvfree(entry);
			}
		}
		if (slot->backup_rmap) {
			hlist_for_each_entry_safe(entry, tmp,
						  &slot->backup_rmap[i], node) {
				hlist_del(&entry->node);
				kvfree(entry);
			}
		}
	}

	kvfree(slot->rmap);
	kvfree(slot->backup_rmap);
	kvfree(slot->rmap_lock);
	slot->rmap = NULL;
	slot->backup_rmap = NULL;
	slot->rmap_lock = NULL;
}

gfn_t __kvm_dsm_vfn_to_gfn(struct kvm_dsm_memory_slot *slot,
			   bool backup, hfn_t vfn, bool *is_smm,
			   int *iter_idx, struct kvm_memory_slot *memslot)
{
	struct kvm_dsm_rmap_entry *entry;
	struct hlist_head *head;
	gfn_t gfn = ~0ULL;
	int count = 0;

	head = kvm_dsm_rmap_head(slot, backup, vfn);
	if (!head)
		goto fallback;

	mutex_lock(slot->rmap_lock);
	hlist_for_each_entry(entry, head, node) {
		if (!iter_idx || count++ == *iter_idx) {
			gfn = kvm_dsm_decode_gfn(entry->encoded_gfn, is_smm);
			if (iter_idx)
				*iter_idx = count;
			break;
		}
	}
	if (iter_idx && gfn == ~0ULL)
		*iter_idx = -1;
	mutex_unlock(slot->rmap_lock);

	if (gfn != ~0ULL)
		return gfn;

fallback:
	if (memslot)
		return vfn - slot->base_vfn + memslot->base_gfn;
	if (!backup)
		return vfn - slot->base_vfn + slot->base_gfn;
	return ~0ULL;
}

void kvm_dsm_apply_access_right(struct kvm *kvm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		unsigned long dsm_access, struct kvm_memory_slot *memslot)
{
	struct kvm_dsm_rmap_entry *entry;
	struct kvm_memory_slot *target_slot;
	struct hlist_head *head;

	head = kvm_dsm_rmap_head(slot, false, vfn);
	if (!head)
		return;

	mutex_lock(slot->rmap_lock);
	hlist_for_each_entry(entry, head, node) {
		bool is_smm = false;
		gfn_t gfn = kvm_dsm_decode_gfn(entry->encoded_gfn, &is_smm);

		/* RISC-V KVM has one guest physical address space and no SMM. */
		if (is_smm)
			continue;

		target_slot = __gfn_to_memslot(__kvm_memslots(kvm, 0), gfn);
		if (!target_slot ||
		    target_slot->flags & KVM_MEMSLOT_INVALID ||
		    !kvm_dsm_hvaslot_matches_gfn(slot, target_slot, gfn))
			continue;

		kvm_riscv_gstage_set_dsm_access(kvm, gfn, dsm_access);
	}
	mutex_unlock(slot->rmap_lock);
}
