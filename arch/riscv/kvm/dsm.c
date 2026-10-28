/*
 * Support KVM software distributed memory
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

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm.h"
#ifdef USE_KTCP_NETWORK
#include "ktcp.h"
#endif

#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/mmu_context.h>


#ifdef KVM_DSM_DEBUG
bool kvm_dsm_dbg_verbose = 0;
module_param_named(dsm_debug, kvm_dsm_dbg_verbose, bool, 0644);
MODULE_PARM_DESC(dsm_debug,
		 "Enable verbose RISC-V KVM DSM/Ivy transaction tracing");
#endif

static atomic_t gvm_dsm_hvaslot_miss_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_dsm_memslot_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_dsm_skip_nonram_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_dsm_vma_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_dsm_memcpy_bad_range_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_dsm_memcpy_log_count[DSM_MAX_INSTANCES];

static unsigned int gvm_dsm_log_node(struct kvm *kvm)
{
	u32 node = READ_ONCE(kvm->arch.dsm_id);

	return node < DSM_MAX_INSTANCES ? node : 0;
}

static int kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);

static void kvm_dsm_log_skip_nonram(struct kvm *kvm,
				    const struct kvm_memory_slot *slot,
				    gfn_t gfn, const char *where)
{
	u32 node = gvm_dsm_log_node(kvm);

	if (!dsm_trace_enabled())
		return;

	if (atomic_inc_return(&gvm_dsm_skip_nonram_log_count[node]) > 128)
		return;

	printk(KERN_INFO "GVM DSM skip non-RAM: node=%u where=%s slot=%d gfn=0x%llx base_gfn=0x%llx npages=%lu hva=0x%llx flags=0x%lx\n",
	       READ_ONCE(kvm->arch.dsm_id), where,
	       slot ? slot->id : -1,
	       (unsigned long long)gfn,
	       slot ? (unsigned long long)slot->base_gfn : 0,
	       slot ? slot->npages : 0,
		       slot ? (unsigned long long)slot->userspace_addr : 0,
		       slot ? (unsigned long)slot->flags : 0);
}

static void kvm_dsm_log_memslot_vma(struct kvm *kvm,
				    const struct kvm_memory_slot *slot,
				    int as_id, const char *where)
{
	struct vm_area_struct *vma;
	unsigned long hva;
	u32 node = gvm_dsm_log_node(kvm);
	const char *name = "<anon>";
	unsigned long vm_flags = 0;
	unsigned long vm_start = 0;
	unsigned long vm_end = 0;
	unsigned long ino = 0;

	if (!dsm_trace_enabled() ||
	    !slot || atomic_inc_return(&gvm_dsm_vma_log_count[node]) > 64)
		return;

	hva = slot->userspace_addr;
	if (!mmget_not_zero(kvm->mm))
		return;

	mmap_read_lock(kvm->mm);
	vma = vma_lookup(kvm->mm, hva);
	if (vma) {
		vm_flags = vma->vm_flags;
		vm_start = vma->vm_start;
		vm_end = vma->vm_end;
		if (vma->vm_file) {
			name = vma->vm_file->f_path.dentry->d_name.name;
			ino = file_inode(vma->vm_file)->i_ino;
		}
	} else {
		name = "<no-vma>";
	}
	printk(KERN_INFO
	       "GVM DSM memslot vma: node=%u where=%s as=%d id=%d gfn=0x%llx npages=%lu hva=0x%llx flags=0x%lx vma=[0x%lx,0x%lx) vm_flags=0x%lx file=%s ino=%lu\n",
	       READ_ONCE(kvm->arch.dsm_id), where, as_id, slot->id,
	       (unsigned long long)slot->base_gfn, slot->npages,
	       (unsigned long long)slot->userspace_addr,
	       (unsigned long)slot->flags, vm_start, vm_end, vm_flags,
	       name, ino);
	mmap_read_unlock(kvm->mm);
	mmput(kvm->mm);
}

/*
 * The old dsm_memslots are free here rather than kvm_dsm_remove_memslot.
 */
int kvm_dsm_register_memslot_hva(struct kvm *kvm, struct kvm_memory_slot *slot,
		unsigned long npages)
{
	int ret, i;
	hfn_t base_vfn, start, end;
	struct kvm_dsm_memslots *slots = NULL, *old_slots = __kvm_hvaslots(kvm);
	struct kvm_dsm_memory_slot *old_slot;

	if (!kvm->arch.dsm_enabled)
		return 0;
	if (!kvm_dsm_memslot_is_ram(slot)) {
		kvm_dsm_log_skip_nonram(kvm, slot, slot ? slot->base_gfn : 0,
					"register_hva");
		return 0;
	}
	kvm_dsm_log_memslot_vma(kvm, slot, -1, "register_hva");

	slots = dsm_kvzalloc(sizeof(struct kvm_dsm_memslots));
	if (!slots)
		return -ENOMEM;
	memcpy(slots, old_slots, sizeof(struct kvm_dsm_memslots));

	base_vfn = slot->userspace_addr >> PAGE_SHIFT;
	for (i = 0; i < old_slots->used_slots; i++) {
		if (base_vfn >= old_slots->memslots[i].base_vfn)
			continue;
		if (i == 0) {
			start = base_vfn;
			end = min(base_vfn + npages, old_slots->memslots[i].base_vfn);
		} else {
			old_slot = &old_slots->memslots[i - 1];
			if (base_vfn + npages <= old_slot->base_vfn + old_slot->npages)
				continue;
			start = max(base_vfn, old_slot->base_vfn + old_slot->npages);
			end = min(base_vfn + npages, old_slots->memslots[i].base_vfn);
			if (start == end)
				continue;
		}
		ret = insert_hvaslot(slots, i, start,
				     slot->base_gfn + (start - base_vfn),
				     end - start);
		if (ret < 0)
			goto out_free;
	}

	if (old_slots->used_slots == 0) {
		start = base_vfn;
		end = base_vfn + npages;
	} else {
		old_slot = &old_slots->memslots[old_slots->used_slots - 1];
		start = max(base_vfn, old_slot->base_vfn + old_slot->npages);
		end = base_vfn + npages;
	}
	if (end > start) {
		ret = insert_hvaslot(slots, old_slots->used_slots, start,
				     slot->base_gfn + (start - base_vfn),
				     end - start);
		if (ret < 0)
			goto out_free;
	}

	rcu_assign_pointer(kvm->arch.dsm_hvaslots, slots);
	synchronize_srcu_expedited(&kvm->srcu);
	printk(KERN_INFO "GVM DSM hvaslot register: node=%u slot=%d base_gfn=0x%llx npages=%lu base_vfn=0x%llx hvaslots=%d\n",
	       READ_ONCE(kvm->arch.dsm_id), slot->id,
	       (unsigned long long)slot->base_gfn, slot->npages,
	       (unsigned long long)base_vfn, slots->used_slots);
	kvfree(old_slots);
	return 0;

out_free:
	kvfree(slots);
	return ret;
}

/* This should happen before the new memslot is added to kvm_memslots */
int kvm_dsm_add_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		int as_id)
{
	// printk("kvm-dsm: add memslot %llx-%llx\n", slot->base_gfn,
			// slot->base_gfn + slot->npages);
	struct kvm_dsm_memslots *slots;
	struct kvm_dsm_memory_slot *hvaslot, *new_hvaslot;
	unsigned long npages;
	gfn_t gfn, gfn_end, gfn_iter;
	hfn_t vfn;
	int ret = 0, i, iter_idx;
	bool flag;

	if (!kvm->arch.dsm_enabled)
		return 0;
	if (!kvm_dsm_memslot_is_ram(slot)) {
		kvm_dsm_log_skip_nonram(kvm, slot, slot ? slot->base_gfn : 0,
					"add_memslot");
		return 0;
	}
	kvm_dsm_log_memslot_vma(kvm, slot, as_id, "add_memslot");

	gfn_end = slot->base_gfn + slot->npages;
	slots = __kvm_hvaslots(kvm);
	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		flag = false;
		npages = 1;
		for (i = 0; i < slots->used_slots; i++) {
			hvaslot = &slots->memslots[i];
			iter_idx = 0;
			while (iter_idx >= 0) {
				bool is_smm = false;

				gfn_iter = __kvm_dsm_vfn_to_gfn(hvaslot, true,
						hvaslot->base_vfn, &is_smm,
						&iter_idx, NULL);
				if (gfn_iter == ~0ULL)
					break;
				if (!!is_smm == !!as_id && gfn_iter <= gfn && gfn_iter +
						hvaslot->npages > gfn) {
					flag = true;
					break;
				}
			}
			if (flag)
				break;
		}
		if (!flag)
			continue;
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		new_hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		if (!new_hvaslot) {
			u32 node = gvm_dsm_log_node(kvm);

			if (atomic_inc_return(&gvm_dsm_memslot_log_count[node]) <= 256)
				printk(KERN_ERR "GVM DSM add_memslot: missing new hvaslot node=%u as=%d slot=%d gfn=0x%llx vfn=0x%llx base_gfn=0x%llx npages=%lu hva=0x%llx hvaslots=%d\n",
				       READ_ONCE(kvm->arch.dsm_id), as_id, slot->id,
				       (unsigned long long)gfn,
				       (unsigned long long)vfn,
				       (unsigned long long)slot->base_gfn,
				       slot->npages,
				       (unsigned long long)slot->userspace_addr,
				       slots->used_slots);
			continue;
		}
		if (new_hvaslot == hvaslot)
			continue;
		npages = min(gfn_end - gfn, min(hvaslot->npages - (gfn - gfn_iter),
					new_hvaslot->npages - (vfn - new_hvaslot->base_vfn)));
		/* Retreive dsm state from backup in case of gfn->vfn mapping changes. */
		for (i = 0; i < npages; i++) {
			new_hvaslot->vfn_dsm_state[i + (vfn - new_hvaslot->base_vfn)].state
				= hvaslot->vfn_dsm_state[i + (gfn - gfn_iter)].state;
#ifdef IVY_KVM_DSM
			memcpy(new_hvaslot->vfn_dsm_state[i + (vfn -
					new_hvaslot->base_vfn)].copyset,
					hvaslot->vfn_dsm_state[i + (gfn - gfn_iter)].copyset,
					sizeof(copyset_t));
#elif defined(TARDIS_KVM_DSM)
			/* TODO */
#endif
		}
	}

	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		/* ignore private memslots, they have no corresponding hvaslots */
		if (!hvaslot) {
			u32 node = gvm_dsm_log_node(kvm);

			if (atomic_inc_return(&gvm_dsm_memslot_log_count[node]) <= 256)
				printk(KERN_ERR "GVM DSM add_memslot: missing hvaslot node=%u as=%d slot=%d gfn=0x%llx vfn=0x%llx base_gfn=0x%llx npages=%lu hva=0x%llx hvaslots=%d\n",
				       READ_ONCE(kvm->arch.dsm_id), as_id, slot->id,
				       (unsigned long long)gfn,
				       (unsigned long long)vfn,
				       (unsigned long long)slot->base_gfn,
				       slot->npages,
				       (unsigned long long)slot->userspace_addr,
				       slots->used_slots);
			return 0;
		}
		npages = min(gfn_end - gfn, hvaslot->base_vfn + hvaslot->npages - vfn);
		ret = kvm_dsm_rmap_add(kvm, hvaslot, false,
				kvm_dsm_encode_rmap_gfn(gfn, !!as_id),
				vfn, npages);
		if (ret < 0)
			goto out_free;
	}
	return ret;

out_free:
	gfn_end = gfn;
	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		if (!hvaslot)
			break;
		npages = min(gfn_end - gfn, hvaslot->base_vfn + hvaslot->npages - vfn);
		kvm_dsm_rmap_remove(kvm, hvaslot, false,
				kvm_dsm_encode_rmap_gfn(gfn, !!as_id),
				vfn, npages);
	}
	return ret;
}

/* This should happen after the old memslot is marked invalid in kvm_memslots */
void kvm_dsm_remove_memslot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *hvaslot;
	unsigned long npages;
	gfn_t gfn, gfn_end;
	hfn_t vfn;
	int i,bkt;
	int nr_as = KVM_ADDRESS_SPACE_NUM;

	if (!kvm->arch.dsm_enabled)
		return;
	if (!kvm_dsm_memslot_is_ram(slot)) {
		kvm_dsm_log_skip_nonram(kvm, slot, slot ? slot->base_gfn : 0,
					"remove_memslot");
		return;
	}

	/*
	 * The slot passed in is exactly the memory slot marked invalid in the
	 * current kvm_memslots, so we can find if the slot is in smm space.
	 *
	 * XXX: Or maybe we can use KVM_MEMSLOT_INVALID as the indicator of the
	 * matching memslot, as there should be only one slot that is invalid at a
	 * given time.
	 */
	for (i = 0; i < nr_as; i++) {
		memslots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(memslot, bkt,memslots) {
			if (memslot == slot)
				goto out;
		}
	}
out:
	if (i == nr_as) {
		return;
	}

	gfn_end = slot->base_gfn + slot->npages;
	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		/* ignore private memslots, they have no corresponding hvaslots */
		if (!hvaslot)
			return;
		npages = min(gfn_end - gfn, hvaslot->base_vfn + hvaslot->npages - vfn);
		/* Backup dsm state. */
		kvm_dsm_rmap_remove(kvm, hvaslot, false,
				kvm_dsm_encode_rmap_gfn(gfn, !!i),
				vfn, npages);
		kvm_dsm_rmap_add(kvm, hvaslot, true,
				kvm_dsm_encode_rmap_gfn(gfn, !!i),
				vfn, npages);
	}
}

static int kvm_dsm_register_existing_memslots(struct kvm *kvm)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *slot;
	int as_id, bkt, ret;
	unsigned int registered = 0;

	mutex_lock(&kvm->slots_lock);

	for (as_id = 0; as_id < KVM_ADDRESS_SPACE_NUM; as_id++) {
		memslots = __kvm_memslots(kvm, as_id);

		kvm_for_each_memslot(slot, bkt, memslots) {
			if (!slot->npages || slot->id >= KVM_USER_MEM_SLOTS ||
			    slot->flags & KVM_MEMSLOT_INVALID)
				continue;

			ret = kvm_dsm_register_memslot_hva(kvm, slot,
							   slot->npages);
			if (ret)
				goto out_unlock;

			ret = kvm_dsm_add_memslot(kvm, slot, as_id);
			if (ret)
				goto out_unlock;

			registered++;
			kvm_dsm_log_memslot_vma(kvm, slot, as_id, "init");
			printk(KERN_INFO "GVM DSM memslot init: node=%u as=%d id=%d gfn=0x%llx npages=%lu hva=0x%llx\n",
			       READ_ONCE(kvm->arch.dsm_id), as_id, slot->id,
			       (unsigned long long)slot->base_gfn,
			       slot->npages,
			       (unsigned long long)slot->userspace_addr);
		}
	}

	ret = 0;
	printk(KERN_INFO "GVM DSM memslot init: node=%u registered=%u hvaslots=%d\n",
	       READ_ONCE(kvm->arch.dsm_id), registered,
	       __kvm_hvaslots(kvm)->used_slots);

out_unlock:
	mutex_unlock(&kvm->slots_lock);
	return ret;
}

/*
 * Should be called inside kvm->srcu or kvm->slots_lock, and paired with
 * kvm_dsm_release_page.
 */
static int __kvm_dsm_acquire_page(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn, bool is_smm, bool write)
{
	struct kvm_dsm_memory_slot *hvaslot;
	hfn_t vfn;
	int dsm_access;

	if (WARN_ON(kvm->mm != current->mm)) {
		printk(KERN_ERR "GVM DSM acquire: unexpected mm context node=%u gfn=0x%llx\n",
		       READ_ONCE(kvm->arch.dsm_id), (unsigned long long)gfn);
		return -EINVAL;
	}
	if (!kvm->arch.dsm_enabled){
		// printk("dsm_not_enabled");
		return KVM_DSM_ACCESS_RW;
	}

	/*
	 * We should ignore private memslots since they are not really visible
	 * to guest and thus are not part of guest state that should be
	 * distributedly shared.
	 */
	if (!kvm_dsm_memslot_is_ram(slot))
	{
		kvm_dsm_log_skip_nonram(kvm, slot, gfn, "acquire_page");
		// printk("ignore private memslots");
		return KVM_DSM_ACCESS_RW;
	}

	vfn = __gfn_to_vfn_memslot(slot, gfn);


	hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
	if (!hvaslot)
	{
		u32 node = gvm_dsm_log_node(kvm);

		if (atomic_inc_return(&gvm_dsm_hvaslot_miss_log_count[node]) <= 256)
			printk(KERN_ERR "GVM DSM acquire: missing hvaslot node=%u slot=%d gfn=0x%llx vfn=0x%llx base_gfn=0x%llx npages=%lu hva=0x%llx hvaslots=%d write=%u\n",
			       READ_ONCE(kvm->arch.dsm_id), slot->id,
			       (unsigned long long)gfn,
			       (unsigned long long)vfn,
			       (unsigned long long)slot->base_gfn,
			       slot->npages,
			       (unsigned long long)slot->userspace_addr,
			       __kvm_hvaslots(kvm)->used_slots, write);
		return KVM_DSM_ACCESS_RW;
	}
	if (!kvm_dsm_hvaslot_matches_gfn(hvaslot, slot, gfn)) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM acquire: hvaslot mismatch node=%u slot=%d gfn=0x%llx vfn=0x%llx hvaslot_base_gfn=0x%llx hvaslot_base_vfn=0x%llx npages=%lu write=%u\n",
		       READ_ONCE(kvm->arch.dsm_id), slot->id,
		       (unsigned long long)gfn,
		       (unsigned long long)vfn,
		       (unsigned long long)hvaslot->base_gfn,
		       (unsigned long long)hvaslot->base_vfn,
		       hvaslot->npages, write);
		return -EFAULT;
	}
	// printk("dsm_lock vfn %llx, hvaslot_vfn %llx", vfn, hvaslot->base_vfn);

	dsm_lock(kvm, hvaslot, vfn,NULL);
	// printk("dsm_lock end");
	dsm_access = kvm_dsm_page_fault(kvm, slot, gfn, is_smm, write);
	if (dsm_access < 0) {
		dsm_unlock(kvm, hvaslot, vfn,NULL);
	}
	return dsm_access;
}

int kvm_dsm_acquire_page(struct kvm *kvm, struct kvm_memory_slot **slot,
		gfn_t gfn, bool write)
{
	struct kvm_memory_slot *memslot;
	memslot = gfn_to_memslot(kvm, gfn);
	if (slot)
		*slot = memslot;
	return __kvm_dsm_acquire_page(kvm, memslot, gfn, 0, write);
}

int kvm_dsm_vcpu_acquire_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot **slot, gfn_t gfn, bool write)
{
	struct kvm_memory_slot *memslot;
	memslot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (slot)
		*slot = memslot;
	return __kvm_dsm_acquire_page(vcpu->kvm, memslot,
			gfn, 0, write);
}

/*
 * Should be called inside kvm->srcu or kvm->slots_lock, and paired with
 * kvm_dsm_acquire_page.
 */
void kvm_dsm_release_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn)
{
	// printk("kvm_dsm_release_page 321");
	struct kvm_dsm_memory_slot *hvaslot;
	hfn_t vfn;

	if(WARN_ON(kvm->mm != current->mm))
		return;

	if (!kvm->arch.dsm_enabled)
		return;
	if (!kvm_dsm_memslot_is_ram(slot)) {
		kvm_dsm_log_skip_nonram(kvm, slot, gfn, "release_page");
		return;
	}

	vfn = __gfn_to_vfn_memslot(slot, gfn);
	hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
	if (!hvaslot)
		return;
	if (!kvm_dsm_hvaslot_matches_gfn(hvaslot, slot, gfn)) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM release: hvaslot mismatch node=%u slot=%d gfn=0x%llx vfn=0x%llx hvaslot_base_gfn=0x%llx hvaslot_base_vfn=0x%llx npages=%lu\n",
		       READ_ONCE(kvm->arch.dsm_id), slot->id,
		       (unsigned long long)gfn,
		       (unsigned long long)vfn,
		       (unsigned long long)hvaslot->base_gfn,
		       (unsigned long long)hvaslot->base_vfn,
		       hvaslot->npages);
		return;
	}
	// printk("kvm_dsm_release_page 336");
	dsm_unlock_fast_path(hvaslot, vfn, false);
	dsm_unlock(kvm, hvaslot, vfn,NULL);
}

void kvm_dsm_vcpu_release_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot *slot, gfn_t gfn)
{
	kvm_dsm_release_page(vcpu->kvm, slot, gfn);
}

/*
 * Synchronize a Guest page before a remotely started vCPU can consume it.
 *
 * HSM messages and Ivy page transactions use independent TCP connections.
 * Force the local copy invalid and fetch it from the source owner so that a
 * target vCPU cannot run through a stale G-stage mapping before an outstanding
 * DSM invalidation becomes visible.
 */
int kvm_dsm_sync_remote_gpa(struct kvm *kvm, gpa_t gpa, u32 owner)
{
	struct kvm_dsm_memory_slot *hvaslot;
	struct kvm_memory_slot *acquired_slot;
	struct kvm_memory_slot *memslot;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	hfn_t vfn;
	int idx;
	int ret;

	if (!READ_ONCE(kvm->arch.dsm_enabled))
		return 0;
	if (owner >= READ_ONCE(kvm->arch.cluster_iplist_len) ||
	    owner == READ_ONCE(kvm->arch.dsm_id))
		return -EINVAL;
	if (WARN_ON(kvm->mm != current->mm))
		return -EINVAL;

	idx = srcu_read_lock(&kvm->srcu);
	memslot = __gfn_to_memslot(__kvm_memslots(kvm, 0), gfn);
	if (!kvm_dsm_memslot_is_ram(memslot)) {
		ret = 0;
		goto out_srcu;
	}

	vfn = __gfn_to_vfn_memslot(memslot, gfn);
	hvaslot = gfn_to_hvaslot(kvm, memslot, gfn);
	if (!hvaslot || !kvm_dsm_hvaslot_matches_gfn(hvaslot, memslot, gfn)) {
		ret = -EFAULT;
		goto out_srcu;
	}

	dsm_lock(kvm, hvaslot, vfn, memslot);
	dsm_lock_fast_path(hvaslot, vfn, false);

	dsm_change_state(hvaslot, vfn, DSM_INVALID);
	dsm_set_prob_owner(hvaslot, vfn, owner);
	bitmap_zero(hvaslot->vfn_dsm_state[
			    dsm_vfn_index(hvaslot, vfn)].copyset,
		    DSM_MAX_INSTANCES);
	kvm_dsm_apply_access_right(kvm, hvaslot, vfn, DSM_INVALID, memslot);

	dsm_unlock_fast_path(hvaslot, vfn, false);
	dsm_unlock(kvm, hvaslot, vfn, memslot);

	/*
	 * Fetch while the target vCPU is still stopped. Besides updating the
	 * bytes, this establishes the normal Ivy version/copyset state before
	 * the first G-stage mapping is installed.
	 */
	ret = kvm_dsm_acquire_page(kvm, &acquired_slot, gfn, false);
	if (ret < 0)
		goto out_srcu;
	kvm_dsm_release_page(kvm, acquired_slot, gfn);
	ret = 0;

	pr_info("kvm-riscv-dsm: synchronized remote HSM page gpa=0x%llx gfn=0x%llx owner=%u\n",
		(unsigned long long)gpa, (unsigned long long)gfn, owner);

out_srcu:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

int kvm_dsm_acquire(struct kvm *kvm, struct kvm_memslots **slots, gpa_t gpa,
		unsigned long len, bool write)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;
	int ret = KVM_DSM_ACCESS_RW;

	memslots = __kvm_memslots(kvm, 0);
	if (slots)
		*slots = memslots;
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(memslots, gfn);
		ret = __kvm_dsm_acquire_page(kvm, slot, gfn, 0, write);
		if (ret < 0)
			goto out_release;
	}
	return ret;

out_release:
	while (--gfn >= (gpa >> PAGE_SHIFT)) {
		slot = __gfn_to_memslot(memslots, gfn);
		kvm_dsm_release_page(kvm, slot, gfn);
	}
	return ret;
}

int kvm_dsm_vcpu_acquire(struct kvm_vcpu *vcpu, struct kvm_memslots **slots,
		gpa_t gpa, unsigned long len, bool write)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;
	int ret = KVM_DSM_ACCESS_RW;


	// printk("vcpu_acquire\n");
	memslots = kvm_vcpu_memslots(vcpu);
	if (slots)
		*slots = memslots;
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(memslots, gfn);
		ret = __kvm_dsm_acquire_page(vcpu->kvm, slot,
				gfn, 0, write);
		if (ret < 0)
			goto out_release;
	}
	return ret;

out_release:
	while (--gfn >= (gpa >> PAGE_SHIFT)) {
		slot = __gfn_to_memslot(memslots, gfn);
		kvm_dsm_vcpu_release_page(vcpu, slot, gfn);
	}
	return ret;
}

void kvm_dsm_release(struct kvm *kvm, struct kvm_memslots *slots, gpa_t gpa,
		unsigned long len)
{
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;

	BUG_ON(!slots);
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(slots, gfn);
		kvm_dsm_release_page(kvm, slot, gfn);
	}
}

void kvm_dsm_vcpu_release(struct kvm_vcpu *vcpu, struct kvm_memslots *slots,
		gpa_t gpa, unsigned long len)
{
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;
	// printk("vcpu_release\n");

	BUG_ON(!slots);
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(slots, gfn);
		kvm_dsm_vcpu_release_page(vcpu, slot, gfn);
	}
}

/* DSM server functions entry. */
static int kvm_dsm_handle_req(void *data)
{
#ifdef IVY_KVM_DSM
	return ivy_kvm_dsm_handle_req(data);
#elif defined(TARDIS_KVM_DSM)
	return tardis_kvm_dsm_handle_req(data);
#endif
}

/*
 * kvm_dsm_init: init
 * kvm_dsm_threadfn: kvm-dsm
 * kvm_dsm_handle_req: dsm-conn
 *
 * init spanws one kvm-dsm.
 * Upon accepting any incoming connections, kvm-dsm spanws NDSM_CONN_THREADS
 * dsm-conn.
 * Invariant: Inv request should not be blocked. The multiple server threads
 * help.
 */
static int kvm_dsm_threadfn(void *data)
{
	int ret;

	kconnection_t *listen_sock = NULL;
	kconnection_t *accept_sock = NULL;
	struct dsm_address addr;
	struct dsm_conn *conn;
	struct list_head conn_list;
	struct task_struct *thread;
	int i, count;
	char comm[TASK_COMM_LEN];

	struct kvm *kvm = (struct kvm *)data;

	allow_signal(SIGKILL);
	INIT_LIST_HEAD(&conn_list);

	ret = get_dsm_address(kvm, kvm->arch.dsm_id, &addr);
	if (ret < 0) {
		return ret;
	}
	ret = network_ops.listen(addr.host, addr.port, &listen_sock);
	if (ret < 0) {
		return ret;
	}

	dsm_debug_v("kvm[%d] started dsm server on %s:%s\n", kvm->arch.dsm_id,
			addr.host, addr.port);
	dsm_trace_info("kvm[%d] started dsm server on %s:%s\n",
		       kvm->arch.dsm_id, addr.host, addr.port);
	count = 0;
	while (1) {
		if (kthread_should_stop()) {
			ret = 0;
			goto out_listen_sock;
		}
		ret = network_ops.accept(listen_sock, &accept_sock, 0);
		if (ret < 0) {
			/* We only exit with -ERESTARTSYS when the kthread should stop. */
			if (ret == -ERESTARTSYS)
				ret = 0;
			goto out_listen_sock;
		}
		conn = kzalloc(sizeof(struct dsm_conn), GFP_KERNEL);
		if (conn == NULL) {
			ret = -ENOMEM;
			goto out_accept_sock;
		}
		printk(KERN_INFO "kvm-dsm: node-%d accepted connection\n", kvm->arch.dsm_id);
		conn->kvm = kvm;
		conn->sock = accept_sock;

		for (i = 0; i < NDSM_CONN_THREADS; i++) {
			/*
			 * The count is somewhat meaningless since it doesn't contain
			 * information about which remote node it connects to.
			 */
			thread = kthread_run(kvm_dsm_handle_req, (void*)conn, "dsm-conn/%d:%d",
					kvm->arch.dsm_id, count++);
			if (IS_ERR(thread)) {
				printk(KERN_ERR "kvm-dsm: failed to start kernel thread for dsm connection\n");
				ret = PTR_ERR(thread);
				goto out_accept_sock;
			}
			conn->threads[i] = thread;
		}
		list_add_tail(&conn->link, &conn_list);
	}

out_accept_sock:
	network_ops.release(accept_sock);
out_listen_sock:
	while (!list_empty(&conn_list)) {
		conn = list_first_entry(&conn_list, struct dsm_conn, link);
		list_del(&conn->link);
		for (i = 0; i < NDSM_CONN_THREADS; i++) {
			if (!conn->threads[i])
				continue;
			send_sig(SIGKILL, conn->threads[i], 1);
		}
		if (network_ops.shutdown)
			network_ops.shutdown(conn->sock);
		for (i = 0; i < NDSM_CONN_THREADS; i++) {
			if (!conn->threads[i])
				continue;
			get_task_comm(comm, conn->threads[i]);
			ret = kthread_stop(conn->threads[i]);
			dsm_debug("kvm[%d] dsm connection thread %s exited with %d",
					kvm->arch.dsm_id, comm, ret);
			if (ret)
				printk(KERN_ERR "kvm[%d] dsm connection thread %s exited with %d\n",
				       kvm->arch.dsm_id, comm, ret);
		}
		network_ops.release(conn->sock);
		kfree(conn);
	}

	for (i = 0; i < DSM_MAX_INSTANCES; i++) {
		if (kvm->arch.dsm_conn_socks[i]) {
			network_ops.release(kvm->arch.dsm_conn_socks[i]);
			kvm->arch.dsm_conn_socks[i] = NULL;
		}
		if (kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + i]) {
			network_ops.release(kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + i]);
			kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + i] = NULL;
		}
	}
	kfree(kvm->arch.dsm_conn_socks);
	kvm->arch.dsm_conn_socks = NULL;

	network_ops.release(listen_sock);

#ifdef KVM_DSM_PF_PROFILE
	if (dsm_trace_enabled())
		kvm_dsm_report_profile(kvm);
#endif
	clean_couter();
// printk("544 ,%d\n",ret);
	return ret;
}

static int kvm_dsm_init(struct kvm *kvm, struct kvm_dsm_params *params)
{
	int ret = 0;
	struct task_struct *thread;
	int i;
	char **user_cluster_iplist;

	if (!params->cluster_iplist_len ||
	    params->cluster_iplist_len > DSM_MAX_INSTANCES ||
	    params->dsm_id >= params->cluster_iplist_len ||
	    !params->cluster_iplist)
		return -EINVAL;

	if (kvm->arch.dsm_enabled)
		return ret;

	/* QEMU must enable DSM before creating vCPUs and G-stage mappings. */
	if (kvm->created_vcpus)
		return -EBUSY;

	dsm_debug("Enable kvm dsm mode, this kvm instance will be node-%u\n",
			params->dsm_id);

	/* Deep copy cluster_iplist from user space. */
	kvm->arch.cluster_iplist_len = params->cluster_iplist_len;
	kvm->arch.cluster_iplist = (char **)kzalloc(sizeof(void *) *
			params->cluster_iplist_len, GFP_KERNEL);
	if (!kvm->arch.cluster_iplist)
		return -ENOMEM;
	user_cluster_iplist = (char **)kzalloc(sizeof(void *) *
			params->cluster_iplist_len, GFP_KERNEL);
	if (!user_cluster_iplist) {
		ret = -ENOMEM;
		goto out_free_cluster_iplist;
	}
	if (copy_from_user(user_cluster_iplist,
			u64_to_user_ptr(params->cluster_iplist),
			sizeof(void *) * params->cluster_iplist_len)) {
		ret = -EFAULT;
		goto out_free_cluster_iplist;
	}
	for (i = 0; i < params->cluster_iplist_len; i++) {
		long copied;

		kvm->arch.cluster_iplist[i] = kmalloc(20, GFP_KERNEL);
		if (!kvm->arch.cluster_iplist[i]) {
			ret = -ENOMEM;
			goto out_free_cluster_iplist;
		}
		copied = strncpy_from_user(kvm->arch.cluster_iplist[i],
				user_cluster_iplist[i], 20);
		if (copied < 0 || copied >= 20) {
			ret = -EINVAL;
			goto out_free_cluster_iplist;
		}
	}

	kfree(user_cluster_iplist);
	user_cluster_iplist = NULL;
	mutex_init(&kvm->arch.conn_init_lock);
#ifdef TARDIS_KVM_DSM
	ret = tardis_kvm_dsm_init(kvm);
	if (ret < 0) {
		goto out_free_cluster_iplist;
	}
#endif

#ifdef USE_KTCP_NETWORK
	network_ops.send = ktcp_send;
	network_ops.receive = ktcp_receive;
	network_ops.connect = ktcp_connect;
	network_ops.listen = ktcp_listen;
	network_ops.accept = ktcp_accept;
	network_ops.shutdown = ktcp_shutdown;
	network_ops.release = ktcp_release;
	dsm_debug("%s: kvm %d use TCP connection\n", __func__, params->dsm_id);
#endif

#ifdef USE_KRDMA_NETWORK
	network_ops.send = krdma_send;
	network_ops.receive = krdma_receive;
	network_ops.connect = krdma_connect;
	network_ops.listen = krdma_listen;
	network_ops.accept = krdma_accept;
	network_ops.shutdown = NULL;
	network_ops.release = krdma_release;
	dsm_debug("%s: kvm %d use RDMA connection\n", __func__, params->dsm_id);
#endif

	kvm->arch.dsm_conn_socks = kzalloc(DSM_MAX_INSTANCES * 2 *
			sizeof(kconnection_t *), GFP_KERNEL);
	if (kvm->arch.dsm_conn_socks == NULL) {
		ret = -ENOMEM;
		goto out_free_cluster_iplist;
	}

	kvm->arch.dsm_enabled = true;
	kvm->arch.dsm_id = params->dsm_id;

	ret = kvm_dsm_register_existing_memslots(kvm);
	WRITE_ONCE(kvm->arch.dsm_stopped, false);
	if (ret)
		goto out;

	thread = kthread_run(kvm_dsm_threadfn, (void*)kvm, "kvm-dsm/%d",
			kvm->arch.dsm_id);
	if (IS_ERR(thread)) {

		printk(KERN_ERR "kvm-dsm: failed to start kernel thread for dsm server\n");
		ret = PTR_ERR(thread);
		goto out;
	}
	kvm->arch.dsm_thread = thread;
	return ret;

out:
	kfree(kvm->arch.dsm_conn_socks);
	kvm->arch.dsm_conn_socks = NULL;
	kvm->arch.dsm_enabled = false;
	goto out_free_cluster_iplist;
out_free_cluster_iplist:
	for (i = 0; i < params->cluster_iplist_len; i++)
		kfree(kvm->arch.cluster_iplist[i]);
	kfree(kvm->arch.cluster_iplist);
	kvm->arch.cluster_iplist = NULL;
	kvm->arch.cluster_iplist_len = 0;
	kfree(user_cluster_iplist);
	return ret;
}

int kvm_dsm_alloc(struct kvm *kvm)
{
	mutex_init(&kvm->arch.dsm_lock);
	/* TODO: number of nodes is not set in this moment. */
	kvm->arch.dsm_hvaslots = dsm_kvzalloc(sizeof(struct kvm_dsm_memslots));
	if (!kvm->arch.dsm_hvaslots)
		return -ENOMEM;

	return 0;
}

void kvm_dsm_stop(struct kvm *kvm)
{
	struct task_struct *thread;
	int ret;

	if (!kvm->arch.dsm_enabled)
		return;

	WRITE_ONCE(kvm->arch.dsm_stopped, true);
	smp_mb();

	thread = xchg(&kvm->arch.dsm_thread, NULL);
	if (!thread)
		return;

	printk(KERN_INFO "kvm-dsm: node-%d stopping dsm server\n",
	       kvm->arch.dsm_id);
#ifdef TARDIS_KVM_DSM
	send_sig(SIGKILL, kvm->arch.expiration_timer_thread, 1);
	ret = kthread_stop(kvm->arch.expiration_timer_thread);
	if (ret < 0)
		printk(KERN_ERR "%s: node-%d dsm expiration timer exited with %d\n",
		       __func__, kvm->arch.dsm_id, ret);
#endif
	send_sig(SIGKILL, thread, 1);
	ret = kthread_stop(thread);
	if (ret < 0)
		printk(KERN_ERR "%s: node-%d dsm root server exited with %d\n",
		       __func__, kvm->arch.dsm_id, ret);
#ifdef TARDIS_KVM_DSM
	cleanup_srcu_struct(&kvm->arch.expiration_list_srcu);
#endif
}

void kvm_dsm_free(struct kvm *kvm)
{
	int i, used_slots;
	struct kvm_dsm_memslots *slots;

	kvm_dsm_stop(kvm);

	if (kvm->arch.dsm_enabled) {
		for (i = 0; i < kvm->arch.cluster_iplist_len; i++)
			kfree(kvm->arch.cluster_iplist[i]);
		kfree(kvm->arch.cluster_iplist);
		kvm->arch.cluster_iplist = NULL;
		kvm->arch.cluster_iplist_len = 0;
	}

	slots = kvm->arch.dsm_hvaslots;
	if (!slots)
		return;

	used_slots = slots->used_slots;
	for (i = 0; i < used_slots; i++) {
#ifdef KVM_DSM_DIFF
		unsigned long j;
		for (j = 0; j < slots->memslots[i].npages; j++) {
			kfree(slots->memslots[i].vfn_dsm_state[j].diff.twin);
		}
#endif
		kvm_dsm_free_rmap(kvm, &slots->memslots[i]);
		kvfree(slots->memslots[i].vfn_dsm_state);
	}
	RCU_INIT_POINTER(kvm->arch.dsm_hvaslots, NULL);
	kvfree(slots);
}

static int kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write)
{
	int ret;
#ifdef KVM_DSM_PF_PROFILE
	struct timespec64 ts;
	ulong start;

	ktime_get_real_ts64(&ts);
	start = ts.tv_sec * 1000 * 1000 + ts.tv_nsec / 1000;
#endif

#ifdef IVY_KVM_DSM
	ret = ivy_kvm_dsm_page_fault(kvm, memslot, gfn, is_smm, write);
#endif

#ifdef KVM_DSM_PF_PROFILE
	ktime_get_real_ts64(&ts);
	kvm->stat.total_tx_latency += ts.tv_sec * 1000 * 1000 + ts.tv_nsec / 1000
		- start;
#endif
	return ret;
}

static int kvm_dsm_copy_user_range(struct kvm *kvm, unsigned long dst,
                                   unsigned long src, unsigned long len)
{
	unsigned long copied = 0;
	void *buf;
	int ret = 0;

	if (!len)
		return 0;
	if (current->mm != kvm->mm)
		return -EFAULT;

	buf = (void *)__get_free_page(GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (copied < len) {
		unsigned long chunk = min_t(unsigned long, PAGE_SIZE,
					    len - copied);

		if (copy_from_user(buf, u64_to_user_ptr((u64)(src + copied)), chunk) ||
		    copy_to_user(u64_to_user_ptr((u64)(dst + copied)), buf, chunk)) {
			ret = -EFAULT;
			break;
		}
		copied += chunk;
	}

	free_page((unsigned long)buf);
	return ret;
}

static int kvm_dsm_memcpy(struct kvm *kvm, unsigned long host_virt_addr,
		unsigned long userspace_addr, unsigned long length, bool write)
{
	struct kvm_dsm_memory_slot *slot;
	struct kvm_memory_slot *memslot;
	hfn_t vfn, vfn_end;
	gfn_t gfn;
	unsigned long npages, gfn_npages, i, j;
	unsigned long hva_start, hva_end, l;
	void *user_buf;
	int idx, ret = 0;

	if (current->mm != kvm->mm)
		return -EFAULT;
	if (!kvm->arch.dsm_enabled)
		return -EINVAL;
	if (!length || host_virt_addr + length < host_virt_addr ||
	    userspace_addr + length < userspace_addr)
		return -EINVAL;

	if (atomic_inc_return(&gvm_dsm_memcpy_log_count[gvm_dsm_log_node(kvm)]) <= 64)
		printk(KERN_INFO
		       "GVM DSM memcpy call: node=%u comm=%s host_hva=0x%lx user_hva=0x%lx len=%lu write=%u current_mm=%p kvm_mm=%p\n",
		       READ_ONCE(kvm->arch.dsm_id), current->comm,
		       host_virt_addr, userspace_addr, length, write,
		       current->mm, kvm->mm);

	dsm_debug_v("hva %lx, length %lu, write %d\n", host_virt_addr, length, write);
	idx = srcu_read_lock(&kvm->srcu);

	vfn_end = ((host_virt_addr + length - 1) >> PAGE_SHIFT) + 1;
	for (vfn = host_virt_addr >> PAGE_SHIFT; vfn < vfn_end; vfn += npages) {
		slot = vfn_to_hvaslot(kvm, vfn);
		if (!slot) {
			u32 node = gvm_dsm_log_node(kvm);

			if (atomic_inc_return(&gvm_dsm_memcpy_bad_range_log_count[node]) <= 64)
				printk(KERN_ERR "GVM DSM memcpy: HVA is not DSM RAM node=%u hva=0x%lx user=0x%lx len=%lu write=%u vfn=0x%llx\n",
				       READ_ONCE(kvm->arch.dsm_id), host_virt_addr,
				       userspace_addr, length, write,
				       (unsigned long long)vfn);
			ret = -EFAULT;
			goto out;
		}
		npages = min(vfn_end - vfn, slot->base_vfn + slot->npages - vfn);

		mutex_lock(&kvm->arch.dsm_lock);
		for (i = 0; i < npages; i++) {
			dsm_lock(kvm, slot, vfn + i,NULL);
		}

		for (i = 0; i < npages; i += gfn_npages) {
			gfn = __kvm_dsm_vfn_to_gfn(slot, false, vfn + i,
						   NULL, NULL, NULL);
			memslot = __gfn_to_memslot(__kvm_memslots(kvm, 0), gfn);
			if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
			    (memslot->flags & KVM_MEMSLOT_INVALID) ||
			    gfn < memslot->base_gfn ||
			    gfn >= memslot->base_gfn + memslot->npages) {
				u32 node = gvm_dsm_log_node(kvm);

				if (atomic_inc_return(&gvm_dsm_memcpy_bad_range_log_count[node]) <= 64)
					printk(KERN_ERR "GVM DSM memcpy: invalid rmap gfn node=%u hva=0x%lx len=%lu write=%u vfn=0x%llx gfn=0x%llx memslot=%px\n",
					       READ_ONCE(kvm->arch.dsm_id),
					       host_virt_addr, length, write,
					       (unsigned long long)(vfn + i),
					       (unsigned long long)gfn, memslot);
				ret = -EFAULT;
				goto out_unlock;
			}
			gfn_npages = min(npages - i, (unsigned long)(memslot->base_gfn +
						memslot->npages - gfn));
			for (j = 0; j < gfn_npages; j++) {
				ret = kvm_dsm_page_fault(kvm, memslot, gfn + j, 0, write);
				if (ret < 0)
					goto out_unlock;
			}
		}

		hva_start = max(host_virt_addr, (unsigned long)(vfn << PAGE_SHIFT));
		user_buf = (void *)(userspace_addr + hva_start - host_virt_addr);
			if (slot) {
				hva_end = min(host_virt_addr + length, (unsigned long)
						(slot->base_vfn + slot->npages) << PAGE_SHIFT);
			}
				l = hva_end - hva_start;
				if (write)
					ret = kvm_dsm_copy_user_range(kvm, hva_start,
								      (unsigned long)user_buf, l);
			else
				ret = kvm_dsm_copy_user_range(kvm,
							      (unsigned long)user_buf,
							      hva_start, l);

out_unlock:
		for (i = 0; i < npages; i++) {
			dsm_unlock_fast_path(slot, vfn + i, false);
			dsm_unlock(kvm, slot, vfn + i,NULL);
		}
		mutex_unlock(&kvm->arch.dsm_lock);
		if (ret < 0)
			goto out;
	}
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int kvm_dsm_mempin(struct kvm *kvm, unsigned long host_virt_addr,
		unsigned long length, bool write, bool unpin)
{
	struct kvm_dsm_memory_slot *slot;
	struct kvm_memory_slot *memslot;
	hfn_t vfn, vfn_end;
	gfn_t gfn;
	unsigned long npages, gfn_npages, i, j;
	int idx, ret = 0;

	dsm_trace_info("GVM DSM mempin: node=%u hva=0x%lx len=%lu write=%u unpin=%u\n",
		       READ_ONCE(kvm->arch.dsm_id), host_virt_addr,
		       length, write, unpin);

	if (current->mm != kvm->mm)
		return -EFAULT;
	if (!kvm->arch.dsm_enabled)
		return -EINVAL;
	if (!length)
		return 0;

	dsm_debug_v("hva %lx, length %lu, write %d unpin %d\n", host_virt_addr, length, write, unpin);
	idx = srcu_read_lock(&kvm->srcu);

	vfn_end = ((host_virt_addr + length - 1) >> PAGE_SHIFT) + 1;
	for (vfn = host_virt_addr >> PAGE_SHIFT; vfn < vfn_end; vfn += npages) {
		slot = vfn_to_hvaslot(kvm, vfn);
		/* ignore private memslots, they have no corresponding hvaslots */
		if (!slot) {
			npages = 1;
			continue;
		}
		npages = min(vfn_end - vfn, slot->base_vfn + slot->npages - vfn);

		mutex_lock(&kvm->arch.dsm_lock);
		for (i = 0; i < npages; i++) {
			dsm_lock(kvm, slot, vfn + i,NULL);
		}

		if (unpin) {
			for (i = 0; i < npages; i++) {
				dsm_unpin(slot, vfn + i, write);
			}
			goto out_unlock;
		}

		for (i = 0; i < npages; i += gfn_npages) {
			gfn = __kvm_dsm_vfn_to_gfn(slot, false, vfn + i,
						   NULL, NULL, NULL);
			memslot = __gfn_to_memslot(__kvm_memslots(kvm, 0), gfn);
			if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
			    (memslot->flags & KVM_MEMSLOT_INVALID) ||
			    gfn < memslot->base_gfn ||
			    gfn >= memslot->base_gfn + memslot->npages) {
				u32 node = gvm_dsm_log_node(kvm);

				if (atomic_inc_return(&gvm_dsm_memcpy_bad_range_log_count[node]) <= 64)
					printk(KERN_ERR "GVM DSM mempin: invalid rmap gfn node=%u hva=0x%lx len=%lu write=%u unpin=%u vfn=0x%llx gfn=0x%llx memslot=%px\n",
					       READ_ONCE(kvm->arch.dsm_id),
					       host_virt_addr, length, write, unpin,
					       (unsigned long long)(vfn + i),
					       (unsigned long long)gfn, memslot);
				ret = -EFAULT;
				goto out_unlock;
			}
			gfn_npages = min(npages - i, (unsigned long)(memslot->base_gfn +
						memslot->npages - gfn));
			for (j = 0; j < gfn_npages; j++) {
				ret = kvm_dsm_page_fault(kvm, memslot, gfn + j, 0, write);
				if (ret < 0)
					goto out_unlock;
			}
		}

		for (i = 0; i < npages; i++) {
			dsm_pin(slot, vfn + i, write);
		}

out_unlock:
		for (i = 0; i < npages; i++) {
			dsm_unlock_fast_path(slot, vfn + i, false);
			dsm_unlock(kvm, slot, vfn + i,NULL);
		}
		mutex_unlock(&kvm->arch.dsm_lock);
		if (ret < 0)
			goto out;
	}
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

long kvm_vm_ioctl_dsm(struct kvm *kvm, unsigned ioctl,
				  unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int r;

	switch (ioctl) {
	case KVM_DSM_ENABLE: {
		struct kvm_dsm_params params;
		r = -EFAULT;
		if (copy_from_user(&params, argp, sizeof(params)))
			goto out;

		/* TODO: It would be better to ensure DSM mode is enabled before the VM
		 * is started, not sure how this can be done properly, maybe using the
		 * following code?
		 *
		 * r = -EINVAL;
		 * if (kvm->created_vcpus)
		 *     goto out;
		 */
		r = kvm_dsm_init(kvm, &params);
		if (r)
			goto out;
		break;
	}
	case KVM_DSM_MEMCPY: {
		struct kvm_dsm_memcpy cpy;
		r = -EFAULT;
		if (copy_from_user(&cpy, argp, sizeof(cpy)))
			goto out;
		r = kvm_dsm_memcpy(kvm, cpy.host_virt_addr, cpy.userspace_addr,
				cpy.length, cpy.write);
		if (r)
			goto out;
		break;
	}
	case KVM_DSM_MEMPIN: {
		struct kvm_dsm_mempin pin;
		r = -EFAULT;
		if (copy_from_user(&pin, argp, sizeof(pin)))
			goto out;
		r = kvm_dsm_mempin(kvm, pin.host_virt_addr, pin.length, pin.write,
				pin.unpin);
		if (r)
			goto out;
		break;
	}
	default:
		r = -ENOTTY;
		break;
	}
out:
	// printk("kvm_vm_ioctl_dsm 950, %d\n",r);
	return r;
}
