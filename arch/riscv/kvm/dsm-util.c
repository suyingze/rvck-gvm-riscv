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

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm.h" /* KVM_DSM_DEBUG */
#include "dsm-util.h"

#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/mmu_context.h>
#include <linux/sched/mm.h>
// #include <linux/jhash.h>

struct kvm_network_ops network_ops;
static atomic_t gvm_dsm_remote_copy_log_count[DSM_MAX_INSTANCES];
static atomic_t gvm_dsm_remote_write_log_count[DSM_MAX_INSTANCES];

int get_dsm_address(struct kvm *kvm, int dsm_id, struct dsm_address *addr)
{
	if (addr == NULL) {
		return -EINVAL;
	}
	sprintf(addr->port, "%d", 37710 + dsm_id);
	addr->host = kvm->arch.cluster_iplist[dsm_id];

	return 0;
}

int dsm_create_memslot(struct kvm_dsm_memory_slot *slot,
		unsigned long npages)
{
	unsigned long i;
	int ret = 0;
	slot->rmap = NULL;
	slot->backup_rmap = NULL;
	slot->rmap_lock = NULL;
	slot->vfn_dsm_state = NULL;

	slot->rmap = dsm_kvzalloc(npages * sizeof(*slot->rmap));
	if (!slot->rmap) {
		ret = -ENOMEM;
		goto out_free_rmap;
	}

	slot->backup_rmap = dsm_kvzalloc(npages * sizeof(*slot->backup_rmap));
	if (!slot->backup_rmap) {
		ret = -ENOMEM;
		goto out_free_backup_rmap;
	}

	slot->rmap_lock = dsm_kvzalloc(sizeof(*slot->rmap_lock));
	if (!slot->rmap_lock) {
		ret = -ENOMEM;
		goto out_free_rmap_lock;
	}

	slot->vfn_dsm_state = dsm_kvzalloc(npages * sizeof(*slot->vfn_dsm_state));
	if (!slot->vfn_dsm_state){
        ret = -ENOMEM;
		goto out_free_dsm_state;
    }

	mutex_init(slot->rmap_lock);


	for (i = 0; i < npages; i++) {
		INIT_HLIST_HEAD(&slot->rmap[i]);
		INIT_HLIST_HEAD(&slot->backup_rmap[i]);
		mutex_init(&slot->vfn_dsm_state[i].fast_path_lock);
		mutex_init(&slot->vfn_dsm_state[i].lock);
	}

	return ret;

out_free_dsm_state:
	kvfree(slot->vfn_dsm_state);
	kvfree(slot->rmap_lock);
out_free_rmap_lock:
	kvfree(slot->backup_rmap);
out_free_backup_rmap:
	kvfree(slot->rmap);
out_free_rmap:
	return ret;
}

int insert_hvaslot(struct kvm_dsm_memslots *slots, int pos, hfn_t start,
		gfn_t base_gfn, unsigned long npages)
{
	int ret, i;
	if (slots->used_slots == KVM_DSM_MAX_MEMSLOTS) {
		printk(KERN_ERR "kvm-dsm: all slots are used, no more space for new hvaslot[%llu,%lu]\n",
				start, npages);
		return -EINVAL;
	}

	for (i = slots->used_slots++; i > pos; i--) {
		slots->memslots[i] = slots->memslots[i - 1];
	}

	slots->memslots[i].base_vfn = start;
	slots->memslots[i].base_gfn = base_gfn;
	slots->memslots[i].npages = npages;
	dsm_trace_info("kvm-dsm: create new hvaslot[vfn=0x%llx,gfn=0x%llx,%lu]\n",
		       start, (unsigned long long)base_gfn, npages);
	ret = dsm_create_memslot(&slots->memslots[i], npages);
	if (ret < 0)
		return ret;

	return 0;
}

void dsm_lock(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	unsigned long index;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	index = dsm_vfn_index(slot, vfn);
	mutex_lock(&slot->vfn_dsm_state[index].lock);
}

void dsm_unlock(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	unsigned long idx;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;

	idx = dsm_vfn_index(slot, vfn);
	mutex_unlock(&slot->vfn_dsm_state[idx].lock);
}

static int __kvm_dsm_trylock(struct mutex *l)
{
       int retry_cnt = 0;

       while (!mutex_trylock(l)) {
               retry_cnt++;
               if (retry_cnt > 1024) {
                       return -EAGAIN;
               }
       }
       return 1;
}

int dsm_trylock(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
       if (!dsm_vfn_valid(slot, vfn, __func__))
	       return -EINVAL;

       return __kvm_dsm_trylock(&slot->vfn_dsm_state[dsm_vfn_index(slot, vfn)].lock);
}

int kvm_dsm_connect(struct kvm *kvm, int dest_id, kconnection_t **conn_sock)
{
	int ret;
	struct dsm_address addr;

	ret = get_dsm_address(kvm, dest_id, &addr);
	if (ret < 0) {
		printk(KERN_ERR "kvm-dsm: address not configured properly for node-%d\n", dest_id);
		return ret;
	}

	ret = network_ops.connect(addr.host, addr.port, conn_sock);
	if (ret < 0) {
		printk(KERN_ERR "kvm-dsm: node-%d failed to connect to node-%d\n",
				kvm->arch.dsm_id, dest_id);
		return ret;
	}
	printk(KERN_INFO "kvm-dsm: node-%d established connection with node-%d [%s:%s]\n",
			kvm->arch.dsm_id, dest_id, addr.host, addr.port);
	return 0;
}

static int kvm_dsm_validate_guest_page(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn, int offset, int len,
		const char *where)
{
	if (!slot || slot->id >= KVM_USER_MEM_SLOTS ||
	    (slot->flags & KVM_MEMSLOT_INVALID) ||
	    gfn < slot->base_gfn ||
	    gfn >= slot->base_gfn + slot->npages ||
	    offset < 0 || len < 0 || offset + len > PAGE_SIZE) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM %s: bad guest page node=%u slot=%d gfn=0x%llx base=0x%llx npages=%lu hva=0x%llx flags=0x%lx off=%d len=%d\n",
		       where,
		       kvm ? READ_ONCE(kvm->arch.dsm_id) : 0xffffffffu,
		       slot ? slot->id : -1,
		       (unsigned long long)gfn,
		       slot ? (unsigned long long)slot->base_gfn : 0,
		       slot ? slot->npages : 0,
		       slot ? (unsigned long long)slot->userspace_addr : 0,
		       slot ? (unsigned long)slot->flags : 0,
		       offset, len);
		return -EFAULT;
	}

	return 0;
}

static int kvm_dsm_copy_guest_page_remote(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn, void *data,
		int offset, int len, bool write)
{
	unsigned long hva = slot->userspace_addr +
		((gfn - slot->base_gfn) << PAGE_SHIFT);
	struct vm_area_struct *vma;
	unsigned long end;
	u32 node = READ_ONCE(kvm->arch.dsm_id);
	int log_seq = 0;
	int write_log_seq = 0;
	struct page *page;
	void *mapped;
	unsigned long target;
	unsigned int gup_flags = write ? FOLL_WRITE : 0;
	long pinned;
	int locked = 1;

	if (READ_ONCE(kvm->arch.dsm_stopped))
		return -ESHUTDOWN;

	if (node < DSM_MAX_INSTANCES) {
		if (write)
			write_log_seq = atomic_inc_return(&gvm_dsm_remote_write_log_count[node]);
		else
			log_seq = atomic_inc_return(&gvm_dsm_remote_copy_log_count[node]);
	}

	if (dsm_trace_enabled() &&
	    ((!write && log_seq > 0 && log_seq <= 128) ||
	     (write && write_log_seq > 0 && write_log_seq <= 256))) {
		const char *name = "<anon>";
		unsigned long vm_flags = 0;
		unsigned long vm_start = 0;
		unsigned long vm_end = 0;
		unsigned long ino = 0;

		if (mmget_not_zero(kvm->mm)) {
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
			mmap_read_unlock(kvm->mm);
			mmput(kvm->mm);
		} else {
			name = "<dead-mm>";
		}

		printk(KERN_INFO
		       "GVM DSM remote copy: node=%u op=%s comm=%s gfn=0x%llx hva=0x%lx slot=%d base=0x%llx npages=%lu off=%d len=%d flags=0x%lx current_mm=%p kvm_mm=%p vma=[0x%lx,0x%lx) vm_flags=0x%lx file=%s ino=%lu\n",
		       node, write ? "write" : "read", current->comm,
		       (unsigned long long)gfn, hva, slot->id,
		       (unsigned long long)slot->base_gfn, slot->npages,
		       offset, len, (unsigned long)slot->flags,
		       current->mm, kvm->mm, vm_start, vm_end, vm_flags,
		       name, ino);
	}

	if (!mmget_not_zero(kvm->mm)) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM %s_guest_page: dead mm node=%u gfn=0x%llx\n",
		       write ? "write" : "read", READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn);
		return -EFAULT;
	}

	end = hva + offset + len;
	if (end < hva || end > slot->userspace_addr + (slot->npages << PAGE_SHIFT)) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM %s_guest_page: target outside memslot node=%u gfn=0x%llx hva=0x%lx end=0x%lx slot_hva=0x%llx npages=%lu off=%d len=%d\n",
		       write ? "write" : "read", READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn, hva, end,
		       (unsigned long long)slot->userspace_addr, slot->npages,
		       offset, len);
		mmput(kvm->mm);
		return -EFAULT;
	}

	mmap_read_lock(kvm->mm);
	vma = vma_lookup(kvm->mm, hva + offset);
	if (!vma || hva + offset < vma->vm_start || end > vma->vm_end ||
	    (write && !(vma->vm_flags & VM_WRITE)) ||
	    (!write && !(vma->vm_flags & VM_READ))) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM %s_guest_page: target outside guest RAM VMA node=%u gfn=0x%llx hva=0x%lx target=0x%lx end=0x%lx slot_hva=0x%llx vma=[0x%lx,0x%lx) vm_flags=0x%lx\n",
		       write ? "write" : "read", READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn, hva, hva + offset, end,
		       (unsigned long long)slot->userspace_addr,
		       vma ? vma->vm_start : 0, vma ? vma->vm_end : 0,
		       vma ? vma->vm_flags : 0);
		mmap_read_unlock(kvm->mm);
		mmput(kvm->mm);
		return -EFAULT;
	}
	if (write && vma->vm_file) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM write_guest_page: refusing file-backed VMA node=%u gfn=0x%llx hva=0x%lx target=0x%lx end=0x%lx slot_hva=0x%llx vma=[0x%lx,0x%lx) file=%s\n",
		       READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn, hva, hva + offset, end,
		       (unsigned long long)slot->userspace_addr,
		       vma->vm_start, vma->vm_end,
		       vma->vm_file->f_path.dentry->d_name.name);
		mmap_read_unlock(kvm->mm);
		mmput(kvm->mm);
		return -EFAULT;
	}
	mmap_read_unlock(kvm->mm);

	if (READ_ONCE(kvm->arch.dsm_stopped)) {
		mmput(kvm->mm);
		return -ESHUTDOWN;
	}

	target = hva + offset;
	mmap_read_lock(kvm->mm);
	pinned = pin_user_pages_remote(kvm->mm, target, 1, gup_flags,
				       &page, &locked);
	if (locked)
		mmap_read_unlock(kvm->mm);
	if (pinned != 1) {
		printk_ratelimited(KERN_ERR
		       "GVM DSM %s_guest_page: remote page pin failed node=%u gfn=0x%llx hva=0x%lx pinned=%ld len=%d\n",
		       write ? "write" : "read", READ_ONCE(kvm->arch.dsm_id),
		       (unsigned long long)gfn, target, pinned, len);
		mmput(kvm->mm);
		return pinned < 0 ? pinned : -EFAULT;
	}

	mapped = kmap_local_page(page);
	if (write)
		memcpy((char *)mapped + offset_in_page(target), data, len);
	else
		memcpy(data, (char *)mapped + offset_in_page(target), len);
	kunmap_local(mapped);
	unpin_user_pages_dirty_lock(&page, 1, write);
	mmput(kvm->mm);

	return 0;
}

int kvm_dsm_read_guest_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn, void *data, int offset, int len)
{
	int ret;

	ret = kvm_dsm_validate_guest_page(kvm, slot, gfn, offset, len, "read_guest_page");
	if (ret)
		return ret;

	if (kvm && current->mm != kvm->mm) {
		if (!(current->flags & PF_KTHREAD)) {
			printk_ratelimited(KERN_ERR
			       "GVM DSM read_guest_page: wrong mm node=%u current_mm=%p kvm_mm=%p gfn=0x%llx\n",
			       READ_ONCE(kvm->arch.dsm_id), current->mm, kvm->mm,
			       (unsigned long long)gfn);
			return -EFAULT;
		}
		return kvm_dsm_copy_guest_page_remote(kvm, slot, gfn, data,
						      offset, len, false);
	}

	ret = kvm_read_guest_page(kvm, gfn, data, offset, len);

	return ret;
}

int kvm_dsm_write_guest_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn, const void *data, int offset, int len)
{
	int ret;

	ret = kvm_dsm_validate_guest_page(kvm, slot, gfn, offset, len, "write_guest_page");
	if (ret)
		return ret;

	if (!kvm)
		return -EINVAL;

	/*
	 * A vCPU fault handler runs in the QEMU mm and can use KVM's normal
	 * userspace-memory helper.  Only DSM kthreads need remote page pinning
	 * because they do not have the QEMU mm as current->mm.
	 */
	if (current->mm == kvm->mm)
		return kvm_write_guest_page(kvm, gfn, data, offset, len);

	return kvm_dsm_copy_guest_page_remote(kvm, slot, gfn, (void *)data,
					      offset, len, true);
}

int kvm_read_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		void *data, int offset, int len)
{
	int ret = 0;

	ret = kvm_dsm_read_guest_page(kvm, slot, gfn, data, offset, len);
	return ret;
}

int kvm_write_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		const void *data, int offset, int len)
{
	int ret = 0;

	ret = kvm_dsm_write_guest_page(kvm, slot, gfn, data, offset, len);
	return ret;
}

#ifdef KVM_DSM_PF_PROFILE
void kvm_dsm_pf_trace(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool write, int resp_len)
{
	unsigned long index;

	/* Data race here doesn't matter, I suppose. */
	kvm->stat.total_dsm_pfs++;
	kvm->stat.total_tx_bytes += resp_len;

	if (!dsm_vfn_valid(slot, vfn, __func__))
		return;
	index = dsm_vfn_index(slot, vfn);
	if (write) {
		atomic_add(1, &slot->vfn_dsm_state[index].write_pf);
		WARN_ON(atomic_read(&slot->vfn_dsm_state[index].write_pf) == 0);
	} else {
		atomic_add(1, &slot->vfn_dsm_state[index].read_pf);
		WARN_ON(atomic_read(&slot->vfn_dsm_state[index].read_pf) == 0);
	}
}

struct dsm_profile_info {
	hfn_t vfn;
	gfn_t gfn;
	bool is_smm;
	unsigned read_pf;
	unsigned write_pf;
};

/* Find the N pages with maximum read and write. */
void kvm_dsm_report_profile(struct kvm *kvm)
{
	#define N 10
	int idx;
	struct kvm_dsm_memslots *slots;
	struct kvm_dsm_memory_slot *slot;
	struct kvm_dsm_info *info;

	struct dsm_profile_info read_most[N];
	struct dsm_profile_info write_most[N];
	unsigned read_faults = 0, write_faults = 0;
	int i, j, k;

	/* TODO: Use priority queue */
	idx = srcu_read_lock(&kvm->srcu);
	slots = __kvm_hvaslots(kvm);

	for (i = 0; i < N; i++) {
		for (j = 0; j < slots->used_slots; j++) {
			slot = &slots->memslots[j];
			for (k = 0; k < slot->npages; k++) {
				info = &slot->vfn_dsm_state[k];
				if (atomic_read(&info->read_pf) > read_faults && (i == 0 ||
							atomic_read(&info->read_pf) < read_most[i - 1].read_pf)) {
					read_faults = atomic_read(&info->read_pf);
					read_most[i].read_pf = atomic_read(&info->read_pf);
					read_most[i].write_pf = atomic_read(&info->write_pf);
					read_most[i].vfn = slot->base_vfn + k;
					read_most[i].gfn = __kvm_dsm_vfn_to_gfn(slot, false,
							slot->base_vfn + k, NULL, NULL, NULL);
				}
				if (atomic_read(&info->write_pf) > write_faults && (i == 0 ||
							atomic_read(&info->write_pf) < write_most[i - 1].write_pf)) {
					write_faults = atomic_read(&info->write_pf);
					write_most[i].read_pf = atomic_read(&info->read_pf);
					write_most[i].write_pf = atomic_read(&info->write_pf);
					write_most[i].vfn = slot->base_vfn + k;
					write_most[i].gfn = __kvm_dsm_vfn_to_gfn(slot, false,
							slot->base_vfn + k, NULL, NULL, NULL);
				}
			}
		}
		read_faults = write_faults = 0;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	printk(KERN_INFO "kvm-dsm: node-%d most frequently read %d pages\n",
			kvm->arch.dsm_id, N);
	printk(KERN_INFO "\tvfn\tgfn\tread\twrite\n");
	for (i = 0; i < N; i++) {
		printk(KERN_INFO "\t%llx\t[%llu,%d]\t%u\t%u\n", read_most[i].vfn,
				read_most[i].gfn, (int)read_most[i].is_smm,
				read_most[i].read_pf, read_most[i].write_pf);
	}

	printk(KERN_INFO "kvm-dsm: node-%d most frequently written %d pages\n",
			kvm->arch.dsm_id, N);
	printk(KERN_INFO "\tvfn\tgfn\tread\twrite\n");
	for (i = 0; i < N; i++) {
		printk(KERN_INFO "\t%llx\t[%llu,%d]\t%u\t%u\n", write_most[i].vfn,
				write_most[i].gfn, (int)write_most[i].is_smm,
				write_most[i].read_pf, write_most[i].write_pf);
	}

	printk(KERN_INFO "kvm-dsm: node-%d total page faults %lu\n",
			kvm->arch.dsm_id, kvm->stat.total_dsm_pfs);
	printk(KERN_INFO "kvm-dsm: node-%d average bytes %lu\n",
			kvm->arch.dsm_id, kvm->stat.total_dsm_pfs ?
			kvm->stat.total_tx_bytes / kvm->stat.total_dsm_pfs : 0);
	printk(KERN_INFO "kvm-dsm: node-%d average tx latency %luus\n",
			kvm->arch.dsm_id, kvm->stat.total_dsm_pfs ?
			kvm->stat.total_tx_latency / kvm->stat.total_dsm_pfs : 0);
}
#endif
