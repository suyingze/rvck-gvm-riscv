#ifndef ARCH_RISCV_KVM_DSM_H
#define ARCH_RISCV_KVM_DSM_H

#include <linux/kvm_host.h>
#include "dsm-types.h"

#include "dsm-util.h"

#ifdef IVY_KVM_DSM
#include "ivy.h"
#elif defined(TARDIS_KVM_DSM)
#include "tardis.h"
#else
#error "At least one DSM protocol should be appointed."
#endif

#ifdef CONFIG_KVM_DSM
int kvm_dsm_acquire_page(struct kvm *kvm, struct kvm_memory_slot **slot,
		gfn_t gfn, bool write);
int kvm_dsm_vcpu_acquire_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot **slot, gfn_t gfn, bool write);
void kvm_dsm_release_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn);
void kvm_dsm_vcpu_release_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot *slot, gfn_t gfn);
int kvm_dsm_acquire(struct kvm *kvm, struct kvm_memslots **slots, gpa_t gpa,
		unsigned long len, bool write);
int kvm_dsm_vcpu_acquire(struct kvm_vcpu *vcpu, struct kvm_memslots **slots,
		gpa_t gpa, unsigned long len, bool write);
void kvm_dsm_release(struct kvm *kvm, struct kvm_memslots *slot, gpa_t gpa,
		unsigned long len);
void kvm_dsm_vcpu_release(struct kvm_vcpu *vcpu, struct kvm_memslots *slots,
		gpa_t gpa, unsigned long len);

int kvm_dsm_sync_remote_gpa(struct kvm *kvm, gpa_t gpa, u32 owner);

int kvm_dsm_alloc(struct kvm *kvm);
void kvm_dsm_stop(struct kvm *kvm);
void kvm_dsm_free(struct kvm *kvm);
long kvm_vm_ioctl_dsm(struct kvm *kvm, unsigned ioctl, unsigned long arg);

int kvm_dsm_register_memslot_hva(struct kvm *kvm, struct kvm_memory_slot *slot,
		unsigned long npages);
int kvm_dsm_add_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		int as_id);
void kvm_dsm_remove_memslot(struct kvm *kvm, struct kvm_memory_slot *slot);

#else
static inline int kvm_dsm_acquire_page(struct kvm *kvm,
		struct kvm_memory_slot **slot, gfn_t gfn, bool write)
{
	return KVM_DSM_ACCESS_RW;
}

static inline int kvm_dsm_vcpu_acquire_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot **slot, gfn_t gfn, bool write)
{
	return KVM_DSM_ACCESS_RW;
}

static inline void kvm_dsm_release_page(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn)
{
}

static inline void kvm_dsm_vcpu_release_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot *slot, gfn_t gfn)
{
}

static inline int kvm_dsm_acquire(struct kvm *kvm,
		struct kvm_memslots **slots, gpa_t gpa, unsigned long len,
		bool write)
{
	return KVM_DSM_ACCESS_RW;
}

static inline int kvm_dsm_vcpu_acquire(struct kvm_vcpu *vcpu,
		struct kvm_memslots **slots, gpa_t gpa, unsigned long len,
		bool write)
{
	return KVM_DSM_ACCESS_RW;
}

static inline void kvm_dsm_release(struct kvm *kvm, struct kvm_memslots *slot,
		gpa_t gpa, unsigned long len)
{
}

static inline void kvm_dsm_vcpu_release(struct kvm_vcpu *vcpu,
		struct kvm_memslots *slots, gpa_t gpa, unsigned long len)
{
}

static inline int kvm_dsm_sync_remote_gpa(struct kvm *kvm, gpa_t gpa,
					  u32 owner)
{
	return 0;
}

static inline int kvm_dsm_alloc(struct kvm *kvm)
{
	return 0;
}

static inline void kvm_dsm_free(struct kvm *kvm)
{
}

static inline long kvm_vm_ioctl_dsm(struct kvm *kvm, unsigned ioctl,
		unsigned long arg)
{
	return -ENOTTY;
}

static inline int kvm_dsm_register_memslot_hva(struct kvm *kvm,
		struct kvm_memory_slot *slot, unsigned long npages)
{
	return 0;
}

static inline int kvm_dsm_add_memslot(struct kvm *kvm,
		struct kvm_memory_slot *slot, int as_id)
{
	return 0;
}

static inline void kvm_dsm_remove_memslot(struct kvm *kvm,
		struct kvm_memory_slot *slot)
{
}

#endif /* CONFIG_KVM_DSM */

#endif /* ARCH_RISCV_KVM_DSM_H */
