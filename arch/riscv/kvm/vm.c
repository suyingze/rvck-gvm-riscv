// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kvm_host.h>
#include <asm/kvm_mmu.h>
#include <asm/timex.h>

#ifdef CONFIG_KVM_DSM
#include "dsm.h"
#endif

const struct _kvm_stats_desc kvm_vm_stats_desc[] = {
	KVM_GENERIC_VM_STATS()
};
static_assert(ARRAY_SIZE(kvm_vm_stats_desc) ==
		sizeof(struct kvm_vm_stat) / sizeof(u64));

const struct kvm_stats_header kvm_vm_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vm_stats_desc),
	.id_offset =  sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vm_stats_desc),
};

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	int r;

	r = kvm_riscv_mmu_alloc_pgd(kvm);
	if (r)
		return r;

	r = kvm_riscv_gstage_vmid_init(kvm);
	if (r) {
		kvm_riscv_mmu_free_pgd(kvm);
		return r;
	}

#ifdef CONFIG_KVM_DSM
	r = kvm_dsm_alloc(kvm);
	if (r) {
		kvm_riscv_mmu_free_pgd(kvm);
		return r;
	}
#endif

	kvm_riscv_aia_init_vm(kvm);

	kvm_riscv_guest_timer_init(kvm);

	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	kvm_destroy_vcpus(kvm);

#ifdef CONFIG_KVM_DSM
	kvm_dsm_free(kvm);
#endif

	kvm_riscv_aia_destroy_vm(kvm);
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irql,
			  bool line_status)
{
	if (!irqchip_in_kernel(kvm))
		return -ENXIO;

	return kvm_riscv_aia_inject_irq(kvm, irql->irq, irql->level);
}

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	struct kvm_msi msi;

	if (!level)
		return -1;

	msi.address_lo = e->msi.address_lo;
	msi.address_hi = e->msi.address_hi;
	msi.data = e->msi.data;
	msi.flags = e->msi.flags;
	msi.devid = e->msi.devid;

	return kvm_riscv_aia_inject_msi(kvm, &msi);
}

static int kvm_riscv_set_irq(struct kvm_kernel_irq_routing_entry *e,
			     struct kvm *kvm, int irq_source_id,
			     int level, bool line_status)
{
	return kvm_riscv_aia_inject_irq(kvm, e->irqchip.pin, level);
}

int kvm_riscv_setup_default_irq_routing(struct kvm *kvm, u32 lines)
{
	struct kvm_irq_routing_entry *ents;
	int i, rc;

	ents = kcalloc(lines, sizeof(*ents), GFP_KERNEL);
	if (!ents)
		return -ENOMEM;

	for (i = 0; i < lines; i++) {
		ents[i].gsi = i;
		ents[i].type = KVM_IRQ_ROUTING_IRQCHIP;
		ents[i].u.irqchip.irqchip = 0;
		ents[i].u.irqchip.pin = i;
	}
	rc = kvm_set_irq_routing(kvm, ents, lines, 0);
	kfree(ents);

	return rc;
}

bool kvm_arch_can_set_irq_routing(struct kvm *kvm)
{
	return irqchip_in_kernel(kvm);
}

int kvm_set_routing_entry(struct kvm *kvm,
			  struct kvm_kernel_irq_routing_entry *e,
			  const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		e->set = kvm_riscv_set_irq;
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin;
		if ((e->irqchip.pin >= KVM_IRQCHIP_NUM_PINS) ||
		    (e->irqchip.irqchip >= KVM_NR_IRQCHIPS))
			goto out;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		e->msi.flags = ue->flags;
		e->msi.devid = ue->u.msi.devid;
		break;
	default:
		goto out;
	}
	r = 0;
out:
	return r;
}

int kvm_arch_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
			      struct kvm *kvm, int irq_source_id, int level,
			      bool line_status)
{
	if (!level)
		return -EWOULDBLOCK;

	switch (e->type) {
	case KVM_IRQ_ROUTING_MSI:
		return kvm_set_msi(e, kvm, irq_source_id, level, line_status);

	case KVM_IRQ_ROUTING_IRQCHIP:
		return kvm_riscv_set_irq(e, kvm, irq_source_id,
					 level, line_status);
	}

	return -EWOULDBLOCK;
}

bool kvm_arch_irqchip_in_kernel(struct kvm *kvm)
{
	return irqchip_in_kernel(kvm);
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
		r = kvm_riscv_aia_available();
		break;
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_DEVICE_CTRL:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_SET_GUEST_DEBUG:
		r = 1;
		break;
#ifdef CONFIG_KVM_DSM
	case KVM_CAP_RISCV_DSM:
		r = 1;
		break;
#endif
	case KVM_CAP_NR_VCPUS:
		r = min_t(unsigned int, num_online_cpus(), KVM_MAX_VCPUS);
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	case KVM_CAP_VM_GPA_BITS:
		r = kvm_riscv_gstage_gpa_bits;
		break;
	default:
		r = 0;
		break;
	}

	return r;
}

#ifdef CONFIG_KVM_DSM_IRQ_FORWARD
static int kvm_riscv_dsm_ipi(struct kvm *kvm, struct kvm_dsm_riscv_ipi *params)
{
	int ret = 0;
	unsigned long i;
	unsigned long hmask = params->hart_mask;
	unsigned long hbase = params->hart_base;
	unsigned long hart_bit = 0;
	struct kvm_vcpu *vcpu;

	if (params->hart_base == ~0ULL)
		hbase = -1UL;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (hbase != -1UL) {
			if (vcpu->vcpu_id < hbase)
				continue;
			hart_bit = vcpu->vcpu_id - hbase;
			if (hart_bit >= BITS_PER_LONG)
				continue;
			if (!(hmask & BIT(hart_bit)))
				continue;
		}

		ret = kvm_riscv_vcpu_set_interrupt(vcpu, IRQ_VS_SOFT);
		if (ret < 0)
			break;
	}

	return ret;
}

static int kvm_riscv_dsm_hsm_start(struct kvm *kvm,
				   struct kvm_dsm_riscv_hsm *params)
{
	struct kvm_cpu_context *reset_cntx;
	struct kvm_vcpu *target_vcpu;
	u64 old_time_delta;
	u64 new_time_delta;
	u64 host_cycles;
	u64 guest_cycles;
	bool timer_synced_now = false;
	int ret = 0;

	target_vcpu = kvm_get_vcpu_by_id(kvm, params->target_vcpu_id);
	if (!target_vcpu)
		return -EINVAL;

#ifdef CONFIG_KVM_DSM
	ret = kvm_dsm_sync_remote_gpa(kvm, params->opaque,
				      params->source_dsm_id);
	if (ret)
		return ret;
#endif

	spin_lock(&target_vcpu->arch.mp_state_lock);

	if (!kvm_riscv_vcpu_stopped(target_vcpu)) {
		ret = -EALREADY;
		goto out;
	}

	host_cycles = get_cycles64();
	spin_lock(&kvm->arch.dsm_timer_lock);
	old_time_delta = kvm->arch.timer.time_delta;
	if (!kvm->arch.dsm_timer_synced) {
		/*
		 * The source and target host counters have unrelated origins.
		 * Rebase the source guest-time snapshot onto this host's counter.
		 * Synchronize once per VM so later HSM starts cannot move time
		 * backwards because of network-latency jitter.
		 */
		new_time_delta = params->guest_cycles - host_cycles;
		WRITE_ONCE(kvm->arch.timer.time_delta, new_time_delta);
		kvm->arch.dsm_timer_synced = true;
		timer_synced_now = true;
	}
	guest_cycles = host_cycles + kvm->arch.timer.time_delta;
	spin_unlock(&kvm->arch.dsm_timer_lock);

	if (timer_synced_now)
		pr_info("kvm-riscv-dsm: timer sync source_guest_cycles=%llu old_time_delta=%lld new_time_delta=%lld\n",
			params->guest_cycles, (s64)old_time_delta,
			(s64)kvm->arch.timer.time_delta);

	pr_info("kvm-riscv-dsm: hsm receive source=%u target=%u host_cycles=%llu guest_cycles=%llu source_guest_cycles=%llu time_delta=%lld synced_now=%u\n",
		params->vcpu_id, params->target_vcpu_id, host_cycles,
		guest_cycles, params->guest_cycles,
		(s64)kvm->arch.timer.time_delta, timer_synced_now);

	reset_cntx = &target_vcpu->arch.guest_reset_context;
	reset_cntx->sepc = params->start_addr;
	reset_cntx->a0 = params->target_vcpu_id;
	reset_cntx->a1 = params->opaque;
	kvm_make_request(KVM_REQ_VCPU_RESET, target_vcpu);

	__kvm_riscv_vcpu_power_on(target_vcpu);

out:
	spin_unlock(&target_vcpu->arch.mp_state_lock);
	return ret;
}
#endif

int kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
#if defined(CONFIG_KVM_DSM) || defined(CONFIG_KVM_DSM_IRQ_FORWARD)
	struct kvm *kvm = filp->private_data;
#ifdef CONFIG_KVM_DSM_IRQ_FORWARD
	void __user *argp = (void __user *)arg;
#endif

	switch (ioctl) {
#ifdef CONFIG_KVM_DSM
	case KVM_DSM_ENABLE:
	case KVM_DSM_MEMCPY:
	case KVM_DSM_MEMPIN:
		return kvm_vm_ioctl_dsm(kvm, ioctl, arg);
#endif
#ifdef CONFIG_KVM_DSM_IRQ_FORWARD
	case KVM_DSM_IPI: {
		struct kvm_dsm_riscv_ipi params;

		if (copy_from_user(&params, argp, sizeof(params)))
			return -EFAULT;
		return kvm_riscv_dsm_ipi(kvm, &params);
	}
	case KVM_DSM_HSM_START: {
		struct kvm_dsm_riscv_hsm params;

		if (copy_from_user(&params, argp, sizeof(params)))
			return -EFAULT;
		return kvm_riscv_dsm_hsm_start(kvm, &params);
	}
#endif
	}
#endif

	return -ENOTTY;
}
