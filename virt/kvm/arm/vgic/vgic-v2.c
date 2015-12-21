/*
 * Copyright (C) 2015, 2016 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/irqchip/arm-gic.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/vgic/vgic.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"

/*
 * Call this function to convert a u64 value to an unsigned long * bitmask
 * in a way that works on both 32-bit and 64-bit LE and BE platforms.
 *
 * Warning: Calling this function may modify *val.
 */
static unsigned long *u64_to_bitmask(u64 *val)
{
#if defined(CONFIG_CPU_BIG_ENDIAN) && BITS_PER_LONG == 32
	*val = (*val >> 32) | (*val << 32);
#endif
	return (unsigned long *)val;
}

void vgic_v2_process_maintenance(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;

	if (cpuif->vgic_misr & GICH_MISR_EOI) {
		u64 eisr = cpuif->vgic_eisr;
		unsigned long *eisr_bmap = u64_to_bitmask(&eisr);
		int lr;

		for_each_set_bit(lr, eisr_bmap, vcpu->arch.vgic_cpu.nr_lr) {
			struct vgic_irq *irq;
			u32 intid = cpuif->vgic_lr[lr] & GICH_LR_VIRTUALID;

			irq = vgic_get_irq(vcpu->kvm, vcpu, intid);

			WARN_ON(irq->config == VGIC_CONFIG_EDGE);
			WARN_ON(cpuif->vgic_lr[lr] & GICH_LR_STATE);

			kvm_notify_acked_irq(vcpu->kvm, 0,
					     intid - VGIC_NR_PRIVATE_IRQS);

			cpuif->vgic_lr[lr] &= ~GICH_LR_STATE; /* Useful?? */
			cpuif->vgic_elrsr |= 1ULL << lr;
		}
	}

	/* check and disable underflow maintenance IRQ */
	cpuif->vgic_hcr &= ~GICH_HCR_UIE;

	/*
	 * In the next iterations of the vcpu loop, if we sync the
	 * vgic state after flushing it, but before entering the guest
	 * (this happens for pending signals and vmid rollovers), then
	 * make sure we don't pick up any old maintenance interrupts
	 * here.
	 */
	cpuif->vgic_eisr = 0;
}

void vgic_v2_set_underflow(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;

	cpuif->vgic_hcr |= GICH_HCR_UIE;
}

/*
 * transfer the content of the LRs back into the corresponding ap_list:
 * - active bit is transferred as is
 * - pending bit is
 *   - transferred as is in case of edge sensitive IRQs
 *   - set to the line-level (resample time) for level sensitive IRQs
 */
void vgic_v2_fold_lr_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;
	int lr;

	for (lr = 0; lr < vcpu->arch.vgic_cpu.used_lrs; lr++) {
		u32 val = cpuif->vgic_lr[lr];
		u32 intid = val & GICH_LR_VIRTUALID;
		struct vgic_irq *irq;

		irq = vgic_get_irq(vcpu->kvm, vcpu, intid);

		spin_lock(&irq->irq_lock);

		/* Always preserve the active bit */
		irq->active = !!(val & GICH_LR_ACTIVE_BIT);

		/* Edge is the only case where we preserve the pending bit */
		if (irq->config == VGIC_CONFIG_EDGE &&
		    (val & GICH_LR_PENDING_BIT)) {
			irq->pending = true;

			if (intid < VGIC_NR_SGIS) {
				u32 cpuid = val & GICH_LR_PHYSID_CPUID;

				cpuid >>= GICH_LR_PHYSID_CPUID_SHIFT;
				irq->source |= (1 << cpuid);
			}
		}

		/* Clear soft pending state when level IRQs have been acked */
		if (irq->config == VGIC_CONFIG_LEVEL &&
		    !(val & GICH_LR_PENDING_BIT)) {
			irq->soft_pending = false;
			irq->pending = irq->line_level;
		}

		spin_unlock(&irq->irq_lock);
	}
}

/*
 * Populates the particular LR with the state of a given IRQ:
 * - for an edge sensitive IRQ the pending state is reset in the struct
 * - for a level sensitive IRQ the pending state value is unchanged;
 *   it will be resampled on deactivation
 *
 * If irq is not NULL, the irq_lock must be hold already by the caller.
 */
void vgic_v2_populate_lr(struct kvm_vcpu *vcpu, struct vgic_irq *irq, int lr)
{
	u32 val;

	if (!irq) {
		val = 0;
		goto out;
	}

	val = irq->intid;

	if (irq->pending) {
		val |= GICH_LR_PENDING_BIT;

		if (irq->config == VGIC_CONFIG_EDGE)
			irq->pending = false;

		if (irq->intid < VGIC_NR_SGIS) {
			u32 src = ffs(irq->source);

			BUG_ON(!src);
			val |= (src - 1) << GICH_LR_PHYSID_CPUID_SHIFT;
			irq->source &= ~(1 << (src - 1));
			if (irq->source)
				irq->pending = true;
		}
	}

	if (irq->active)
		val |= GICH_LR_ACTIVE_BIT;

	if (irq->hw) {
		val |= GICH_LR_HW;
		val |= irq->hwintid << GICH_LR_PHYSID_CPUID_SHIFT;
	} else {
		if (irq->config == VGIC_CONFIG_LEVEL)
			val |= GICH_LR_EOI;
	}

out:
	vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] = val;
}

void vgic_v2_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	u32 vmcr;

	vmcr  = (vmcrp->ctlr << GICH_VMCR_CTRL_SHIFT) & GICH_VMCR_CTRL_MASK;
	vmcr |= (vmcrp->abpr << GICH_VMCR_ALIAS_BINPOINT_SHIFT) &
		GICH_VMCR_ALIAS_BINPOINT_MASK;
	vmcr |= (vmcrp->bpr << GICH_VMCR_BINPOINT_SHIFT) &
		GICH_VMCR_BINPOINT_MASK;
	vmcr |= (vmcrp->pmr << GICH_VMCR_PRIMASK_SHIFT) &
		GICH_VMCR_PRIMASK_MASK;

	vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr = vmcr;
}

void vgic_v2_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	u32 vmcr = vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr;

	vmcrp->ctlr = (vmcr & GICH_VMCR_CTRL_MASK) >>
			GICH_VMCR_CTRL_SHIFT;
	vmcrp->abpr = (vmcr & GICH_VMCR_ALIAS_BINPOINT_MASK) >>
			GICH_VMCR_ALIAS_BINPOINT_SHIFT;
	vmcrp->bpr  = (vmcr & GICH_VMCR_BINPOINT_MASK) >>
			GICH_VMCR_BINPOINT_SHIFT;
	vmcrp->pmr  = (vmcr & GICH_VMCR_PRIMASK_MASK) >>
			GICH_VMCR_PRIMASK_SHIFT;
}

/* Use lower byte as target bitmap for gicv2 */
void vgic_v2_irq_change_affinity(struct kvm *kvm, u32 intid, u8 new_targets)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct vgic_irq *irq;
	int target;

	BUG_ON(intid <= VGIC_MAX_PRIVATE);
	BUG_ON(dist->vgic_model != KVM_DEV_TYPE_ARM_VGIC_V2);

	irq = vgic_get_irq(kvm, NULL, intid);

	spin_lock(&irq->irq_lock);
	irq->targets = new_targets;

	target = ffs(irq->targets);
	target = target ? (target - 1) : 0;
	irq->target_vcpu = kvm_get_vcpu(kvm, target);
	spin_unlock(&irq->irq_lock);
}

/* not yet implemented */
void vgic_v2_enable(struct kvm_vcpu *vcpu)
{
}

int vgic_v2_map_resources(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	int ret = 0;

	if (vgic_ready(kvm))
		goto out;

	if (IS_VGIC_ADDR_UNDEF(dist->vgic_dist_base) ||
	    IS_VGIC_ADDR_UNDEF(dist->vgic_cpu_base)) {
		kvm_err("Need to set vgic cpu and dist addresses first\n");
		ret = -ENXIO;
		goto out;
	}

	/*
	 * Initialize the vgic if this hasn't already been done on demand by
	 * accessing the vgic state from userspace.
	 */
	ret = vgic_init(kvm);
	if (ret) {
		kvm_err("Unable to initialize VGIC dynamic data structures\n");
		goto out;
	}

	ret = vgic_register_dist_regions(kvm, dist->vgic_dist_base, VGIC_V2);
	if (ret) {
		kvm_err("Unable to register VGIC MMIO regions\n");
		goto out;
	}

	ret = kvm_phys_addr_ioremap(kvm, dist->vgic_cpu_base,
				    kvm_vgic_global_state.vcpu_base,
				    KVM_VGIC_V2_CPU_SIZE, true);
	if (ret) {
		kvm_err("Unable to remap VGIC CPU to VCPU\n");
		goto out;
	}

	dist->ready = true;

out:
	if (ret)
		kvm_vgic_destroy(kvm);
	return ret;
}

/**
 * vgic_v2_probe - probe for a GICv2 compatible interrupt controller in DT
 * @node:	pointer to the DT node
 *
 * Returns 0 if a GICv2 has been found, returns an error code otherwise
 */
int vgic_v2_probe(struct device_node *vgic_node)
{
	int ret;
	struct resource vctrl_res;
	struct resource vcpu_res;

	kvm_vgic_global_state.maint_irq = irq_of_parse_and_map(vgic_node, 0);
	if (!kvm_vgic_global_state.maint_irq) {
		kvm_err("error getting vgic maintenance irq from DT\n");
		ret = -ENXIO;
		goto out;
	}

	ret = of_address_to_resource(vgic_node, 2, &vctrl_res);
	if (ret) {
		kvm_err("Cannot obtain GICH resource\n");
		goto out;
	}

	kvm_vgic_global_state.vctrl_base = of_iomap(vgic_node, 2);
	if (!kvm_vgic_global_state.vctrl_base) {
		kvm_err("Cannot ioremap GICH\n");
		ret = -ENOMEM;
		goto out;
	}

	kvm_vgic_global_state.nr_lr =
		readl_relaxed(kvm_vgic_global_state.vctrl_base + GICH_VTR);
	kvm_vgic_global_state.nr_lr = (kvm_vgic_global_state.nr_lr & 0x3f) + 1;

	ret = create_hyp_io_mappings(kvm_vgic_global_state.vctrl_base,
				     kvm_vgic_global_state.vctrl_base +
					 resource_size(&vctrl_res),
				     vctrl_res.start);
	if (ret) {
		kvm_err("Cannot map VCTRL into hyp\n");
		goto out_unmap;
	}

	if (of_address_to_resource(vgic_node, 3, &vcpu_res)) {
		kvm_err("Cannot obtain GICV resource\n");
		ret = -ENXIO;
		goto out_unmap;
	}

	if (!PAGE_ALIGNED(vcpu_res.start)) {
		kvm_err("GICV physical address 0x%llx not page aligned\n",
			(unsigned long long)vcpu_res.start);
		ret = -ENXIO;
		goto out_unmap;
	}

	if (!PAGE_ALIGNED(resource_size(&vcpu_res))) {
		kvm_err("GICV size 0x%llx not a multiple of page size 0x%lx\n",
			(unsigned long long)resource_size(&vcpu_res),
			PAGE_SIZE);
		ret = -ENXIO;
		goto out_unmap;
	}

	kvm_vgic_global_state.can_emulate_gicv2 = true;
	kvm_register_vgic_device(KVM_DEV_TYPE_ARM_VGIC_V2);

	kvm_vgic_global_state.vcpu_base = vcpu_res.start;

	kvm_info("%s@%llx IRQ%d\n", vgic_node->name,
		 vctrl_res.start, kvm_vgic_global_state.maint_irq);

	kvm_vgic_global_state.type = VGIC_V2;
	kvm_vgic_global_state.max_gic_vcpus = VGIC_V2_MAX_CPUS;
	goto out;

out_unmap:
	iounmap(kvm_vgic_global_state.vctrl_base);
out:
	of_node_put(vgic_node);
	return ret;
}
