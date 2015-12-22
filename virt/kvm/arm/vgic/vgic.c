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

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/list_sort.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/irqdesc.h>

#include "vgic.h"

struct vgic_global kvm_vgic_global_state;

/*
 * Locking order is always:
 *   vgic_cpu->ap_list_lock
 *     vgic_irq->irq_lock
 *
 * (that is, always take the ap_list_lock before the struct vgic_irq lock).
 *
 * When taking more than one ap_list_lock at the same time, always take the
 * lowest numbered VCPU's ap_list_lock first, so:
 *   vcpuX->vcpu_id < vcpuY->vcpu_id:
 *     spin_lock(vcpuX->arch.vgic_cpu.ap_list_lock);
 *     spin_lock(vcpuY->arch.vgic_cpu.ap_list_lock);
 */

static inline struct vgic_irq *vgic_its_get_lpi(struct kvm *kvm, u32 intid)
{
	return NULL;
}

struct vgic_irq *vgic_get_irq(struct kvm *kvm, struct kvm_vcpu *vcpu,
			      u32 intid)
{
	/* SGIs and PPIs */
	if (intid <= VGIC_MAX_PRIVATE)
		return &vcpu->arch.vgic_cpu.private_irqs[intid];

	/* SPIs */
	if (intid <= VGIC_MAX_SPI)
		return &kvm->arch.vgic.spis[intid - VGIC_NR_PRIVATE_IRQS];

	/* LPIs */
	if (intid >= VGIC_MIN_LPI)
		return vgic_its_get_lpi(kvm, intid);

	WARN(1, "Looking up struct vgic_irq for reserved INTID");
	return NULL;
}

/*
 * The order of items in the ap_lists defines how we'll pack things in LRs as
 * well, the first items in the list being the first things populated in the
 * LRs.
 *
 * A hard rule is that active interrupts can never be pushed out of the LRs
 * (and therefore take priority) since we cannot reliably trap on deactivation
 * of IRQs and therefore they have to be present in the LRs.
 *
 * Otherwise things should be sorted by the priority field and the GIC
 * hardware support will take care of preemption of priority groups etc.
 *
 * Return negative if "a" sorts before "b", 0 to preserve order, and positive
 * to sort "b" before "a".
 */
static int vgic_irq_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct vgic_irq *irqa = container_of(a, struct vgic_irq, ap_list);
	struct vgic_irq *irqb = container_of(b, struct vgic_irq, ap_list);
	bool penda, pendb;
	int ret;

	spin_lock(&irqa->irq_lock);
	spin_lock(&irqb->irq_lock);

	if (irqa->active || irqb->active) {
		ret = (int)irqb->active - (int)irqa->active;
		goto out;
	}

	penda = irqa->enabled && irqa->pending;
	pendb = irqb->enabled && irqb->pending;

	if (!penda || !pendb) {
		ret = (int)pendb - (int)penda;
		goto out;
	}

	/* Both pending and enabled, sort by priority */
	ret = irqa->priority - irqb->priority;
out:
	spin_unlock(&irqb->irq_lock);
	spin_unlock(&irqa->irq_lock);
	return ret;
}

/* Must be called with the ap_list_lock held */
static void vgic_sort_ap_list(struct kvm_vcpu *vcpu)
{
	list_sort(NULL, &vcpu->arch.vgic_cpu.ap_list_head, vgic_irq_cmp);
}

/*
 * Only valid injection if changing level for level-triggered IRQs or for a
 * rising edge.
 */
static bool vgic_validate_injection(struct vgic_irq *irq, bool level)
{
	switch (irq->config) {
	case VGIC_CONFIG_LEVEL:
		return irq->line_level != level;
	case VGIC_CONFIG_EDGE:
		return level;
	default:
		BUG();
	}
}

static void vgic_update_irq_pending(struct kvm *kvm, struct kvm_vcpu *vcpu,
				    u32 intid, bool level)
{
	struct vgic_irq *irq = vgic_get_irq(kvm, vcpu, intid);

	BUG_ON(in_interrupt());

retry:
	spin_lock(&irq->irq_lock);

	if (!vgic_validate_injection(irq, level)) {
		/* Nothing to see here, move along... */
		spin_unlock(&irq->irq_lock);
		return;
	}

	if (irq->config == VGIC_CONFIG_LEVEL) {
		irq->line_level = level;
		irq->pending = level || irq->soft_pending;
	} else {
		irq->pending = true;
	}

	if (irq->vcpu || !(irq->pending && irq->enabled)) {
		/*
		 * If this IRQ is already on a VCPU's ap_list, then it
		 * cannot be moved or modified and there is no more work for
		 * us to do.
		 *
		 * Otherwise, if the irq is not pending and enabled, it does
		 * not need to be inserted into an ap_list and there is also
		 * no more work for us to do.
		 *
		 * In both cases, unlock and return, having set the pending
		 * state of the IRQ.
		 */
		spin_unlock(&irq->irq_lock);
	} else {
		struct kvm_vcpu *vcpu = irq->target_vcpu;

		/*
		 * We must unlock the irq lock to take the ap_list_lock where
		 * we are going to insert this new pending interrupt.
		 */
		spin_unlock(&irq->irq_lock);

		/* someone can do stuff here, which we re-check below */

		spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);
		spin_lock(&irq->irq_lock);

		/*
		 * Did something change behind our backs?
		 *
		 * There are two cases:
		 * 1) The irq became pending or active behind our backs and
		 *    the irq->vcpu field was set correspondingly when putting
		 *    the irq on an ap_list.
		 * 2) Someone changed the affinity on this irq behind our
		 *    backs and we are now holding the wrong ap_list_lock.
		 *
		 * In both cases, drop locks and simply retry.
		 */
		if (irq->vcpu || irq->target_vcpu != vcpu) {
			spin_unlock(&irq->irq_lock);
			spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
			goto retry;
		}

		list_add_tail(&irq->ap_list, &vcpu->arch.vgic_cpu.ap_list_head);
		irq->vcpu = vcpu;

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);

		kvm_vcpu_kick(vcpu);
	}
}

int vgic_queue_irq(struct kvm *kvm, struct kvm_vcpu *vcpu, u32 intid,
		   bool enable, bool make_pending, u8 sgi_source_mask)
{
	struct vgic_irq *irq = vgic_get_irq(kvm, vcpu, intid);
	struct kvm_vcpu *target_vcpu;
	bool queue, injected = false;

retry:
	spin_lock(&irq->irq_lock);

	if (enable)
		irq->enabled = true;

	if (make_pending) {
		irq->pending = true;
		if (irq->config == VGIC_CONFIG_LEVEL)
			irq->soft_pending = true;
	}

	queue = irq->enabled && irq->pending;

	if (intid < VGIC_NR_SGIS && sgi_source_mask)
		irq->source |= sgi_source_mask;

	target_vcpu = vgic_target_oracle(irq);

	spin_unlock(&irq->irq_lock);

	if (!queue)
		return 0;

	spin_lock(&target_vcpu->arch.vgic_cpu.ap_list_lock);
	spin_lock(&irq->irq_lock);

	if (!irq->vcpu &&			/* not yet queued */
	    irq->target_vcpu == target_vcpu &&	/* still the right VCPU */
	    irq->enabled && irq->pending) {	/* ready to be injected */
		irq->vcpu = target_vcpu;
		list_add_tail(&irq->ap_list,
			      &target_vcpu->arch.vgic_cpu.ap_list_head);
	}

	if (irq->vcpu)
		injected = true;

	spin_unlock(&irq->irq_lock);
	spin_unlock(&target_vcpu->arch.vgic_cpu.ap_list_lock);

	if (!injected)
		goto retry;

	kvm_vcpu_kick(target_vcpu);

	return 0;
}

/**
 * kvm_vgic_inject_irq - Inject an IRQ from a device to the vgic
 * @kvm:     The VM structure pointer
 * @cpuid:   The CPU for PPIs
 * @intid:   The INTID to inject a new state to.
 *           must not be mapped to a HW interrupt.
 * @level:   Edge-triggered:  true:  to trigger the interrupt
 *			      false: to ignore the call
 *	     Level-sensitive  true:  raise the input signal
 *			      false: lower the input signal
 *
 * The GIC is not concerned with devices being active-LOW or active-HIGH for
 * level-sensitive interrupts.  You can think of the level parameter as 1
 * being HIGH and 0 being LOW and all devices being active-HIGH.
 */
int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, unsigned int intid,
			bool level)
{
	struct kvm_vcpu *vcpu;
	int ret;

	ret = vgic_lazy_init(kvm);
	if (ret)
		return ret;

	vcpu = kvm_get_vcpu(kvm, cpuid);
	vgic_update_irq_pending(kvm, vcpu, intid, level);

	return 0;
}

/**
 * kvm_vgic_inject_mapped_irq - Inject a hardware mapped IRQ to the vgic
 * @kvm:     The VM structure pointer
 * @cpuid:   The CPU for PPIs
 * @irq_num: The INTID to inject a new state to.
 * @level:   Edge-triggered:  true:  to trigger the interrupt
 *			      false: to ignore the call
 *	     Level-sensitive  true:  raise the input signal
 *			      false: lower the input signal
 *
 * The GIC is not concerned with devices being active-LOW or active-HIGH for
 * level-sensitive interrupts.  You can think of the level parameter as 1
 * being HIGH and 0 being LOW and all devices being active-HIGH.
 */
int kvm_vgic_inject_mapped_irq(struct kvm *kvm, int cpuid, unsigned int intid,
			       bool level)
{
	struct kvm_vcpu *vcpu;
	int ret;

	ret = vgic_lazy_init(kvm);
	if (ret)
		return ret;

	vcpu = kvm_get_vcpu(kvm, cpuid);
	vgic_update_irq_pending(kvm, vcpu, intid, level);

	return 0;
}

struct irq_phys_map *kvm_vgic_map_phys_irq(struct kvm_vcpu *vcpu,
					   u32 virt_irq, u32 intid)
{
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, virt_irq);
	struct irq_desc *desc;
	struct irq_data *data;

	BUG_ON(!irq);

	desc = irq_to_desc(intid);
	if (!desc) {
		kvm_err("%s: no interrupt descriptor\n", __func__);
		return NULL;
	}

	data = irq_desc_get_irq_data(desc);
	while (data->parent_data)
		data = data->parent_data;

	spin_lock(&irq->irq_lock);

	irq->hw = true;
	irq->hwintid = data->hwirq;

	spin_unlock(&irq->irq_lock);

	return NULL;
}

int kvm_vgic_unmap_phys_irq(struct kvm_vcpu *vcpu, struct irq_phys_map *map,
			    u32 intid)
{
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid);

	BUG_ON(!irq);

	spin_lock(&irq->irq_lock);

	irq->hw = false;
	irq->hwintid = 0;

	spin_unlock(&irq->irq_lock);

	return 0;
}

/**
 * kvm_vgic_target_oracle - compute the target vcpu for an irq
 *
 * @irq:	The irq to route. Must be already locked.
 *
 * Based on the current state of the interrupt (enabled, pending,
 * active, vcpu and target_vcpu), compute the next vcpu this should be
 * given to. Return NULL if this shouldn't be injected at all.
 */
struct kvm_vcpu *vgic_target_oracle(struct vgic_irq *irq)
{
	/* If the interrupt is active, it must stay on the current vcpu */
	if (irq->active)
		return irq->vcpu;

	/* If enabled and pending, it can migrate to a new one */
	if (irq->enabled && irq->pending)
		return irq->target_vcpu;

	/* Otherwise, it is considered idle */
	return NULL;
}

/**
 * vgic_prune_ap_list - Remove non-relevant interrupts from the list
 *
 * @vcpu: The VCPU pointer
 *
 * Go over the list of "interesting" interrupts, and prune those that we
 * won't have to consider in the near future.
 */
static void vgic_prune_ap_list(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq, *tmp;

retry:
	spin_lock(&vgic_cpu->ap_list_lock);

	list_for_each_entry_safe(irq, tmp, &vgic_cpu->ap_list_head, ap_list) {
		struct kvm_vcpu *target_vcpu, *vcpuA, *vcpuB;

		spin_lock(&irq->irq_lock);

		BUG_ON(vcpu != irq->vcpu);

		target_vcpu = vgic_target_oracle(irq);

		if (!target_vcpu) {
			/*
			 * We don't need to process this interrupt any
			 * further, move it off the list.
			 */
			list_del_init(&irq->ap_list);
			irq->vcpu = NULL;
			spin_unlock(&irq->irq_lock);
			continue;
		}

		if (target_vcpu == vcpu) {
			/* We're on the right CPU */
			spin_unlock(&irq->irq_lock);
			continue;
		}

		/* This interrupt looks like it has to be migrated. */

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vgic_cpu->ap_list_lock);

		/*
		 * Ensure locking order by always locking the smallest
		 * ID first.
		 */
		if (vcpu->vcpu_id < target_vcpu->vcpu_id) {
			vcpuA = vcpu;
			vcpuB = target_vcpu;
		} else {
			vcpuA = target_vcpu;
			vcpuB = vcpu;
		}

		spin_lock(&vcpuA->arch.vgic_cpu.ap_list_lock);
		spin_lock(&vcpuB->arch.vgic_cpu.ap_list_lock);
		spin_lock(&irq->irq_lock);

		/*
		 * If the affinity has been preserved, move the
		 * interrupt around. Otherwise, it means things have
		 * changed while the interrupt was unlocked, and we
		 * need to replay this.
		 *
		 * In all cases, we cannot trust the list not to have
		 * changed, so we restart from the beginning.
		 */
		if (target_vcpu == vgic_target_oracle(irq)) {
			struct vgic_cpu *new_cpu = &target_vcpu->arch.vgic_cpu;

			list_del_init(&irq->ap_list);
			irq->vcpu = target_vcpu;
			list_add_tail(&irq->ap_list, &new_cpu->ap_list_head);
		}

		spin_unlock(&irq->irq_lock);
		spin_unlock(&vcpuB->arch.vgic_cpu.ap_list_lock);
		spin_unlock(&vcpuA->arch.vgic_cpu.ap_list_lock);
		goto retry;
	}

	spin_unlock(&vgic_cpu->ap_list_lock);
}

static inline void vgic_process_maintenance_interrupt(struct kvm_vcpu *vcpu)
{
	if (kvm_vgic_global_state.type == VGIC_V2)
		vgic_v2_process_maintenance(vcpu);
	else
		vgic_v3_process_maintenance(vcpu);
}

static inline void vgic_fold_lr_state(struct kvm_vcpu *vcpu)
{
	if (kvm_vgic_global_state.type == VGIC_V2)
		vgic_v2_fold_lr_state(vcpu);
	else
		vgic_v3_fold_lr_state(vcpu);
}

/* requires the ap_lock to be held */
static inline void vgic_populate_lr(struct kvm_vcpu *vcpu,
				    struct vgic_irq *irq, int lr)
{
	if (kvm_vgic_global_state.type == VGIC_V2)
		vgic_v2_populate_lr(vcpu, irq, lr);
	else
		vgic_v3_populate_lr(vcpu, irq, lr);
}

static inline void vgic_set_underflow(struct kvm_vcpu *vcpu)
{
	if (kvm_vgic_global_state.type == VGIC_V2)
		vgic_v2_set_underflow(vcpu);
	else
		vgic_v3_set_underflow(vcpu);
}

void vgic_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr)
{
	if (kvm_vgic_global_state.type == VGIC_V2)
		vgic_v2_set_vmcr(vcpu, vmcr);
	else
		vgic_v3_set_vmcr(vcpu, vmcr);
}

void vgic_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr)
{
	if (kvm_vgic_global_state.type == VGIC_V2)
		vgic_v2_get_vmcr(vcpu, vmcr);
	else
		vgic_v3_get_vmcr(vcpu, vmcr);
}

static int compute_ap_list_depth(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq;
	int count = 0;

	list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list) {
		spin_lock(&irq->irq_lock);
		/* GICv2 SGIs can count for more than one... */
		if (irq->intid < VGIC_NR_SGIS && irq->source)
			count += hweight8(irq->source);
		else
			count++;
		spin_unlock(&irq->irq_lock);
	}
	return count;
}

/* requires the vcpu ap_lock to be held */
static void vgic_populate_lrs(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	u32 model = vcpu->kvm->arch.vgic.vgic_model;
	struct vgic_irq *irq;
	int count = 0;

	if (compute_ap_list_depth(vcpu) > vcpu->arch.vgic_cpu.nr_lr) {
		vgic_set_underflow(vcpu);
		vgic_sort_ap_list(vcpu);
	}

	list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list) {
		spin_lock(&irq->irq_lock);

		if (unlikely(vgic_target_oracle(irq) != vcpu))
			goto next;

		/*
		 * If we get an SGI with multiple sources, try to get
		 * them in all at once.
		 */
		if (model == KVM_DEV_TYPE_ARM_VGIC_V2 &&
		    irq->intid < VGIC_NR_SGIS) {
			while (irq->source && count < vcpu->arch.vgic_cpu.nr_lr)
				vgic_populate_lr(vcpu, irq, count++);
		} else {
			vgic_populate_lr(vcpu, irq, count++);
		}

next:
		spin_unlock(&irq->irq_lock);

		if (count == vcpu->arch.vgic_cpu.nr_lr)
			break;
	}

	vcpu->arch.vgic_cpu.used_lrs = count;

	/* Nuke remaining LRs */
	for ( ; count < vcpu->arch.vgic_cpu.nr_lr; count++)
		vgic_populate_lr(vcpu, NULL, count);
}

void kvm_vgic_sync_hwstate(struct kvm_vcpu *vcpu)
{
	vgic_process_maintenance_interrupt(vcpu);
	vgic_fold_lr_state(vcpu);
	vgic_prune_ap_list(vcpu);
}

void kvm_vgic_flush_hwstate(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->arch.vgic_cpu.ap_list_lock);
	vgic_populate_lrs(vcpu);
	spin_unlock(&vcpu->arch.vgic_cpu.ap_list_lock);
}

int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq;
	int pending = 0;

	spin_lock(&vgic_cpu->ap_list_lock);

	list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list) {
		pending |= irq->pending && irq->enabled;
	}

	spin_unlock(&vgic_cpu->ap_list_lock);

	return pending;
}

bool kvm_vgic_map_is_active(struct kvm_vcpu *vcpu, u32 intid)
{
	struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid);
	bool map_is_active;

	spin_lock(&irq->irq_lock);
	map_is_active = irq->hw && irq->active;
	spin_unlock(&irq->irq_lock);

	return map_is_active;
}
