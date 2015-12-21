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

#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/kvm_host.h>
#include <kvm/vgic/vgic.h>
#include <asm/kvm_mmu.h>
#include "vgic.h"

void kvm_vgic_early_init(struct kvm *kvm)
{
}

/* CREATION */

/**
 * kvm_vgic_create: triggered by the instantiation of the VGIC device by
 * user space, either through the legacy ARM specific VM IOCTL (CREATE_IRQCHIP)
 * or through the generic VM IOCTL, KVM_CREATE_DEVICE API.
 * Completion can be tested by irqchip_in_kernel
 */
int kvm_vgic_create(struct kvm *kvm, u32 type)
{
	int i, vcpu_lock_idx = -1, ret;
	struct kvm_vcpu *vcpu;

	mutex_lock(&kvm->lock);

	if (irqchip_in_kernel(kvm)) {
		ret = -EEXIST;
		goto out;
	}

	/*
	 * This function is also called by the KVM_CREATE_IRQCHIP handler,
	 * which had no chance yet to check the availability of the GICv2
	 * emulation. So check this here again. KVM_CREATE_DEVICE does
	 * the proper checks already.
	 */
	if (type == KVM_DEV_TYPE_ARM_VGIC_V2 &&
		!kvm_vgic_global_state.can_emulate_gicv2) {
		ret = -ENODEV;
		goto out;
	}

	/*
	 * Any time a vcpu is run, vcpu_load is called which tries to grab the
	 * vcpu->mutex.  By grabbing the vcpu->mutex of all VCPUs we ensure
	 * that no other VCPUs are run while we create the vgic.
	 */
	ret = -EBUSY;
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!mutex_trylock(&vcpu->mutex))
			goto out_unlock;
		vcpu_lock_idx = i;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.has_run_once)
			goto out_unlock;
	}
	ret = 0;

	if (type == KVM_DEV_TYPE_ARM_VGIC_V2)
		kvm->arch.max_vcpus = VGIC_V2_MAX_CPUS;
	else
		kvm->arch.max_vcpus = VGIC_V3_MAX_CPUS;

	if (atomic_read(&kvm->online_vcpus) > kvm->arch.max_vcpus) {
		ret = -E2BIG;
		goto out_unlock;
	}

	kvm->arch.vgic.in_kernel = true;
	kvm->arch.vgic.vgic_model = type;

	/*
	 * kvm_vgic_global_state.vctrl_base is set on vgic probe (kvm_arch_init)
	 * it is stored in distributor struct for asm save/restore purpose
	 */
	kvm->arch.vgic.vctrl_base = kvm_vgic_global_state.vctrl_base;

	kvm->arch.vgic.vgic_dist_base = VGIC_ADDR_UNDEF;
	kvm->arch.vgic.vgic_cpu_base = VGIC_ADDR_UNDEF;
	kvm->arch.vgic.vgic_redist_base = VGIC_ADDR_UNDEF;

out_unlock:
	for (; vcpu_lock_idx >= 0; vcpu_lock_idx--) {
		vcpu = kvm_get_vcpu(kvm, vcpu_lock_idx);
		mutex_unlock(&vcpu->mutex);
	}

out:
	mutex_unlock(&kvm->lock);
	return ret;
}

void kvm_vgic_destroy(struct kvm *kvm)
{
}

void kvm_vgic_vcpu_early_init(struct kvm_vcpu *vcpu)
{
}

void kvm_vgic_vcpu_destroy(struct kvm_vcpu *vcpu)
{
}

int kvm_vgic_map_resources(struct kvm *kvm)
{
	return 0;
}

int vgic_init(struct kvm *kvm)
{
	return 0;
}

/* GENERIC PROBE */

static void vgic_init_maintenance_interrupt(void *info)
{
	enable_percpu_irq(kvm_vgic_global_state.maint_irq, 0);
}

static int vgic_cpu_notify(struct notifier_block *self,
			   unsigned long action, void *cpu)
{
	switch (action) {
	case CPU_STARTING:
	case CPU_STARTING_FROZEN:
		vgic_init_maintenance_interrupt(NULL);
		break;
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		disable_percpu_irq(kvm_vgic_global_state.maint_irq);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block vgic_cpu_nb = {
	.notifier_call = vgic_cpu_notify,
};

static irqreturn_t vgic_maintenance_handler(int irq, void *data)
{
	/*
	 * We cannot rely on the vgic maintenance interrupt to be
	 * delivered synchronously. This means we can only use it to
	 * exit the VM, and we perform the handling of EOIed
	 * interrupts on the exit path (see vgic_process_maintenance).
	 */
	return IRQ_HANDLED;
}

static const struct of_device_id vgic_ids[] = {
	{ .compatible = "arm,cortex-a15-gic",	.data = vgic_v2_probe, },
	{ .compatible = "arm,cortex-a7-gic",	.data = vgic_v2_probe, },
	{ .compatible = "arm,gic-400",		.data = vgic_v2_probe, },
	{ .compatible = "arm,gic-v3",		.data = vgic_v3_probe, },
	{},
};

/**
 * kvm_vgic_hyp_init: populates the kvm_vgic_global_state variable
 * according to the host GIC model. Accordingly calls either
 * vgic_v2/v3_probe which registers the KVM_DEVICE that can be
 * instantiated by a guest later on .
 */
int kvm_vgic_hyp_init(void)
{
	const struct of_device_id *matched_id;
	const int (*vgic_probe)(struct device_node *);
	struct device_node *vgic_node;
	int ret;

	vgic_node = of_find_matching_node_and_match(NULL,
						    vgic_ids, &matched_id);
	if (!vgic_node) {
		kvm_err("error: no compatible GIC node found\n");
		return -ENODEV;
	}

	vgic_probe = matched_id->data;
	ret = vgic_probe(vgic_node);
	if (ret)
		return ret;

	ret = request_percpu_irq(kvm_vgic_global_state.maint_irq,
				 vgic_maintenance_handler,
				 "vgic", kvm_get_running_vcpus());
	if (ret) {
		kvm_err("Cannot register interrupt %d\n",
			kvm_vgic_global_state.maint_irq);
		return ret;
	}

	ret = __register_cpu_notifier(&vgic_cpu_nb);
	if (ret) {
		kvm_err("Cannot register vgic CPU notifier\n");
		goto out_free_irq;
	}

	on_each_cpu(vgic_init_maintenance_interrupt, NULL, 1);

	return 0;

out_free_irq:
	free_percpu_irq(kvm_vgic_global_state.maint_irq,
			kvm_get_running_vcpus());
	return ret;
}
