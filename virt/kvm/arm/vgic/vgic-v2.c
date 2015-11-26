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

#include "vgic.h"

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

