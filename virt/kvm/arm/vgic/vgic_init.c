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
#include <kvm/vgic/vgic.h>

void kvm_vgic_early_init(struct kvm *kvm)
{
}

int kvm_vgic_create(struct kvm *kvm, u32 type)
{
	return 0;
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

int kvm_vgic_hyp_init(void)
{
	return 0;
}

int kvm_vgic_addr(struct kvm *kvm, unsigned long type, u64 *addr, bool write)
{
	return 0;
}

int vgic_init(struct kvm *kvm)
{
	return 0;
}
