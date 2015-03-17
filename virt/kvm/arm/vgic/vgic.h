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
#ifndef __KVM_ARM_VGIC_NEW_H__
#define __KVM_ARM_VGIC_NEW_H__

#define PRODUCT_ID_KVM		0x4b	/* ASCII code K */
#define IMPLEMENTER_ARM		0x43b

#define VGIC_ADDR_UNDEF		(-1)
#define IS_VGIC_ADDR_UNDEF(_x)  ((_x) == VGIC_ADDR_UNDEF)

#define INTERRUPT_ID_BITS_SPIS	10
#define INTERRUPT_ID_BITS_ITS	16

struct vgic_irq *vgic_get_irq(struct kvm *kvm, struct kvm_vcpu *vcpu,
			      u32 intid);
struct kvm_vcpu *vgic_target_oracle(struct vgic_irq *irq);
int vgic_queue_irq(struct kvm *kvm, struct kvm_vcpu *vcpu, u32 intid,
		   bool enable, bool make_pending, u8 sgi_source_mask);

void vgic_v2_irq_change_affinity(struct kvm *kvm, u32 intid, u8 target);
void vgic_v2_process_maintenance(struct kvm_vcpu *vcpu);
void vgic_v2_fold_lr_state(struct kvm_vcpu *vcpu);
void vgic_v2_populate_lr(struct kvm_vcpu *vcpu, struct vgic_irq *irq, int lr);
void vgic_v2_set_underflow(struct kvm_vcpu *vcpu);
int vgic_v2_dist_access(struct kvm_vcpu *vcpu, bool is_write,
			int offset, int len, void *val);
int vgic_v2_has_attr_regs(struct kvm_device *dev, struct kvm_device_attr *attr);
void vgic_v2_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);
void vgic_v2_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);
void vgic_v2_enable(struct kvm_vcpu *vcpu);
int vgic_v2_probe(struct device_node *vgic_node);
int vgic_v2_map_resources(struct kvm *kvm);
int vgic_register_dist_regions(struct kvm *kvm, gpa_t dist_base_address,
			       enum vgic_type);

#ifdef CONFIG_KVM_ARM_VGIC_V3
void vgic_v3_irq_change_affinity(struct kvm *kvm, u32 intid, u64 mpidr);
void vgic_v3_process_maintenance(struct kvm_vcpu *vcpu);
void vgic_v3_fold_lr_state(struct kvm_vcpu *vcpu);
void vgic_v3_populate_lr(struct kvm_vcpu *vcpu, struct vgic_irq *irq, int lr);
void vgic_v3_set_underflow(struct kvm_vcpu *vcpu);
int vgic_v3_dist_access(struct kvm_vcpu *vcpu, bool is_write,
			int offset, int len, void *val);
int vgic_v3_redist_access(struct kvm_vcpu *vcpu, bool is_write,
			  int offset, int len, void *val);
void vgic_v3_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);
void vgic_v3_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);
void vgic_v3_enable(struct kvm_vcpu *vcpu);
int vgic_v3_probe(struct device_node *vgic_node);
int vgic_v3_map_resources(struct kvm *kvm);
int vgic_register_redist_regions(struct kvm *kvm, gpa_t dist_base_address);

int vits_init(struct kvm *kvm);
void vgic_enable_lpis(struct kvm_vcpu *vcpu);
struct vgic_irq *vgic_its_get_lpi(struct kvm *kvm, u32 intid);
void vits_destroy(struct kvm *kvm);
#else
static inline void vgic_v3_irq_change_affinity(struct kvm *kvm, u32 intid,
					       u64 mpidr)
{
}

static inline void vgic_v3_process_maintenance(struct kvm_vcpu *vcpu)
{
}

static inline void vgic_v3_fold_lr_state(struct kvm_vcpu *vcpu)
{
}

static inline void vgic_v3_populate_lr(struct kvm_vcpu *vcpu,
				       struct vgic_irq *irq, int lr)
{
}

static inline void vgic_v3_set_underflow(struct kvm_vcpu *vcpu)
{
}

static inline int vgic_v3_dist_access(struct kvm_vcpu *vcpu, bool is_write,
				      int offset, int len, void *val)
{
	return -ENXIO;
}

static inline int vgic_v3_redist_access(struct kvm_vcpu *vcpu, bool is_write,
					int offset, int len, void *val)
{
	return -ENXIO;
}

static inline
void vgic_v3_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr)
{
}

static inline
void vgic_v3_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr)
{
}

static inline void vgic_v3_enable(struct kvm_vcpu *vcpu)
{
}

static inline int vgic_v3_probe(struct device_node *vgic_node)
{
	return -ENODEV;
}

static inline int vgic_v3_map_resources(struct kvm *kvm)
{
	return -ENODEV;
}

static inline int vgic_register_redist_regions(struct kvm *kvm,
					       gpa_t dist_base_address)
{
	return -ENODEV;
}

static inline int vits_init(struct kvm *kvm)
{
	return 0;
}

static inline void vgic_enable_lpis(struct kvm_vcpu *vcpu)
{
	return;
}

static inline struct vgic_irq *vgic_its_get_lpi(struct kvm *kvm, u32 intid)
{
	return NULL;
}

static inline void vits_destroy(struct kvm *kvm)
{
	return;
}
#endif

void vgic_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);
void vgic_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcr);

int vgic_lazy_init(struct kvm *kvm);
int vgic_init(struct kvm *kvm);
int vits_init(struct kvm *kvm);
void kvm_register_vgic_device(unsigned long type);

#endif
