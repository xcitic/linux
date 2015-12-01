/*
 * VGIC MMIO handling functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <kvm/vgic/vgic.h>
#include <linux/bitops.h>
#include <linux/irqchip/arm-gic.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <asm/kvm_emulate.h>

#include "vgic.h"
#include "vgic_mmio.h"

void write_mask32(u32 value, int offset, int len, void *val)
{
	value = cpu_to_le32(value) >> (offset * 8);
	memcpy(val, &value, len);
}

u32 mask32(u32 origvalue, int offset, int len, const void *val)
{
	origvalue &= ~((BIT_ULL(len) - 1) << (offset * 8));
	memcpy((char *)&origvalue + (offset * 8), val, len);
	return origvalue;
}

#ifdef CONFIG_KVM_ARM_VGIC_V3
void write_mask64(u64 value, int offset, int len, void *val)
{
	value = cpu_to_le64(value) >> (offset * 8);
	memcpy(val, &value, len);
}

/* FIXME: I am clearly misguided here, there must be some saner way ... */
u64 mask64(u64 origvalue, int offset, int len, const void *val)
{
	origvalue &= ~((BIT_ULL(len) - 1) << (offset * 8));
	memcpy((char *)&origvalue + (offset * 8), val, len);
	return origvalue;
}
#endif

int vgic_mmio_read_raz(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
		       gpa_t addr, int len, void *val)
{
	memset(val, 0, len);

	return 0;
}

int vgic_mmio_write_wi(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
		       gpa_t addr, int len, const void *val)
{
	return 0;
}

static int vgic_mmio_read_v2_misc(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *this,
				  gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 value;

	switch ((addr - iodev->base_addr) & ~3) {
	case 0x0:
		value = vcpu->kvm->arch.vgic.enabled ? GICD_ENABLE : 0;
		break;
	case 0x4:
		value = vcpu->kvm->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;
		value = (value >> 5) - 1;
		value |= (atomic_read(&vcpu->kvm->online_vcpus) - 1) << 5;
		break;
	case 0x8:
		value = (PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0);
		break;
	default:
		return 0;
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_v2_misc(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	/*
	 * GICD_TYPER and GICD_IIDR are read-only, the upper three bytes of
	 * GICD_CTLR are reserved.
	 */
	if (addr - iodev->base_addr >= 1)
		return 0;

	vcpu->kvm->arch.vgic.enabled = (*(u32 *)val) ? true : false;
	/* TODO: is there anything to trigger at this point? */

	return 0;
}

/*
 * Read accesses to both GICD_ICENABLER and GICD_ISENABLER return the value
 * of the enabled bit, so there is only one function for both here.
 */
static int vgic_mmio_read_enable(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *this,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->enabled)
			value |= (1U << i);
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_senable(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8)
		vgic_queue_irq(vcpu->kvm, vcpu, intid + i, true, false, 0);

	return 0;
}

static int vgic_mmio_write_cenable(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->enabled = false;
		/* TODO: Does the exit/entry code take care of "unqueuing"? */

		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_read_pending(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *this,
				  gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		if (irq->pending)
			value |= (1U << i);
		spin_unlock(&irq->irq_lock);
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_spending(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8)
		vgic_queue_irq(vcpu->kvm, vcpu, intid + i, false, true, 0);

	return 0;
}

static int vgic_mmio_write_cpending(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		if (irq->config == VGIC_CONFIG_LEVEL) {
			irq->soft_pending = false;
			irq->pending = irq->line_level;
		} else {
			irq->pending = false;
		}
		/* TODO: Does the exit/entry code take care of "unqueuing"? */

		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_read_active(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *this,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	/* Loop over all IRQs affected by this read */
	for (i = 0; i < len * 8; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		if (irq->active)
			value |= (1U << i);
		spin_unlock(&irq->irq_lock);
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_cactive(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->active = false;
		/* TODO: Anything more to do? Does flush/sync cover this? */

		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_write_sactive(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 8;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for_each_set_bit(i, val, len * 8) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);

		irq->active = true;
		/* TODO: Anything more to do? Does flush/sync cover this? */

		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_read_priority(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		((u8 *)val)[i] = irq->priority;
	}

	return 0;
}

static int vgic_mmio_write_priority(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->priority = ((u8 *)val)[i];
		spin_unlock(&irq->irq_lock);
	}

	return 0;
}

static int vgic_mmio_read_config(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *this,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 4;
	u32 value = 0;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len * 4; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (irq->config == VGIC_CONFIG_EDGE)
			value |= (2U << (i * 2));
	}

	write_mask32(value, addr & 3, len, val);
	return 0;
}

static int vgic_mmio_write_config(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *this,
				  gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr) * 4;
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len * 4; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		if (intid + i < 16)
			continue;

		/*
		 * The spec says that interrupts must be disabled before
		 * changing the configuration to avoid UNDEFINED behaviour.
		 * Is this sufficient in our case? Do we quickly enough remove
		 * the IRQ from the ap_list to safely do the config change?
		 * Will even a disabled interrupt in an ap_list cause us
		 * headaches if we change the configuration?
		 */
		spin_lock(&irq->irq_lock);
		if (test_bit(i * 2 + 1, val))
			irq->config = VGIC_CONFIG_EDGE;
		else
			irq->config = VGIC_CONFIG_LEVEL;
		spin_unlock(&irq->irq_lock);
	}

	return 0;
}

static int vgic_mmio_read_target(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *this,
				 gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	if (iodev->redist_vcpu)
		vcpu = iodev->redist_vcpu;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		((u8 *)val)[i] = irq->targets;
	}

	return 0;
}

static int vgic_mmio_write_target(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *this,
				  gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	/* GICD_ITARGETSR[0-7] are read-only */
	if (intid < VGIC_NR_PRIVATE_IRQS)
		return 0;

	for (i = 0; i < len; i++)
		vgic_v2_irq_change_affinity(vcpu->kvm, intid + i,
					    ((u8 *)val)[i]);

	return 0;
}

static int vgic_mmio_write_sgir(struct kvm_vcpu *source_vcpu,
				struct kvm_io_device *this,
				gpa_t addr, int len, const void *val)
{
	int nr_vcpus = atomic_read(&source_vcpu->kvm->online_vcpus);
	u32 value = *(u32 *)val;
	int intid = value & 0xf;
	int targets = (value >> 16) & 0xff;
	int mode = (value >> 24) & 0x03;
	int c;
	struct kvm_vcpu *vcpu;

	switch (mode) {
	case 0x0:		/* as specified by targets */
		break;
	case 0x1:
		targets = (1U << nr_vcpus) - 1;			/* all, ... */
		targets &= ~(1U << source_vcpu->vcpu_id);	/* but self */
		break;
	case 0x2:		/* this very vCPU only */
		targets = (1U << source_vcpu->vcpu_id);
		break;
	case 0x3:		/* reserved */
		break;
	}

	kvm_for_each_vcpu(c, vcpu, source_vcpu->kvm) {
		if (!(targets & (1U << c)))
			continue;

		vgic_queue_irq(source_vcpu->kvm, vcpu, intid, false, true,
			       (1U << source_vcpu->vcpu_id));
	}

	return 0;
}

static int vgic_mmio_read_sgipend(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *this,
				  gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		((u8 *)val)[i] = irq->source;
		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_write_sgipendc(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->source &= ~((u8 *)val)[i];
		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

static int vgic_mmio_write_sgipends(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 intid = (addr - iodev->base_addr);
	int i;

	for (i = 0; i < len; i++) {
		struct vgic_irq *irq = vgic_get_irq(vcpu->kvm, vcpu, intid + i);

		spin_lock(&irq->irq_lock);
		irq->source |= ((u8 *)val)[i];
		spin_unlock(&irq->irq_lock);
	}
	return 0;
}

/*****************************/
/* GICv3 emulation functions */
/*****************************/
#ifdef CONFIG_KVM_ARM_VGIC_V3

static int vgic_mmio_read_v3_misc(struct kvm_vcpu *vcpu,
				  struct kvm_io_device *this,
				  gpa_t addr, int len, void *val)
{
	/* TODO: implement */
	return 0;
}

static int vgic_mmio_write_v3_misc(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, const void *val)
{
	/* TODO: implement */
	return 0;
}

static int vgic_mmio_read_v3r_misc(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, void *val)
{
	/* TODO: implement for ITS support */
	return vgic_mmio_read_raz(vcpu, this, addr, len, val);
}

static int vgic_mmio_write_v3r_misc(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	/* TODO: implement for ITS support */
	return vgic_mmio_write_wi(vcpu, this, addr, len, val);
}

static int vgic_mmio_read_v3r_iidr(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, void *val)
{
	return 0;
}

static int vgic_mmio_read_v3r_typer(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, void *val)
{
	/* TODO: implement */
	return 0;
}

static int vgic_mmio_read_v3r_propbase(struct kvm_vcpu *vcpu,
				       struct kvm_io_device *this,
				       gpa_t addr, int len, void *val)
{
	/* TODO: implement */
	return 0;
}

static int vgic_mmio_write_v3r_propbase(struct kvm_vcpu *vcpu,
				        struct kvm_io_device *this,
				        gpa_t addr, int len, const void *val)
{
	/* TODO: implement */
	return 0;
}

static int vgic_mmio_read_v3r_pendbase(struct kvm_vcpu *vcpu,
				       struct kvm_io_device *this,
				       gpa_t addr, int len, void *val)
{
	/* TODO: implement */
	return 0;
}

static int vgic_mmio_write_v3r_pendbase(struct kvm_vcpu *vcpu,
				        struct kvm_io_device *this,
				        gpa_t addr, int len, const void *val)
{
	/* TODO: implement */
	return 0;
}
#endif

/*
 * The GICv3 per-IRQ registers are split to control PPIs and SGIs in the
 * redistributors, while SPIs are covered by registers in the distributor
 * block. Trying to set private IRQs in this block gets ignored.
 * We take some special care here to fix the calculation of the register
 * offset.
 */
#define REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(name, read_ops, write_ops, bpi) \
	{.reg_offset = name, .bits_per_irq = 0, \
	 .len = (bpi * VGIC_NR_PRIVATE_IRQS) / 8, \
	 .ops.read = vgic_mmio_read_raz, .ops.write = vgic_mmio_write_wi, }, \
	{.reg_offset = name, .bits_per_irq = bpi, .len = 0, \
	 .ops.read = read_ops, .ops.write = write_ops, }

struct vgic_register_region vgic_v2_dist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_CTRL,
		vgic_mmio_read_v2_misc, vgic_mmio_write_v2_misc, 12),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_IGROUP,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_SET,
		vgic_mmio_read_enable, vgic_mmio_write_senable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_CLEAR,
		vgic_mmio_read_enable, vgic_mmio_write_cenable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_SET,
		vgic_mmio_read_pending, vgic_mmio_write_spending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_CLEAR,
		vgic_mmio_read_pending, vgic_mmio_write_cpending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_SET,
		vgic_mmio_read_active, vgic_mmio_write_sactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_CLEAR,
		vgic_mmio_read_active, vgic_mmio_write_cactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PRI,
		vgic_mmio_read_priority, vgic_mmio_write_priority, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_TARGET,
		vgic_mmio_read_target, vgic_mmio_write_target, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_CONFIG,
		vgic_mmio_read_config, vgic_mmio_write_config, 2),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SOFTINT,
		vgic_mmio_read_raz, vgic_mmio_write_sgir, 4),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_CLEAR,
		vgic_mmio_read_sgipend, vgic_mmio_write_sgipendc, 16),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_SET,
		vgic_mmio_read_sgipend, vgic_mmio_write_sgipends, 16),
};

#ifdef CONFIG_KVM_ARM_VGIC_V3
struct vgic_register_region vgic_v3_dist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICD_CTLR,
		vgic_mmio_read_v3_misc, vgic_mmio_write_v3_misc, 16),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IGROUPR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ISENABLER,
		vgic_mmio_read_enable, vgic_mmio_write_senable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICENABLER,
		vgic_mmio_read_enable, vgic_mmio_write_cenable, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ISPENDR,
		vgic_mmio_read_pending, vgic_mmio_write_spending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICPENDR,
		vgic_mmio_read_pending, vgic_mmio_write_cpending, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ISACTIVER,
		vgic_mmio_read_active, vgic_mmio_write_sactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICACTIVER,
		vgic_mmio_read_active, vgic_mmio_write_cactive, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IPRIORITYR,
		vgic_mmio_read_priority, vgic_mmio_write_priority, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ITARGETSR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_ICFGR,
		vgic_mmio_read_config, vgic_mmio_write_config, 2),
	REGISTER_DESC_WITH_BITS_PER_IRQ_SHARED(GICD_IGRPMODR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 1),
};

struct vgic_register_region vgic_v3_redist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICR_CTLR,
		vgic_mmio_read_v3r_misc, vgic_mmio_write_v3r_misc, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_IIDR,
		vgic_mmio_read_v3r_iidr, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_TYPER,
		vgic_mmio_read_v3r_typer, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_PROPBASER,
		vgic_mmio_read_v3r_propbase, vgic_mmio_write_v3r_propbase, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_PENDBASER,
		vgic_mmio_read_v3r_pendbase, vgic_mmio_write_v3r_pendbase, 8),
};

struct vgic_register_region vgic_v3_private_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICR_IGROUPR0,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ISENABLER0,
		vgic_mmio_read_enable, vgic_mmio_write_senable, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ICENABLER0,
		vgic_mmio_read_enable, vgic_mmio_write_cenable, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ISPENDR0,
		vgic_mmio_read_pending, vgic_mmio_write_spending, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ICPENDR0,
		vgic_mmio_read_pending, vgic_mmio_write_cpending, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ISACTIVER0,
		vgic_mmio_read_active, vgic_mmio_write_sactive, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_ICACTIVER0,
		vgic_mmio_read_active, vgic_mmio_write_cactive, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_IPRIORITYR0,
		vgic_mmio_read_priority, vgic_mmio_write_priority, 32),
	REGISTER_DESC_WITH_LENGTH(GICR_ICFGR0,
		vgic_mmio_read_config, vgic_mmio_write_config, 8),
	REGISTER_DESC_WITH_LENGTH(GICR_IGRPMODR0,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GICR_NSACR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
};
#endif

/*
 * Using kvm_io_bus_* to access GIC registers directly from userspace has
 * issues, so we provide our own dispatcher function for that purpose here.
 */
static int vgic_mmio_access(struct kvm_vcpu *vcpu,
			    struct vgic_register_region *region, int nr_regions,
			    bool is_write, int offset, int len, void *val)
{
	int i;
	struct vgic_io_device dev;

	for (i = 0; i < nr_regions; i++) {
		int reg_size = region[i].len;

		if (!reg_size)
			reg_size = (region[i].bits_per_irq * 1024) / 8;

		if ((offset < region[i].reg_offset) ||
		    (offset + len > region[i].reg_offset + reg_size))
			continue;

		dev.base_addr	= region[i].reg_offset;
		dev.redist_vcpu	= vcpu;

		if (is_write)
			return region[i].ops.write(vcpu, &dev.dev,
						   offset, len, val);
		else
			return region[i].ops.read(vcpu, &dev.dev,
						  offset, len, val);
	}

	return -ENODEV;
}

int vgic_v2_dist_access(struct kvm_vcpu *vcpu, bool is_write,
			int offset, int len, void *val)
{
	return vgic_mmio_access(vcpu, vgic_v2_dist_registers,
				ARRAY_SIZE(vgic_v2_dist_registers),
				is_write, offset, len, val);
}

#ifdef CONFIG_KVM_ARM_VGIC_V3
int vgic_v3_dist_access(struct kvm_vcpu *vcpu, bool is_write,
			int offset, int len, void *val)
{
	return vgic_mmio_access(vcpu, vgic_v3_dist_registers,
				ARRAY_SIZE(vgic_v3_dist_registers),
				is_write, offset, len, val);
}

int vgic_v3_redist_access(struct kvm_vcpu *vcpu, bool is_write,
			  int offset, int len, void *val)
{
	return vgic_mmio_access(vcpu, vgic_v3_redist_registers,
				ARRAY_SIZE(vgic_v3_redist_registers),
				is_write, offset, len, val);
}
#endif

int register_reg_region(struct kvm *kvm, struct kvm_vcpu *vcpu,
			struct vgic_register_region *reg_desc,
			struct vgic_io_device *region,
			int nr_irqs, bool offset_private)
{
	int bpi = reg_desc->bits_per_irq;
	int offset = 0;
	int len, ret;

	region->base_addr	+= reg_desc->reg_offset;
	region->redist_vcpu	= vcpu;

	kvm_iodevice_init(&region->dev, &reg_desc->ops);

	if (bpi) {
		len = (bpi * nr_irqs) / 8;
		if (offset_private)
			offset = (bpi * VGIC_NR_PRIVATE_IRQS) / 8;
	} else {
		len = reg_desc->len;
	}

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
				      region->base_addr + offset,
				      len - offset, &region->dev);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

int vgic_register_dist_regions(struct kvm *kvm, gpa_t dist_base_address,
			       enum vgic_type type)
{
	struct vgic_io_device *regions;
	struct vgic_register_region *reg_desc;
	int nr_regions;
	int nr_irqs = kvm->arch.vgic.nr_spis + VGIC_NR_PRIVATE_IRQS;
	int i;
	int ret = 0;

	switch (type) {
	case VGIC_V2:
		reg_desc = vgic_v2_dist_registers;
		nr_regions = ARRAY_SIZE(vgic_v2_dist_registers);
		break;
#ifdef CONFIG_KVM_ARM_VGIC_V3
	case VGIC_V3:
		reg_desc = vgic_v3_dist_registers;
		nr_regions = ARRAY_SIZE(vgic_v3_dist_registers);
		break;
#endif
	default:
		BUG_ON(1);
	}

	regions = kmalloc_array(nr_regions, sizeof(struct vgic_io_device),
				GFP_KERNEL);
	if (!regions)
		return -ENOMEM;

	for (i = 0; i < nr_regions; i++) {
		regions[i].base_addr	= dist_base_address;

		ret = register_reg_region(kvm, NULL, reg_desc, regions + i,
					  nr_irqs, type == VGIC_V3);
		if (ret)
			break;

		reg_desc++;
	}

	if (ret) {
		mutex_lock(&kvm->slots_lock);
		for (i--; i >= 0; i--)
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
						  &regions[i].dev);
		mutex_unlock(&kvm->slots_lock);
	} else {
		kvm->arch.vgic.dist_iodevs = regions;
	}

	return ret;
}

#ifdef CONFIG_KVM_ARM_VGIC_V3
int vgic_register_redist_regions(struct kvm *kvm, gpa_t redist_base_address)
{
	int nr_vcpus = atomic_read(&kvm->online_vcpus);
	int nr_regions = ARRAY_SIZE(vgic_v3_redist_registers) +
			 ARRAY_SIZE(vgic_v3_private_registers);
	struct kvm_vcpu *vcpu;
	struct vgic_io_device *regions, *region;
	int c, i, ret = 0;

	regions = kmalloc(sizeof(struct vgic_io_device) * nr_regions * nr_vcpus,
			  GFP_KERNEL);
	if (!regions)
		return -ENOMEM;

	kvm_for_each_vcpu(c, vcpu, kvm) {
		region = &regions[c * nr_regions];
		for (i = 0; i < ARRAY_SIZE(vgic_v3_redist_registers); i++) {
			region->base_addr = redist_base_address;
			region->base_addr += c * 2 * SZ_64K;

			ret = register_reg_region(kvm, vcpu,
						  vgic_v3_redist_registers + i,
						  region, VGIC_NR_PRIVATE_IRQS,
						  false);
			if (ret)
				break;
			region++;
		}
		if (ret)
			break;

		for (i = 0; i < ARRAY_SIZE(vgic_v3_private_registers); i++) {
			region->base_addr = redist_base_address;
			region->base_addr += c * 2 * SZ_64K + SZ_64K;
			ret = register_reg_region(kvm, vcpu,
						  vgic_v3_private_registers + i,
						  region, VGIC_NR_PRIVATE_IRQS,
						  false);
			if (ret)
				break;
			region++;
		}
		if (ret)
			break;
	}

	if (!ret)
		kvm->arch.vgic.redist_iodevs = regions;

	return ret;
}
#endif
