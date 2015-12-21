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

static int vgic_mmio_read_nyi(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *this,
			      gpa_t addr, int len, void *val)
{
	pr_warn("KVM: handling unimplemented VGIC MMIO read: VCPU %d, address: 0x%llx\n",
		vcpu->vcpu_id, (unsigned long long)addr);
	return 0;
}

static int vgic_mmio_write_nyi(struct kvm_vcpu *vcpu,
			       struct kvm_io_device *this,
			       gpa_t addr, int len, const void *val)
{
	pr_warn("KVM: handling unimplemented VGIC MMIO write: VCPU %d, address: 0x%llx\n",
		vcpu->vcpu_id, (unsigned long long)addr);
	return 0;
}

struct vgic_register_region vgic_v2_dist_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_CTRL,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 12),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_IGROUP,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ENABLE_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PENDING_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_ACTIVE_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 1),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_PRI,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_TARGET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 8),
	REGISTER_DESC_WITH_BITS_PER_IRQ(GIC_DIST_CONFIG,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 8),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SOFTINT,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 4),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_CLEAR,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 16),
	REGISTER_DESC_WITH_LENGTH(GIC_DIST_SGI_PENDING_SET,
		vgic_mmio_read_nyi, vgic_mmio_write_nyi, 16),
};

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
