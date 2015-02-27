/*
 * GICv3 ITS emulation
 *
 * Copyright (C) 2015 ARM Ltd.
 * Author: Andre Przywara <andre.przywara@arm.com>
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

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"
#include "vgic_mmio.h"

#define BASER_BASE_ADDRESS(x) ((x) & 0xfffffffff000ULL)

static int vgic_mmio_read_its_ctlr(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, void *val)
{
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u32 reg;

	reg = GITS_CTLR_QUIESCENT;
	if (its->enabled)
		reg |= GITS_CTLR_ENABLE;

	write_mask32(reg, addr & 3, len, val);

	return 0;
}

static int vgic_mmio_write_its_ctlr(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, const void *val)
{
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);

        if (addr - iodev->base_addr == 0)
		its->enabled = !!(*(u8*)val & GITS_CTLR_ENABLE);

	return 0;
}

static int vgic_mmio_read_its_typer(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, void *val)
{
	u64 reg = GITS_TYPER_PLPIS;

	/*
	 * We use linear CPU numbers for redistributor addressing,
	 * so GITS_TYPER.PTA is 0.
	 * To avoid memory waste on the guest side, we keep the
	 * number of IDBits and DevBits low for the time being.
	 * This could later be made configurable by userland.
	 * Since we have all collections in linked list, we claim
	 * that we can hold all of the collection tables in our
	 * own memory and that the ITT entry size is 1 byte (the
	 * smallest possible one).
	 */
	reg |= 0xff << GITS_TYPER_HWCOLLCNT_SHIFT;
	reg |= 0x0f << GITS_TYPER_DEVBITS_SHIFT;
	reg |= 0x0f << GITS_TYPER_IDBITS_SHIFT;

	write_mask64(reg, addr & 7, len, val);

	return 0;
}

static int vgic_mmio_read_its_iidr(struct kvm_vcpu *vcpu,
				   struct kvm_io_device *this,
				   gpa_t addr, int len, void *val)
{
	u32 reg = (PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0);

	write_mask32(reg, addr & 3, len, val);

	return 0;
}

static int vgic_mmio_read_its_idregs(struct kvm_vcpu *vcpu,
				     struct kvm_io_device *this,
				     gpa_t addr, int len, void *val)
{
	struct vgic_io_device *iodev = container_of(this,
						    struct vgic_io_device, dev);
	u32 reg = 0;
	int idreg = (addr & ~3) - iodev->base_addr + GITS_IDREGS_BASE;

	switch (idreg) {
	case GITS_PIDR2:
		reg = GIC_PIDR2_ARCH_GICv3;
		break;
	case GITS_PIDR4:
		/* This is a 64K software visible page */
		reg = 0x40;
		break;
	/* Those are the ID registers for (any) GIC. */
	case GITS_CIDR0:
		reg = 0x0d;
		break;
	case GITS_CIDR1:
		reg = 0xf0;
		break;
	case GITS_CIDR2:
		reg = 0x05;
		break;
	case GITS_CIDR3:
		reg = 0xb1;
		break;
	}

	write_mask32(reg, addr & 3, len, val);

	return 0;
}

/*
 * This function is called with both the ITS and the distributor lock dropped,
 * so the actual command handlers must take the respective locks when needed.
 */
static int vits_handle_command(struct kvm_vcpu *vcpu, u64 *its_cmd)
{
	return -ENODEV;
}

static int vgic_mmio_read_its_cbaser(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *this,
				    gpa_t addr, int len, void *val)
{
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;

	write_mask64(its->cbaser, addr & 7, len, val);

	return 0;
}

static int vgic_mmio_write_its_cbaser(struct kvm_vcpu *vcpu,
				      struct kvm_io_device *this,
				      gpa_t addr, int len, const void *val)
{
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;

	if (its->enabled)
		return 0;

	its->cbaser = mask64(its->cbaser, addr & 7, len, val);
	its->creadr = 0;

	return 0;
}

static int its_cmd_buffer_size(struct kvm *kvm)
{
	struct vgic_its *its = &kvm->arch.vgic.its;

	return ((its->cbaser & 0xff) + 1) << 12;
}

static gpa_t its_cmd_buffer_base(struct kvm *kvm)
{
	struct vgic_its *its = &kvm->arch.vgic.its;

	return BASER_BASE_ADDRESS(its->cbaser);
}

/*
 * By writing to CWRITER the guest announces new commands to be processed.
 * Since we cannot read from guest memory inside the ITS spinlock, we
 * iterate over the command buffer (with the lock dropped) until the read
 * pointer matches the write pointer. Other VCPUs writing this register in the
 * meantime will just update the write pointer, leaving the command
 * processing to the first instance of the function.
 */
static int vgic_mmio_write_its_cwriter(struct kvm_vcpu *vcpu,
				       struct kvm_io_device *this,
				       gpa_t addr, int len, const void *val)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	struct vgic_its *its = &dist->its;
	gpa_t cbaser = its_cmd_buffer_base(vcpu->kvm);
	u64 cmd_buf[4];
	u32 reg;
	bool finished;

	reg = mask64(its->cwriter & 0xfffe0, addr & 7, len, val);
	reg &= 0xfffe0;
	if (reg > its_cmd_buffer_size(vcpu->kvm))
		return 0;

	spin_lock(&its->lock);

	/*
	 * If there is still another VCPU handling commands, let this
	 * one pick up the new CWRITER and process "our" new commands as well.
	 */
	finished = (its->cwriter != its->creadr);
	its->cwriter = reg;

	spin_unlock(&its->lock);

	while (!finished) {
		int ret = kvm_read_guest(vcpu->kvm, cbaser + its->creadr,
					 cmd_buf, 32);
		if (ret) {
			/*
			 * Gah, we are screwed. Reset CWRITER to that command
			 * that we have finished processing and return.
			 */
			spin_lock(&its->lock);
			its->cwriter = its->creadr;
			spin_unlock(&its->lock);
			break;
		}
		vits_handle_command(vcpu, cmd_buf);

		spin_lock(&its->lock);
		its->creadr += 32;
		if (its->creadr == its_cmd_buffer_size(vcpu->kvm))
			its->creadr = 0;
		finished = (its->creadr == its->cwriter);
		spin_unlock(&its->lock);
	}

	return 0;
}

static int vgic_mmio_read_its_cwriter(struct kvm_vcpu *vcpu,
				      struct kvm_io_device *this,
				      gpa_t addr, int len, void *val)
{
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u64 reg = its->cwriter & 0xfffe0;

	write_mask64(reg, addr & 7, len, val);

	return 0;
}

static int vgic_mmio_read_its_creadr(struct kvm_vcpu *vcpu,
				     struct kvm_io_device *this,
				     gpa_t addr, int len, void *val)
{
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u64 reg = its->creadr & 0xfffe0;

	write_mask64(reg, addr & 7, len, val);

	return 0;
}

struct vgic_register_region its_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GITS_CTLR,
		vgic_mmio_read_its_ctlr, vgic_mmio_write_its_ctlr, 4),
	REGISTER_DESC_WITH_LENGTH(GITS_IIDR,
		vgic_mmio_read_its_iidr, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GITS_TYPER,
		vgic_mmio_read_its_typer, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GITS_CBASER,
		vgic_mmio_read_its_cbaser, vgic_mmio_write_its_cbaser, 8),
	REGISTER_DESC_WITH_LENGTH(GITS_CWRITER,
		vgic_mmio_read_its_cwriter, vgic_mmio_write_its_cwriter, 8),
	REGISTER_DESC_WITH_LENGTH(GITS_CREADR,
		vgic_mmio_read_its_creadr, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GITS_BASER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 0x40),
	REGISTER_DESC_WITH_LENGTH(GITS_IDREGS_BASE,
		vgic_mmio_read_its_idregs, vgic_mmio_write_wi, 0x30),
};

/* This is called on setting the LPI enable bit in the redistributor. */
void vgic_enable_lpis(struct kvm_vcpu *vcpu)
{
}

int vits_init(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct vgic_its *its = &dist->its;
	int nr_vcpus = atomic_read(&kvm->online_vcpus);
	struct vgic_io_device *regions;
	int ret, i;

	dist->pendbaser = kcalloc(nr_vcpus, sizeof(u64), GFP_KERNEL);
	if (!dist->pendbaser)
		return -ENOMEM;

	spin_lock_init(&its->lock);

	regions = kmalloc_array(ARRAY_SIZE(its_registers),
				sizeof(struct vgic_io_device), GFP_KERNEL);

	for (i = 0; i < ARRAY_SIZE(its_registers); i++) {
		regions[i].base_addr = dist->vgic_its_base;

		ret = register_reg_region(kvm, NULL, &its_registers[i],
					  &regions[i], 0, false);
	}

	if (ret)
		return ret;

	its->enabled = false;

	return -ENXIO;
}

void vits_destroy(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct vgic_its *its = &dist->its;

	if (!vgic_has_its(kvm))
		return;

	kfree(dist->pendbaser);

	its->enabled = false;
}
