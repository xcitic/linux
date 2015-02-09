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

struct vgic_register_region its_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GITS_CTLR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GITS_IIDR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GITS_TYPER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 4),
	REGISTER_DESC_WITH_LENGTH(GITS_CBASER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GITS_CWRITER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GITS_CREADR,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 8),
	REGISTER_DESC_WITH_LENGTH(GITS_BASER,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 0x40),
	REGISTER_DESC_WITH_LENGTH(GITS_IDREGS_BASE,
		vgic_mmio_read_raz, vgic_mmio_write_wi, 0x30),
};

/* This is called on setting the LPI enable bit in the redistributor. */
void vgic_enable_lpis(struct kvm_vcpu *vcpu)
{
}

int vits_init(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct vgic_its *its = &dist->its;
	struct vgic_io_device *regions;
	int ret, i;

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
