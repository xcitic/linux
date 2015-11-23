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
#ifndef __ASM_ARM_KVM_VGIC_VGIC_H
#define __ASM_ARM_KVM_VGIC_VGIC_H

#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/irqreturn.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <kvm/iodev.h>

#define VGIC_NR_SGIS		16
#define VGIC_NR_PPIS		16
#define VGIC_NR_PRIVATE_IRQS	(VGIC_NR_SGIS + VGIC_NR_PPIS)

enum vgic_type {
	VGIC_V2,		/* Good ol' GICv2 */
	VGIC_V3,		/* New fancy GICv3 */
};

/* same for all guests, as depending only on the _host's_ GIC model */
struct vgic_global {
	/* type of the host GIC */
	enum vgic_type		type;

	/* virtual control interface mapping */
	void __iomem		*vctrl_base;

	/* Number of implemented list registers */
	int			nr_lr;
};

enum vgic_irq_config {
	VGIC_CONFIG_EDGE = 0,
	VGIC_CONFIG_LEVEL
};

struct vgic_irq {
	spinlock_t irq_lock;		/* Protects the content of the struct */
	struct list_head ap_list;

	struct kvm_vcpu *vcpu;		/* SGIs and PPIs: The VCPU
					 * SPIs and LPIs: The VCPU whose ap_list
					 * on which this is queued.
					 */

	struct kvm_vcpu *target_vcpu;	/* The VCPU that this interrupt should
					 * be send to, as a result of the
					 * targets reg (v2) or the
					 * affinity reg (v3).
					 */

	u32 intid;			/* Guest visible INTID */
	bool pending;
	bool line_level;		/* Level only */
	bool soft_pending;		/* Level only */
	bool active;			/* not used for LPIs */
	bool enabled;
	bool hw;			/* Tied to HW IRQ */
	u32 hwintid;			/* HW INTID number */
	u8 targets;			/* GICv2  */
	u8 source;			/* GICv2 SGIs only */
	u8 priority;
	enum vgic_irq_config config;	/* Level or edge */
};

struct vgic_dist {
	bool			in_kernel;
	bool			ready;

	/* vGIC model the kernel emulates for the guest (GICv2 or GICv3) */
	u32			vgic_model;

	int			nr_spis;

	/* base addresses in guest physical address space: */
	/* distributor */
	phys_addr_t		vgic_dist_base;

	union {
		/* v2 CPU interface */
		phys_addr_t		vgic_cpu_base;

		/* v3 redistributors */
		phys_addr_t		vgic_redist_base;
	};

	/* distributor enabled */
	u32			enabled;

	struct vgic_irq		*spis;
};

struct vgic_v2_cpu_if {
	u32		vgic_hcr;
	u32		vgic_vmcr;
	u32		vgic_misr;	/* Saved only */
	u64		vgic_eisr;	/* Saved only */
	u64		vgic_elrsr;	/* Saved only */
	u32		vgic_apr;
	u32		vgic_lr[VGIC_V2_MAX_LRS];
};

struct vgic_v3_cpu_if {
#ifdef CONFIG_KVM_ARM_VGIC_V3
	u32		vgic_hcr;
	u32		vgic_vmcr;
	u32		vgic_sre;	/* Restored only, change ignored */
	u32		vgic_misr;	/* Saved only */
	u32		vgic_eisr;	/* Saved only */
	u32		vgic_elrsr;	/* Saved only */
	u32		vgic_ap0r[4];
	u32		vgic_ap1r[4];
	u64		vgic_lr[VGIC_V3_MAX_LRS];
#endif
};

struct vgic_cpu {
	/* CPU vif control registers for world switch */
	union {
		struct vgic_v2_cpu_if	vgic_v2;
		struct vgic_v3_cpu_if	vgic_v3;
	};

	struct vgic_irq private_irqs[VGIC_NR_PRIVATE_IRQS];

	spinlock_t ap_list_lock;	/* Protects the ap_list */
	/* list of IRQs for that VCPU to consider */
	struct list_head ap_list_head;
};

#endif /* __ASM_ARM_KVM_VGIC_VGIC_H */
