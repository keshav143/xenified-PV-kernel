#include <linux/init.h>
#include <linux/mm.h>

#include <asm/pat.h>

#include "mtrr.h"

#include <xen/xen.h>
#include <xen/interface/platform.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>

static void xen_set_mtrr(unsigned int reg, unsigned long base,
			 unsigned long size, mtrr_type type)
{
	struct xen_platform_op op;
	int error;

	/* mtrr_ops->set() is called once per CPU,
	 * but Xen's ops apply to all CPUs.
	 */
	if (smp_processor_id())
		return;

	if (size == 0) {
		op.cmd = XENPF_del_memtype;
		op.u.del_memtype.handle = 0;
		op.u.del_memtype.reg    = reg;
	} else {
		op.cmd = XENPF_add_memtype;
		op.u.add_memtype.mfn     = base;
		op.u.add_memtype.nr_mfns = size;
		op.u.add_memtype.type    = type;
	}

	error = HYPERVISOR_dom0_op(&op);
	BUG_ON(error != 0);
}

static void xen_get_mtrr(unsigned int reg, unsigned long *base,
			 unsigned long *size, mtrr_type *type)
{
	struct xen_platform_op op;

	op.cmd = XENPF_read_memtype;
	op.u.read_memtype.reg = reg;
	if (HYPERVISOR_dom0_op(&op) != 0) {
		*base = 0;
		*size = 0;
		*type = 0;
		return;
	}

	*size = op.u.read_memtype.nr_mfns;
	*base = op.u.read_memtype.mfn;
	*type = op.u.read_memtype.type;
}

static int __init xen_num_var_ranges(void)
{
	int ranges;
	struct xen_platform_op op;

	op.cmd = XENPF_read_memtype;

	for (ranges = 0; ; ranges++) {
		op.u.read_memtype.reg = ranges;
		if (HYPERVISOR_dom0_op(&op) != 0)
			break;
	}
	return ranges;
}

/*
 * DOM0 TODO: Need to fill in the remaining mtrr methods to have full
 * working userland mtrr support.
 */
static struct mtrr_ops xen_mtrr_ops = {
	.vendor            = X86_VENDOR_UNKNOWN,
	.get_free_region   = generic_get_free_region,
	.set               = xen_set_mtrr,
	.get               = xen_get_mtrr,
	.have_wrcomb       = positive_have_wrcomb,
	.validate_add_page = generic_validate_add_page,
	.use_intel_if	   = 0,
	.num_var_ranges	   = xen_num_var_ranges,
};

void __init xen_init_mtrr(void)
{
	/* 
	 * Check that we're running under Xen, and privileged enough
	 * to play with MTRRs.
	 */
	if (!xen_initial_domain())
		return;

	/* 
	 * Check that the CPU has an MTRR implementation we can
	 * support.
	 */
	if (cpu_has_mtrr ||
	    cpu_has_k6_mtrr ||
	    cpu_has_cyrix_arr ||
	    cpu_has_centaur_mcr) {
		mtrr_if = &xen_mtrr_ops;
		pat_init();
	}
}
