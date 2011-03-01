#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>

#include <asm/io_apic.h>
#include <asm/acpi.h>
#include <asm/hw_irq.h>

#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>

#include <xen/xen.h>
#include <xen/interface/xen.h>
#include <xen/interface/physdev.h>

void __init xen_io_apic_init(void)
{
	enable_IO_APIC();
}

void xen_init_apic(void)
{
	if (!xen_initial_domain())
		return;

#ifdef CONFIG_ACPI
	/*
	 * Pretend ACPI found our lapic even though we've disabled it,
	 * to prevent MP tables from setting up lapics.
	 */
	acpi_lapic = 1;
#endif
}
