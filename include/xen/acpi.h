#ifndef _XEN_ACPI_H
#define _XEN_ACPI_H

#include <linux/types.h>
#include <acpi/acpi_drivers.h>
#include <acpi/processor.h>
#include <xen/xen.h>

#ifdef CONFIG_XEN_S3
#include <asm/xen/hypervisor.h>

static inline bool xen_pv_acpi(void)
{
	return xen_pv_domain();
}
#else
static inline bool xen_pv_acpi(void)
{
	return false;
}
#endif

int acpi_notify_hypervisor_state(u8 sleep_state,
				 u32 pm1a_cnt, u32 pm1b_cnd);

/*
 * Following are interfaces for xen acpi processor control
 */

/* Events notified to xen */
#define PROCESSOR_PM_INIT	1
#define PROCESSOR_PM_CHANGE	2
#define PROCESSOR_HOTPLUG	3

/* Objects for the PM events */
#define PM_TYPE_IDLE		0
#define PM_TYPE_PERF		1
#define PM_TYPE_THR		2
#define PM_TYPE_MAX		3

#define XEN_MAX_ACPI_ID 255

/* Processor hotplug events */
#define HOTPLUG_TYPE_ADD	0
#define HOTPLUG_TYPE_REMOVE	1

int xen_acpi_processor_init(void);
void xen_acpi_processor_exit(void);

int xen_acpi_processor_power_init(struct acpi_processor *pr,
		struct acpi_device *device);
int xen_acpi_processor_cst_has_changed(struct acpi_processor *pr);

void xen_arch_acpi_processor_init_pdc(struct acpi_processor *pr);

#ifdef CONFIG_CPU_FREQ
int xen_acpi_processor_ppc_has_changed(struct acpi_processor *pr);
int xen_acpi_processor_get_performance(struct acpi_processor *pr);
#else
static inline int xen_acpi_processor_ppc_has_changed(struct acpi_processor *pr)
{
	return acpi_processor_ppc_has_changed(pr);
}
static inline int xen_acpi_processor_get_performance(struct acpi_processor *pr)
{
	printk(KERN_WARNING
		"Warning: xen_acpi_processor_get_performance not supported\n"
		"Consider compiling CPUfreq support into your kernel.\n");
	return 0;
}
#endif

#if defined(CONFIG_ACPI_HOTPLUG_MEMORY) || \
	defined(CONFIG_ACPI_HOTPLUG_MEMORY_MODULE)
int xen_hotadd_memory(struct acpi_memory_device *mem_device);
#endif

#if defined(CONFIG_ACPI_PROCESSOR_XEN) || \
defined(CONFIG_ACPI_PROCESSOR_XEN_MODULE)

struct processor_cntl_xen_ops {
	/* Transfer processor PM events to xen */
int (*pm_ops[PM_TYPE_MAX])(struct acpi_processor *pr, int event);
	/* Notify physical processor status to xen */
	int (*hotplug)(struct acpi_processor *pr, int type);
};

extern int processor_cntl_xen_notify(struct acpi_processor *pr,
			int event, int type);
extern int processor_cntl_xen_power_cache(int cpu, int cx,
		struct acpi_power_register *reg);
#else

static inline int processor_cntl_xen_notify(struct acpi_processor *pr,
			int event, int type)
{
	return 0;
}
static inline int processor_cntl_xen_power_cache(int cpu, int cx,
		struct acpi_power_register *reg)
{
	return 0;
}
#endif /* CONFIG_ACPI_PROCESSOR_XEN */

#endif	/* _XEN_ACPI_H */
