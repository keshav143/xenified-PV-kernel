/*
 * processor_xen.c - ACPI Processor Driver for xen
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/pm.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dmi.h>
#include <linux/moduleparam.h>
#include <linux/cpuidle.h>
#include <linux/acpi.h>

#include <acpi/acpi_bus.h>
#include <acpi/acpi_drivers.h>
#include <acpi/processor.h>
#include <xen/acpi.h>
#include <xen/pcpu.h>

#define PREFIX "ACPI: "

#define ACPI_PROCESSOR_CLASS            "processor"
#define ACPI_PROCESSOR_DEVICE_NAME	"Processor"
#define ACPI_PROCESSOR_FILE_INFO	"info"
#define ACPI_PROCESSOR_FILE_THROTTLING	"throttling"
#define ACPI_PROCESSOR_FILE_LIMIT	"limit"
#define ACPI_PROCESSOR_NOTIFY_PERFORMANCE 0x80
#define ACPI_PROCESSOR_NOTIFY_POWER	0x81
#define ACPI_PROCESSOR_NOTIFY_THROTTLING	0x82

#define _COMPONENT              ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME("processor_xen");

static const struct acpi_device_id processor_device_ids[] = {
	{ACPI_PROCESSOR_OBJECT_HID, 0},
	{"ACPI0007", 0},
	{"", 0},
};

/*
 * Xen ACPI processor driver
 */

/* from processor_core.c */

static int xen_acpi_processor_add(struct acpi_device *device);
static void xen_acpi_processor_notify(struct acpi_device *device, u32 event);

struct acpi_driver xen_acpi_processor_driver = {
	.name = "processor",
	.class = ACPI_PROCESSOR_CLASS,
	.ids = processor_device_ids,
	.ops = {
		.add = xen_acpi_processor_add,
		.remove = acpi_processor_remove,
		.suspend = acpi_processor_suspend,
		.resume = acpi_processor_resume,
		.notify = xen_acpi_processor_notify,
		},
};

static int is_processor_present(acpi_handle handle)
{
	acpi_status status;
	unsigned long long sta = 0;


	status = acpi_evaluate_integer(handle, "_STA", NULL, &sta);

	if (ACPI_SUCCESS(status) && (sta & ACPI_STA_DEVICE_PRESENT))
		return 1;

	/*
	 * _STA is mandatory for a processor that supports hot plug
	 */
	if (status == AE_NOT_FOUND)
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				"Processor does not support hot plug\n"));
	else
		ACPI_EXCEPTION((AE_INFO, status,
				"Processor Device is not present"));
	return 0;
}

static acpi_status
xen_acpi_processor_hotadd_init(struct acpi_processor *pr, int *p_cpu)
{
	if (!is_processor_present(pr->handle))
		return AE_ERROR;

	if (processor_cntl_xen_notify(pr,
				PROCESSOR_HOTPLUG, HOTPLUG_TYPE_ADD))
		return AE_ERROR;

	return AE_OK;
}

static int xen_acpi_processor_get_info(struct acpi_device *device)
{
	acpi_status status = 0;
	union acpi_object object = { 0 };
	struct acpi_buffer buffer = { sizeof(union acpi_object), &object };
	struct acpi_processor *pr;
	int cpu_index, device_declaration = 0;
	static int cpu0_initialized;

	pr = acpi_driver_data(device);
	if (!pr)
		return -EINVAL;

	if (num_online_cpus() > 1)
		errata.smp = TRUE;

	acpi_processor_errata(pr);

	/*
	 * Check to see if we have bus mastering arbitration control.  This
	 * is required for proper C3 usage (to maintain cache coherency).
	 */
	if (acpi_gbl_FADT.pm2_control_block &&
			acpi_gbl_FADT.pm2_control_length) {
		pr->flags.bm_control = 1;
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "Bus mastering arbitration control present\n"
				  ));
	} else
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "No bus mastering arbitration control\n"));

	if (!strcmp(acpi_device_hid(device), ACPI_PROCESSOR_OBJECT_HID)) {
		/* Declared with "Processor" statement; match ProcessorID */
		status = acpi_evaluate_object(pr->handle, NULL, NULL, &buffer);
		if (ACPI_FAILURE(status)) {
			printk(KERN_ERR PREFIX "Evaluating processor object\n");
			return -ENODEV;
		}

		/*
		 * TBD: Synch processor ID (via LAPIC/LSAPIC structures) on SMP.
		 *      >>> 'acpi_get_processor_id(acpi_id, &id)' in
		 *      arch/xxx/acpi.c
		 */
		pr->acpi_id = object.processor.proc_id;
	} else {
		/*
		 * Declared with "Device" statement; match _UID.
		 * Note that we don't handle string _UIDs yet.
		 */
		unsigned long long value;
		status = acpi_evaluate_integer(pr->handle, METHOD_NAME__UID,
						NULL, &value);
		if (ACPI_FAILURE(status)) {
			printk(KERN_ERR PREFIX
			    "Evaluating processor _UID [%#x]\n", status);
			return -ENODEV;
		}
		device_declaration = 1;
		pr->acpi_id = value;
	}

	/* TBD: add Xen specific code to query cpu_index */
	cpu_index = -1;

	/* Handle UP system running SMP kernel, with no LAPIC in MADT */
	if (!cpu0_initialized && (cpu_index == -1) &&
	    (num_online_cpus() == 1)) {
		cpu_index = 0;
	}

	cpu0_initialized = 1;

	pr->id = cpu_index;

	/*
	 *  Extra Processor objects may be enumerated on MP systems with
	 *  less than the max # of CPUs, or Xen vCPU < pCPU.
	 *  They should be ignored _iff they are physically not present.
	 *
	 */
	if (xen_pcpu_index(pr->acpi_id, 1) == -1) {
		if (ACPI_FAILURE
		    (xen_acpi_processor_hotadd_init(pr, &pr->id))) {
			return -ENODEV;
		}
	}

	/*
	 * On some boxes several processors use the same processor bus id.
	 * But they are located in different scope. For example:
	 * \_SB.SCK0.CPU0
	 * \_SB.SCK1.CPU0
	 * Rename the processor device bus id. And the new bus id will be
	 * generated as the following format:
	 * CPU+CPU ID.
	 */
	sprintf(acpi_device_bid(device), "CPU%X", pr->id);
	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Processor [%d:%d]\n", pr->id,
				pr->acpi_id));

	if (!object.processor.pblk_address)
		ACPI_DEBUG_PRINT((ACPI_DB_INFO, "No PBLK (NULL address)\n"));
	else if (object.processor.pblk_length != 6)
		printk(KERN_ERR PREFIX "Invalid PBLK length [%d]\n",
				object.processor.pblk_length);
	else {
		pr->throttling.address = object.processor.pblk_address;
		pr->throttling.duty_offset = acpi_gbl_FADT.duty_offset;
		pr->throttling.duty_width = acpi_gbl_FADT.duty_width;

		pr->pblk = object.processor.pblk_address;

		/*
		 * We don't care about error returns - we just try to mark
		 * these reserved so that nobody else is confused into thinking
		 * that this region might be unused..
		 *
		 * (In particular, allocating the IO range for Cardbus)
		 */
		request_region(pr->throttling.address, 6, "ACPI CPU throttle");
	}

	/*
	 * If ACPI describes a slot number for this CPU, we can use it
	 * ensure we get the right value in the "physical id" field
	 * of /proc/cpuinfo
	 */
	status = acpi_evaluate_object(pr->handle, "_SUN", NULL, &buffer);
	if (ACPI_SUCCESS(status))
		arch_fix_phys_package_id(pr->id, object.integer.value);

	return 0;
}

static struct acpi_device *processor_device_array[XEN_MAX_ACPI_ID + 1];

static int __cpuinit xen_acpi_processor_add(struct acpi_device *device)
{
	struct acpi_processor *pr = NULL;
	int result = 0;
	struct sys_device *sysdev;

	pr = kzalloc(sizeof(struct acpi_processor), GFP_KERNEL);
	if (!pr)
		return -ENOMEM;

	if (!zalloc_cpumask_var(&pr->throttling.shared_cpu_map, GFP_KERNEL)) {
		kfree(pr);
		return -ENOMEM;
	}

	pr->handle = device->handle;
	strcpy(acpi_device_name(device), ACPI_PROCESSOR_DEVICE_NAME);
	strcpy(acpi_device_class(device), ACPI_PROCESSOR_CLASS);
	device->driver_data = pr;

	result = xen_acpi_processor_get_info(device);
	if (result) {
		/* Processor is physically not present */
		return 0;
	}

	/*
	 * Buggy BIOS check
	 * ACPI id of processors can be reported wrongly by the BIOS.
	 * Don't trust it blindly
	 */
	if (pr->acpi_id > XEN_MAX_ACPI_ID ||
			(processor_device_array[pr->acpi_id] != NULL &&
			 processor_device_array[pr->acpi_id] != device)) {
		printk(KERN_WARNING "BIOS reported wrong ACPI id "
			"for the processor\n");
		result = -ENODEV;
		goto err_free_cpumask;
	}

	processor_device_array[pr->acpi_id] = device;

	if (pr->id != -1) {
		per_cpu(processors, pr->id) = pr;

		result = acpi_processor_add_fs(device);
		if (result)
			goto err_free_cpumask;

		sysdev = get_cpu_sysdev(pr->id);
		if (sysdev != NULL && sysfs_create_link(&device->dev.kobj,
					&sysdev->kobj, "sysdev")) {
			result = -EFAULT;
			goto err_remove_fs;
		}
	}

	/* _PDC call should be done before doing anything else (if reqd.). */
	xen_arch_acpi_processor_init_pdc(pr);
	acpi_processor_set_pdc(pr);
	arch_acpi_processor_cleanup_pdc(pr);

#ifdef CONFIG_CPU_FREQ
	xen_acpi_processor_ppc_has_changed(pr);
	result = xen_acpi_processor_get_performance(pr);
	if (result)
		goto err_remove_fs;
#endif

	if (pr->id != -1) {
		acpi_processor_get_throttling_info(pr);
		acpi_processor_get_limit_info(pr);
	}

	xen_acpi_processor_power_init(pr, device);

	if (pr->id != -1) {
		pr->cdev = thermal_cooling_device_register("Processor", device,
				&processor_cooling_ops);
		if (IS_ERR(pr->cdev)) {
			result = PTR_ERR(pr->cdev);
			goto err_power_exit;
		}

		dev_info(&device->dev, "registered as cooling_device%d\n",
				pr->cdev->id);

		result = sysfs_create_link(&device->dev.kobj,
				&pr->cdev->device.kobj,
				"thermal_cooling");
		if (result) {
			printk(KERN_ERR PREFIX "Create sysfs link\n");
			goto err_thermal_unregister;
		}
		result = sysfs_create_link(&pr->cdev->device.kobj,
				&device->dev.kobj,
				"device");
		if (result) {
			printk(KERN_ERR PREFIX "Create sysfs link\n");
			goto err_remove_sysfs;
		}
	}

	return 0;

err_remove_sysfs:
	sysfs_remove_link(&device->dev.kobj, "thermal_cooling");
err_thermal_unregister:
	thermal_cooling_device_unregister(pr->cdev);
err_power_exit:
	acpi_processor_power_exit(pr, device);
err_remove_fs:
	acpi_processor_remove_fs(device);
err_free_cpumask:
	free_cpumask_var(pr->throttling.shared_cpu_map);

	return result;
}

static void xen_acpi_processor_notify(struct acpi_device *device, u32 event)
{
	struct acpi_processor *pr = acpi_driver_data(device);
	int saved;

	if (!pr)
		return;

	switch (event) {
	case ACPI_PROCESSOR_NOTIFY_PERFORMANCE:
		saved = pr->performance_platform_limit;
		xen_acpi_processor_ppc_has_changed(pr);
		if (saved == pr->performance_platform_limit)
			break;
		acpi_bus_generate_proc_event(device, event,
					pr->performance_platform_limit);
		acpi_bus_generate_netlink_event(device->pnp.device_class,
					dev_name(&device->dev), event,
					pr->performance_platform_limit);
		break;
	case ACPI_PROCESSOR_NOTIFY_POWER:
		xen_acpi_processor_cst_has_changed(pr);
		acpi_bus_generate_proc_event(device, event, 0);
		acpi_bus_generate_netlink_event(device->pnp.device_class,
					dev_name(&device->dev), event, 0);
		break;
	case ACPI_PROCESSOR_NOTIFY_THROTTLING:
		acpi_processor_tstate_has_changed(pr);
		acpi_bus_generate_proc_event(device, event, 0);
		acpi_bus_generate_netlink_event(device->pnp.device_class,
					dev_name(&device->dev), event, 0);
	default:
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "Unsupported event [0x%x]\n", event));
		break;
	}

	return;
}

/* from processor_idle.c */

static int xen_acpi_processor_get_power_info(struct acpi_processor *pr)
{
	int ret;
	int invalid_pr_id = 0;

	/*
	 * acpi_processor_get_power_info need valid pr->id
	 * so set pr->id=0 temporarily
	 */
	if (pr->id == -1) {
		invalid_pr_id = 1;
		pr->id = 0;
	}

	ret = acpi_processor_get_power_info(pr);

	if (invalid_pr_id)
		pr->id = -1;

	return ret;
}

int xen_acpi_processor_cst_has_changed(struct acpi_processor *pr)
{
	if (!pr)
		return -EINVAL;

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	xen_acpi_processor_get_power_info(pr);

	processor_cntl_xen_notify(pr,
			PROCESSOR_PM_CHANGE, PM_TYPE_IDLE);

	return 0;
}


int __cpuinit xen_acpi_processor_power_init(struct acpi_processor *pr,
			      struct acpi_device *device)
{
	acpi_status status = 0;
	unsigned int i;

	if (!pr)
		return -EINVAL;

	if (acpi_gbl_FADT.cst_control) {
		status = acpi_os_write_port(acpi_gbl_FADT.smi_command,
				acpi_gbl_FADT.cst_control, 8);
		if (ACPI_FAILURE(status)) {
			ACPI_EXCEPTION((AE_INFO, status,
				"Notifying BIOS of _CST ability failed"));
		}
	}

	xen_acpi_processor_get_power_info(pr);

	pr->flags.power_setup_done = 1;

	if (pr->flags.power) {
			processor_cntl_xen_notify(pr,
					PROCESSOR_PM_INIT, PM_TYPE_IDLE);

		printk(KERN_INFO PREFIX "CPU%d (power states:", pr->id);
		for (i = 1; i <= pr->power.count; i++)
			if (pr->power.states[i].valid)
				printk(" C%d[C%d]", i,
				       pr->power.states[i].type);
		printk(")\n");
	}

	return 0;
}

/* from processor_perflib.c */

#ifdef CONFIG_CPU_FREQ
static int xen_processor_notify_smm(void)
{
	acpi_status status;
	static int is_done;

	/* only need successfully notify BIOS once */
	/* avoid double notification which may lead to unexpected result */
	if (is_done)
		return 0;

	/* Can't write pstate_cnt to smi_cmd if either value is zero */
	if ((!acpi_gbl_FADT.smi_command) || (!acpi_gbl_FADT.pstate_control)) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO, "No SMI port or pstate_cnt\n"));
		return 0;
	}

	ACPI_DEBUG_PRINT((ACPI_DB_INFO,
		"Writing pstate_cnt [0x%x] to smi_cmd [0x%x]\n",
		acpi_gbl_FADT.pstate_control, acpi_gbl_FADT.smi_command));

	status = acpi_os_write_port(acpi_gbl_FADT.smi_command,
				    (u32) acpi_gbl_FADT.pstate_control, 8);
	if (ACPI_FAILURE(status))
		return status;

	is_done = 1;

	return 0;
}

static int xen_acpi_processor_get_platform_limit(struct acpi_processor *pr)
{
	acpi_status status = 0;
	unsigned long long ppc = 0;

	if (!pr)
		return -EINVAL;

	/*
	 * _PPC indicates the maximum state currently supported by the platform
	 * (e.g. 0 = states 0..n; 1 = states 1..n; etc.
	 */
	status = acpi_evaluate_integer(pr->handle, "_PPC", NULL, &ppc);

	if (ACPI_FAILURE(status) && status != AE_NOT_FOUND) {
		ACPI_EXCEPTION((AE_INFO, status, "Evaluating _PPC"));
		return -ENODEV;
	}

	pr->performance_platform_limit = (int)ppc;

	return 0;
}

int xen_acpi_processor_ppc_has_changed(struct acpi_processor *pr)
{
	int ret;

	ret = xen_acpi_processor_get_platform_limit(pr);

	if (ret < 0)
		return ret;
	else
		return processor_cntl_xen_notify(pr,
				PROCESSOR_PM_CHANGE, PM_TYPE_PERF);
}

/*
 * Existing ACPI module does parse performance states at some point,
 * when acpi-cpufreq driver is loaded which however is something
 * we'd like to disable to avoid confliction with xen PM
 * logic. So we have to collect raw performance information here
 * when ACPI processor object is found and started.
 */
int xen_acpi_processor_get_performance(struct acpi_processor *pr)
{
	int ret;
	struct acpi_processor_performance *perf;
	struct acpi_psd_package *pdomain;

	if (pr->performance)
		return -EBUSY;

	perf = kzalloc(sizeof(struct acpi_processor_performance), GFP_KERNEL);
	if (!perf)
		return -ENOMEM;

	pr->performance = perf;
	/* Get basic performance state information */
	ret = acpi_processor_get_performance_info(pr);
	if (ret < 0)
		goto err_out;

	/*
	 * Well, here we need retrieve performance dependency information
	 * from _PSD object. The reason why existing interface is not used
	 * is due to the reason that existing interface sticks to Linux cpu
	 * id to construct some bitmap, however we want to split ACPI
	 * processor objects from Linux cpu id logic. For example, even
	 * when Linux is configured as UP, we still want to parse all ACPI
	 * processor objects to xen. In this case, it's preferred
	 * to use ACPI ID instead.
	 */
	pdomain = &pr->performance->domain_info;
	pdomain->num_processors = 0;
	ret = acpi_processor_get_psd(pr);
	if (ret < 0) {
		/*
		 * _PSD is optional - assume no coordination if absent (or
		 * broken), matching native kernels' behavior.
		 */
		pdomain->num_entries = ACPI_PSD_REV0_ENTRIES;
		pdomain->revision = ACPI_PSD_REV0_REVISION;
		pdomain->domain = pr->acpi_id;
		pdomain->coord_type = DOMAIN_COORD_TYPE_SW_ALL;
		pdomain->num_processors = 1;
	}

	/* Some sanity check */
	if ((pdomain->revision != ACPI_PSD_REV0_REVISION) ||
	    (pdomain->num_entries != ACPI_PSD_REV0_ENTRIES) ||
	    ((pdomain->coord_type != DOMAIN_COORD_TYPE_SW_ALL) &&
	     (pdomain->coord_type != DOMAIN_COORD_TYPE_SW_ANY) &&
	     (pdomain->coord_type != DOMAIN_COORD_TYPE_HW_ALL))) {
		ret = -EINVAL;
		goto err_out;
	}

	/* Last step is to notify BIOS that xen exists */
	xen_processor_notify_smm();

	processor_cntl_xen_notify(pr, PROCESSOR_PM_INIT, PM_TYPE_PERF);

	return 0;
err_out:
	pr->performance = NULL;
	kfree(perf);
	return ret;
}
#endif /* CONFIG_CPU_FREQ */

/* init and exit */

int xen_acpi_processor_init(void)
{
	return acpi_bus_register_driver(&xen_acpi_processor_driver);
}

void xen_acpi_processor_exit(void)
{
	acpi_bus_unregister_driver(&xen_acpi_processor_driver);
}
