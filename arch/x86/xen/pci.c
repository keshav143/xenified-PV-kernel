#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/slab.h>

#include <asm/mpspec.h>
#include <asm/io_apic.h>
#include <asm/pci_x86.h>

#include <asm/xen/hypervisor.h>
#include <asm/xen/pci.h>

#include <xen/interface/xen.h>
#include <xen/events.h>

#include "xen-ops.h"

int xen_register_pirq(u32 gsi, int triggering)
{
	int rc, irq;
	struct physdev_map_pirq map_irq;
	int shareable = 0;
	char *name;

	if (!xen_pv_domain())
		return -1;

	if (triggering == ACPI_EDGE_SENSITIVE) {
		shareable = 0;
		name = "ioapic-edge";
	} else {
		shareable = 1;
		name = "ioapic-level";
	}

	irq = xen_allocate_pirq(gsi, shareable, name);

	printk(KERN_DEBUG "xen: --> irq=%d\n", irq);

	if (irq < 0)
		goto out;

	map_irq.domid = DOMID_SELF;
	map_irq.type = MAP_PIRQ_TYPE_GSI;
	map_irq.index = gsi;
	map_irq.pirq = irq;

	rc = HYPERVISOR_physdev_op(PHYSDEVOP_map_pirq, &map_irq);
	if (rc) {
		printk(KERN_WARNING "xen map irq failed %d\n", rc);
		return -1;
	}

out:
	return irq;
}

int xen_register_gsi(u32 gsi, int triggering, int polarity)
{
	int rc, irq;
	struct physdev_setup_gsi setup_gsi;

	if (!xen_pv_domain())
		return -1;

	printk(KERN_DEBUG "xen: registering gsi %u triggering %d polarity %d\n",
			gsi, triggering, polarity);

	irq = xen_register_pirq(gsi, triggering);

	setup_gsi.gsi = gsi;
	setup_gsi.triggering = (triggering == ACPI_EDGE_SENSITIVE ? 0 : 1);
	setup_gsi.polarity = (polarity == ACPI_ACTIVE_HIGH ? 0 : 1);

	rc = HYPERVISOR_physdev_op(PHYSDEVOP_setup_gsi, &setup_gsi);
	if (rc == -EEXIST)
		printk(KERN_INFO "Already setup the GSI :%d\n", gsi);
	else if (rc) {
		printk(KERN_ERR "Failed to setup GSI :%d, err_code:%d\n",
				gsi, rc);
	}

	return irq;
}

#ifdef CONFIG_ACPI
#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length < sizeof(*entry))


static int __init
xen_acpi_parse_int_src_ovr(struct acpi_subtable_header * header,
			   const unsigned long end)
{
	struct acpi_madt_interrupt_override *intsrc = NULL;

	intsrc = (struct acpi_madt_interrupt_override *)header;

	if (BAD_MADT_ENTRY(intsrc, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (intsrc->source_irq == acpi_gbl_FADT.sci_interrupt) {
		int gsi;
		int trigger, polarity;

		trigger = intsrc->inti_flags & ACPI_MADT_TRIGGER_MASK;
		polarity = intsrc->inti_flags & ACPI_MADT_POLARITY_MASK;

		/* Command-line over-ride via acpi_sci= */
		if (acpi_sci_flags & ACPI_MADT_TRIGGER_MASK)
			trigger = acpi_sci_flags & ACPI_MADT_TRIGGER_MASK;

		if (acpi_sci_flags & ACPI_MADT_POLARITY_MASK)
			polarity = acpi_sci_flags & ACPI_MADT_POLARITY_MASK;

		printk("xen: sci override: source_irq=%d global_irq=%d trigger=%x polarity=%x\n",
			intsrc->source_irq, intsrc->global_irq,
			trigger, polarity);

		switch (polarity) {
		case ACPI_MADT_POLARITY_CONFORMS:
		case ACPI_MADT_POLARITY_ACTIVE_LOW:
			polarity = ACPI_ACTIVE_LOW;
			break;

		case ACPI_MADT_POLARITY_ACTIVE_HIGH:
			polarity = ACPI_ACTIVE_HIGH;
			break;

		default:
			return 0;
		}

		switch (trigger) {
		case ACPI_MADT_TRIGGER_CONFORMS:
		case ACPI_MADT_TRIGGER_LEVEL:
			trigger = ACPI_LEVEL_SENSITIVE;
			break;

		case ACPI_MADT_TRIGGER_EDGE:
			trigger = ACPI_EDGE_SENSITIVE;
			break;

		default:
			return 0;
		}

		gsi = xen_register_gsi(intsrc->global_irq,
				       trigger, polarity);
		/*
		 * stash over-ride to indicate we've been here
		 * and for later update of acpi_gbl_FADT
		 */
		acpi_sci_override_gsi = gsi;

		printk("xen: acpi sci %d\n", gsi);
	}

	return 0;
}

static __init void xen_setup_acpi_sci(void)
{
  acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_OVERRIDE,
			xen_acpi_parse_int_src_ovr,
			nr_irqs);
}
#else
static __init void xen_setup_acpi_sci(void)
{
}
#endif

void __init xen_setup_pirqs(void)
{
	int irq;

	if (0 == nr_ioapics) {
		for (irq = 0; irq < NR_IRQS_LEGACY; irq++)
			xen_allocate_pirq(irq, 0, "xt-pic");
		return;
	}

	/* Pre-allocate legacy irqs */
	for (irq = 0; irq < NR_IRQS_LEGACY; irq++) {
		int trigger, polarity;

		if (acpi_get_override_irq(irq, &trigger, &polarity) == -1)
			continue;

		xen_register_pirq(irq,
			trigger ? ACPI_LEVEL_SENSITIVE : ACPI_EDGE_SENSITIVE);
	}

	xen_setup_acpi_sci();
}

#ifdef CONFIG_PCI_MSI
int xen_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	int irq, ret;
	struct msi_desc *msidesc;

	list_for_each_entry(msidesc, &dev->msi_list, list) {
		irq = xen_create_msi_irq(dev, msidesc, type);
		if (irq < 0)
			return -1;

		ret = set_irq_msi(irq, msidesc);
		if (ret)
			goto error;
	}
	return 0;

error:
	xen_destroy_irq(irq);
	return ret;
}
#endif

struct xen_device_domain_owner {
	domid_t domain;
	struct pci_dev *dev;
	struct list_head list;
};

static DEFINE_SPINLOCK(dev_domain_list_spinlock);
static struct list_head dev_domain_list = LIST_HEAD_INIT(dev_domain_list);

static struct xen_device_domain_owner *find_device(struct pci_dev *dev)
{
	struct xen_device_domain_owner *owner;

	list_for_each_entry(owner, &dev_domain_list, list) {
		if (owner->dev == dev)
			return owner;
	}
	return NULL;
}

int xen_find_device_domain_owner(struct pci_dev *dev)
{
	struct xen_device_domain_owner *owner;
	int domain = -ENODEV;

	spin_lock(&dev_domain_list_spinlock);
	owner = find_device(dev);
	if (owner)
		domain = owner->domain;
	spin_unlock(&dev_domain_list_spinlock);
	return domain;
}
EXPORT_SYMBOL(xen_find_device_domain_owner);

int xen_register_device_domain_owner(struct pci_dev *dev, uint16_t domain)
{
	struct xen_device_domain_owner *owner;

	owner = kzalloc(sizeof(struct xen_device_domain_owner), GFP_KERNEL);
	if (!owner)
		return -ENODEV;

	spin_lock(&dev_domain_list_spinlock);
	if (find_device(dev)) {
		spin_unlock(&dev_domain_list_spinlock);
		kfree(owner);
		return -EEXIST;
	}
	owner->domain = domain;
	owner->dev = dev;
	list_add_tail(&owner->list, &dev_domain_list);
	spin_unlock(&dev_domain_list_spinlock);
	return 0;
}
EXPORT_SYMBOL(xen_register_device_domain_owner);

int xen_unregister_device_domain_owner(struct pci_dev *dev)
{
	struct xen_device_domain_owner *owner;

	spin_lock(&dev_domain_list_spinlock);
	owner = find_device(dev);
	if (!owner) {
		spin_unlock(&dev_domain_list_spinlock);
		return -ENODEV;
	}
	list_del(&owner->list);
	spin_unlock(&dev_domain_list_spinlock);
	kfree(owner);
	return 0;
}
EXPORT_SYMBOL(xen_unregister_device_domain_owner);
