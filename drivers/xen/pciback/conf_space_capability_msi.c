/*
 * PCI Backend -- Configuration overlay for MSI capability
 */
#include <linux/pci.h>
#include <linux/slab.h>
#include "conf_space.h"
#include "conf_space_capability.h"
#include <xen/interface/io/pciif.h>
#include <xen/events.h>
#include "pciback.h"

int pciback_enable_msi(struct pciback_device *pdev,
		struct pci_dev *dev, struct xen_pci_op *op)
{
	struct pciback_dev_data *dev_data;
	int otherend = pdev->xdev->otherend_id;
	int status;

 	if (unlikely(verbose_request))
		printk(KERN_DEBUG "pciback: %s: enable MSI\n", pci_name(dev));

	status = pci_enable_msi(dev);

	if (status) {
		printk(KERN_ERR "error enable msi for guest %x status %x\n",
			otherend, status);
		op->value = 0;
		return XEN_PCI_ERR_op_failed;
	}

	/* The value the guest needs is actually the IDT vector, not the
	 * the local domain's IRQ number. */
	op->value = xen_gsi_from_irq(dev->irq);
	dev_data = pci_get_drvdata(dev);
	if (dev_data)
		dev_data->ack_intr = 0;

	return 0;
}

int pciback_disable_msi(struct pciback_device *pdev,
		struct pci_dev *dev, struct xen_pci_op *op)
{
	struct pciback_dev_data *dev_data;

 	if (unlikely(verbose_request))
		printk(KERN_DEBUG "pciback: %s: disable MSI\n", pci_name(dev));
	pci_disable_msi(dev);

	op->value = xen_gsi_from_irq(dev->irq);
	dev_data = pci_get_drvdata(dev);
	if (dev_data)
		dev_data->ack_intr = 1;
	return 0;
}

int pciback_enable_msix(struct pciback_device *pdev,
		struct pci_dev *dev, struct xen_pci_op *op)
{
	struct pciback_dev_data *dev_data;
	int i, result;
	struct msix_entry *entries;

 	if (unlikely(verbose_request))
		printk(KERN_DEBUG "pciback: %s: enable MSI-X\n", pci_name(dev));
	if (op->value > SH_INFO_MAX_VEC)
		return -EINVAL;

	entries = kmalloc(op->value * sizeof(*entries), GFP_KERNEL);
	if (entries == NULL)
		return -ENOMEM;

	for (i = 0; i < op->value; i++) {
		entries[i].entry = op->msix_entries[i].entry;
		entries[i].vector = op->msix_entries[i].vector;
	}

	result = pci_enable_msix(dev, entries, op->value);

	for (i = 0; i < op->value; i++) {
		op->msix_entries[i].entry = entries[i].entry;
		op->msix_entries[i].vector =
					xen_gsi_from_irq(entries[i].vector);
	}

	kfree(entries);

	op->value = result;
	dev_data = pci_get_drvdata(dev);
	if (dev_data)
		dev_data->ack_intr = 0;

	return result;
}

int pciback_disable_msix(struct pciback_device *pdev,
		struct pci_dev *dev, struct xen_pci_op *op)
{
	struct pciback_dev_data *dev_data;
 	if (unlikely(verbose_request))
		printk(KERN_DEBUG "pciback: %s: disable MSI-X\n", pci_name(dev));
	pci_disable_msix(dev);

	op->value = xen_gsi_from_irq(dev->irq);
	dev_data = pci_get_drvdata(dev);
	if (dev_data)
		dev_data->ack_intr = 1;
	return 0;
}

