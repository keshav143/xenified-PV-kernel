/* Glue code to lib/swiotlb-xen.c */

#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>

#include <asm/xen/hypervisor.h>

int xen_swiotlb __read_mostly;

static struct dma_map_ops xen_swiotlb_dma_ops = {
	.mapping_error = xen_swiotlb_dma_mapping_error,
	.alloc_coherent = xen_swiotlb_alloc_coherent,
	.free_coherent = xen_swiotlb_free_coherent,
	.sync_single_for_cpu = xen_swiotlb_sync_single_for_cpu,
	.sync_single_for_device = xen_swiotlb_sync_single_for_device,
	.sync_single_range_for_cpu = xen_swiotlb_sync_single_range_for_cpu,
	.sync_single_range_for_device = xen_swiotlb_sync_single_range_for_device,
	.sync_sg_for_cpu = xen_swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device = xen_swiotlb_sync_sg_for_device,
	.map_sg = xen_swiotlb_map_sg_attrs,
	.unmap_sg = xen_swiotlb_unmap_sg_attrs,
	.map_page = xen_swiotlb_map_page,
	.unmap_page = xen_swiotlb_unmap_page,
	.dma_supported = xen_swiotlb_dma_supported,
};

/*
 * pci_swiotlb_detect - set swiotlb to 1 if necessary
 *
 * This returns non-zero if we are forced to use swiotlb (by the boot
 * option).
 */
int __init pci_xen_swiotlb_detect(void)
{

	if (xen_pv_domain() && (xen_initial_domain() || swiotlb))
		xen_swiotlb = 1;

	/* If we are running under Xen, we MUST disable the native SWIOTLB */
	if (xen_pv_domain())
		swiotlb = 0;

	return xen_swiotlb;
}

void __init pci_xen_swiotlb_init(void)
{
	if (xen_swiotlb) {
		xen_swiotlb_init(1);
		dma_ops = &xen_swiotlb_dma_ops;
	}
}
