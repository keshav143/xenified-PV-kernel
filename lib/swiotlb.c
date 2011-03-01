
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/swiotlb.h>

#include <asm/scatterlist.h>
#include <linux/iommu-helper.h>


/* Note that this doesn't work with highmem page */
static dma_addr_t swiotlb_virt_to_bus(struct device *hwdev,
				      volatile void *address)
{
	return phys_to_dma(hwdev, virt_to_phys(address));
}
void *
swiotlb_alloc_coherent(struct device *hwdev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flags)
{
	dma_addr_t dev_addr;
	void *ret;
	int order = get_order(size);
	u64 dma_mask = DMA_BIT_MASK(32);
	unsigned long start_dma_addr;

	if (hwdev && hwdev->coherent_dma_mask)
		dma_mask = hwdev->coherent_dma_mask;

	ret = (void *)__get_free_pages(flags, order);
	if (ret && swiotlb_virt_to_bus(hwdev, ret) + size - 1 > dma_mask) {
		/*
		 * The allocated memory isn't reachable by the device.
		 */
		free_pages((unsigned long) ret, order);
		ret = NULL;
	}
	if (!ret) {
		/*
		 * We are either out of memory or the device can't DMA
		 * to GFP_DMA memory; fall back on do_map_single(), which
		 * will grab memory from the lowest available address range.
		 */
		start_dma_addr = swiotlb_virt_to_bus(hwdev, io_tlb_start);
		ret = do_map_single(hwdev, 0, start_dma_addr, size,
				    DMA_FROM_DEVICE);
		if (!ret)
			return NULL;
	}

	memset(ret, 0, size);
	dev_addr = swiotlb_virt_to_bus(hwdev, ret);

	/* Confirm address can be DMA'd by device */
	if (dev_addr + size - 1 > dma_mask) {
		dev_err(hwdev, "DMA: hwdev DMA mask = 0x%016Lx, " \
		       "dev_addr = 0x%016Lx\n",
		       (unsigned long long)dma_mask,
		       (unsigned long long)dev_addr);

		/* DMA_TO_DEVICE to avoid memcpy in do_unmap_single */
		do_unmap_single(hwdev, ret, size, DMA_TO_DEVICE);
		return NULL;
	}
	*dma_handle = dev_addr;
	return ret;
}
EXPORT_SYMBOL(swiotlb_alloc_coherent);

void
swiotlb_free_coherent(struct device *hwdev, size_t size, void *vaddr,
		      dma_addr_t dev_addr)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	WARN_ON(irqs_disabled());
	if (!is_swiotlb_buffer(paddr))
		free_pages((unsigned long)vaddr, get_order(size));
	else
		/* DMA_TO_DEVICE to avoid memcpy in do_unmap_single */
		do_unmap_single(hwdev, vaddr, size, DMA_TO_DEVICE);
}
EXPORT_SYMBOL(swiotlb_free_coherent);

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.  The
 * physical address to use is returned.
 *
 * Once the device is given the dma address, the device owns this memory until
 * either swiotlb_unmap_page or swiotlb_dma_sync_single is performed.
 */
dma_addr_t swiotlb_map_page(struct device *dev, struct page *page,
			    unsigned long offset, size_t size,
			    enum dma_data_direction dir,
			    struct dma_attrs *attrs)
{
	unsigned long start_dma_addr;
	phys_addr_t phys = page_to_phys(page) + offset;
	dma_addr_t dev_addr = phys_to_dma(dev, phys);
	void *map;

	BUG_ON(dir == DMA_NONE);
	/*
	 * If the address happens to be in the device's DMA window,
	 * we can safely return the device addr and not worry about bounce
	 * buffering it.
	 */
	if (dma_capable(dev, dev_addr, size) && !swiotlb_force)
		return dev_addr;

	/*
	 * Oh well, have to allocate and map a bounce buffer.
	 */
	start_dma_addr = swiotlb_virt_to_bus(dev, io_tlb_start);
	map = do_map_single(dev, phys, start_dma_addr, size, dir);
	if (!map) {
		swiotlb_full(dev, size, dir, 1);
		map = io_tlb_overflow_buffer;
	}

	dev_addr = swiotlb_virt_to_bus(dev, map);

	/*
	 * Ensure that the address returned is DMA'ble
	 */
	if (!dma_capable(dev, dev_addr, size))
		panic("DMA: swiotlb_map_single: bounce buffer is not DMA'ble");

	return dev_addr;
}
EXPORT_SYMBOL_GPL(swiotlb_map_page);

/*
 * Unmap a single streaming mode DMA translation.  The dma_addr and size must
 * match what was provided for in a previous swiotlb_map_page call.  All
 * other usages are undefined.
 *
 * After this call, reads by the cpu to the buffer are guaranteed to see
 * whatever the device wrote there.
 */
static void unmap_single(struct device *hwdev, dma_addr_t dev_addr,
			 size_t size, int dir)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	BUG_ON(dir == DMA_NONE);

	if (is_swiotlb_buffer(paddr)) {
		do_unmap_single(hwdev, phys_to_virt(paddr), size, dir);
		return;
	}

	if (dir != DMA_FROM_DEVICE)
		return;

	/*
	 * phys_to_virt doesn't work with hihgmem page but we could
	 * call dma_mark_clean() with hihgmem page here. However, we
	 * are fine since dma_mark_clean() is null on POWERPC. We can
	 * make dma_mark_clean() take a physical address if necessary.
	 */
	dma_mark_clean(phys_to_virt(paddr), size);
}

void swiotlb_unmap_page(struct device *hwdev, dma_addr_t dev_addr,
			size_t size, enum dma_data_direction dir,
			struct dma_attrs *attrs)
{
	unmap_single(hwdev, dev_addr, size, dir);
}
EXPORT_SYMBOL_GPL(swiotlb_unmap_page);

/*
 * Make physical memory consistent for a single streaming mode DMA translation
 * after a transfer.
 *
 * If you perform a swiotlb_map_page() but wish to interrogate the buffer
 * using the cpu, yet do not wish to teardown the dma mapping, you must
 * call this function before doing so.  At the next point you give the dma
 * address back to the card, you must first perform a
 * swiotlb_dma_sync_for_device, and then the device again owns the buffer
 */
static void
swiotlb_sync_single(struct device *hwdev, dma_addr_t dev_addr,
		    size_t size, int dir, int target)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	BUG_ON(dir == DMA_NONE);

	if (is_swiotlb_buffer(paddr)) {
		do_sync_single(hwdev, phys_to_virt(paddr), size, dir, target);
		return;
	}

	if (dir != DMA_FROM_DEVICE)
		return;

	dma_mark_clean(phys_to_virt(paddr), size);
}

void
swiotlb_sync_single_for_cpu(struct device *hwdev, dma_addr_t dev_addr,
			    size_t size, enum dma_data_direction dir)
{
	swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_CPU);
}
EXPORT_SYMBOL(swiotlb_sync_single_for_cpu);

void
swiotlb_sync_single_for_device(struct device *hwdev, dma_addr_t dev_addr,
			       size_t size, enum dma_data_direction dir)
{
	swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_DEVICE);
}
EXPORT_SYMBOL(swiotlb_sync_single_for_device);

/*
 * Same as above, but for a sub-range of the mapping.
 */
static void
swiotlb_sync_single_range(struct device *hwdev, dma_addr_t dev_addr,
			  unsigned long offset, size_t size,
			  int dir, int target)
{
	swiotlb_sync_single(hwdev, dev_addr + offset, size, dir, target);
}

void
swiotlb_sync_single_range_for_cpu(struct device *hwdev, dma_addr_t dev_addr,
				  unsigned long offset, size_t size,
				  enum dma_data_direction dir)
{
	swiotlb_sync_single_range(hwdev, dev_addr, offset, size, dir,
				  SYNC_FOR_CPU);
}
EXPORT_SYMBOL_GPL(swiotlb_sync_single_range_for_cpu);

void
swiotlb_sync_single_range_for_device(struct device *hwdev, dma_addr_t dev_addr,
				     unsigned long offset, size_t size,
				     enum dma_data_direction dir)
{
	swiotlb_sync_single_range(hwdev, dev_addr, offset, size, dir,
				  SYNC_FOR_DEVICE);
}
EXPORT_SYMBOL_GPL(swiotlb_sync_single_range_for_device);

/*
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * This is the scatter-gather version of the above swiotlb_map_page
 * interface.  Here the scatter gather list elements are each tagged with the
 * appropriate dma address and length.  They are obtained via
 * sg_dma_{address,length}(SG).
 *
 * NOTE: An implementation may be able to use a smaller number of
 *       DMA address/length pairs than there are SG table elements.
 *       (for example via virtual mapping capabilities)
 *       The routine returns the number of addr/length pairs actually
 *       used, at most nents.
 *
 * Device ownership issues as mentioned above for swiotlb_map_page are the
 * same here.
 */
int
swiotlb_map_sg_attrs(struct device *hwdev, struct scatterlist *sgl, int nelems,
		     enum dma_data_direction dir, struct dma_attrs *attrs)
{
	unsigned long start_dma_addr;
	struct scatterlist *sg;
	int i;

	BUG_ON(dir == DMA_NONE);

	start_dma_addr = swiotlb_virt_to_bus(hwdev, io_tlb_start);
	for_each_sg(sgl, sg, nelems, i) {
		phys_addr_t paddr = sg_phys(sg);
		dma_addr_t dev_addr = phys_to_dma(hwdev, paddr);

		if (swiotlb_force ||
		    !dma_capable(hwdev, dev_addr, sg->length)) {
			void *map = do_map_single(hwdev, sg_phys(sg),
						  start_dma_addr,
						  sg->length, dir);
			if (!map) {
				/* Don't panic here, we expect map_sg users
				   to do proper error handling. */
				swiotlb_full(hwdev, sg->length, dir, 0);
				swiotlb_unmap_sg_attrs(hwdev, sgl, i, dir,
						       attrs);
				sgl[0].dma_length = 0;
				return 0;
			}
			sg->dma_address = swiotlb_virt_to_bus(hwdev, map);
		} else
			sg->dma_address = dev_addr;
		sg->dma_length = sg->length;
	}
	return nelems;
}
EXPORT_SYMBOL(swiotlb_map_sg_attrs);

int
swiotlb_map_sg(struct device *hwdev, struct scatterlist *sgl, int nelems,
	       int dir)
{
	return swiotlb_map_sg_attrs(hwdev, sgl, nelems, dir, NULL);
}
EXPORT_SYMBOL(swiotlb_map_sg);

/*
 * Unmap a set of streaming mode DMA translations.  Again, cpu read rules
 * concerning calls here are the same as for swiotlb_unmap_page() above.
 */
void
swiotlb_unmap_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
		       int nelems, enum dma_data_direction dir,
		       struct dma_attrs *attrs)
{
	struct scatterlist *sg;
	int i;

	BUG_ON(dir == DMA_NONE);

	for_each_sg(sgl, sg, nelems, i)
		unmap_single(hwdev, sg->dma_address, sg->dma_length, dir);

}
EXPORT_SYMBOL(swiotlb_unmap_sg_attrs);

void
swiotlb_unmap_sg(struct device *hwdev, struct scatterlist *sgl, int nelems,
		 int dir)
{
	return swiotlb_unmap_sg_attrs(hwdev, sgl, nelems, dir, NULL);
}
EXPORT_SYMBOL(swiotlb_unmap_sg);

/*
 * Make physical memory consistent for a set of streaming mode DMA translations
 * after a transfer.
 *
 * The same as swiotlb_sync_single_* but for a scatter-gather list, same rules
 * and usage.
 */
static void
swiotlb_sync_sg(struct device *hwdev, struct scatterlist *sgl,
		int nelems, int dir, int target)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nelems, i)
		swiotlb_sync_single(hwdev, sg->dma_address,
				    sg->dma_length, dir, target);
}

void
swiotlb_sync_sg_for_cpu(struct device *hwdev, struct scatterlist *sg,
			int nelems, enum dma_data_direction dir)
{
	swiotlb_sync_sg(hwdev, sg, nelems, dir, SYNC_FOR_CPU);
}
EXPORT_SYMBOL(swiotlb_sync_sg_for_cpu);

void
swiotlb_sync_sg_for_device(struct device *hwdev, struct scatterlist *sg,
			   int nelems, enum dma_data_direction dir)
{
	swiotlb_sync_sg(hwdev, sg, nelems, dir, SYNC_FOR_DEVICE);
}
EXPORT_SYMBOL(swiotlb_sync_sg_for_device);

int
swiotlb_dma_mapping_error(struct device *hwdev, dma_addr_t dma_addr)
{
	return (dma_addr == swiotlb_virt_to_bus(hwdev, io_tlb_overflow_buffer));
}
EXPORT_SYMBOL(swiotlb_dma_mapping_error);

/*
 * Return whether the given device DMA address mask can be supported
 * properly.  For example, if your device can only drive the low 24-bits
 * during bus mastering, then you would pass 0x00ffffff as the mask to
 * this function.
 */
int
swiotlb_dma_supported(struct device *hwdev, u64 mask)
{
	return swiotlb_virt_to_bus(hwdev, io_tlb_end - 1) <= mask;
}
EXPORT_SYMBOL(swiotlb_dma_supported);
