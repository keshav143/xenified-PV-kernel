/* An software based IOMMU that utilizes the swiotlb-core fuctionality.
 * It can function on Xen when there are PCI devices present.*/


#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <asm/dma.h>
#include <linux/scatterlist.h>
#include <xen/interface/xen.h>
#include <xen/grant_table.h>

#include <asm/xen/page.h>
#include <xen/page.h>
#include <xen/xen-ops.h>

static dma_addr_t xen_phys_to_bus(phys_addr_t paddr)
{
	return phys_to_machine(XPADDR(paddr)).maddr;;
}

static phys_addr_t xen_bus_to_phys(dma_addr_t baddr)
{
	return machine_to_phys(XMADDR(baddr)).paddr;
}

static dma_addr_t xen_virt_to_bus(void *address)
{
	return xen_phys_to_bus(virt_to_phys(address));
}

static int check_pages_physically_contiguous(unsigned long pfn,
					     unsigned int offset,
					     size_t length)
{
	unsigned long next_mfn;
	int i;
	int nr_pages;

	next_mfn = pfn_to_mfn(pfn);
	nr_pages = (offset + length + PAGE_SIZE-1) >> PAGE_SHIFT;

	for (i = 1; i < nr_pages; i++) {
		if (pfn_to_mfn(++pfn) != ++next_mfn)
			return 0;
	}
	return 1;
}

static int range_straddles_page_boundary(phys_addr_t p, size_t size)
{
	unsigned long pfn = PFN_DOWN(p);
	unsigned int offset = p & ~PAGE_MASK;

	if (offset + size <= PAGE_SIZE)
		return 0;
	if (check_pages_physically_contiguous(pfn, offset, size))
		return 0;
	return 1;
}


bool xen_dma_capable(struct device *dev, dma_addr_t dev_addr,
		     phys_addr_t phys, size_t size)
{
	int rc = 0;

	rc =  dma_capable(dev, dev_addr, size) &&
		 !range_straddles_page_boundary(phys, size);
	return rc;
}

static int is_xen_swiotlb_buffer(dma_addr_t dma_addr)
{
	unsigned long mfn = PFN_DOWN(dma_addr);
	unsigned long pfn = mfn_to_local_pfn(mfn);

	/* If the address is outside our domain, it CAN have the same virtual
	* address as another address in our domain. Hence only check address
	* within our domain. */
	if (pfn_valid(pfn))
		return is_swiotlb_buffer(PFN_PHYS(pfn));

	return 0;
}
void *
xen_swiotlb_alloc_coherent(struct device *hwdev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flags)
{
	void *ret;
	int order = get_order(size);
	u64 dma_mask = DMA_BIT_MASK(32);
	unsigned long vstart;

	/*
	* Ignore region specifiers - the kernel's ideas of
	* pseudo-phys memory layout has nothing to do with the
	* machine physical layout.  We can't allocate highmem
	* because we can't return a pointer to it.
	*/
	flags &= ~(__GFP_DMA | __GFP_HIGHMEM);

	if (dma_alloc_from_coherent(hwdev, size, dma_handle, &ret))
		return ret;

	vstart = __get_free_pages(flags, order);
	ret = (void *)vstart;

	if (hwdev && hwdev->coherent_dma_mask)
		dma_mask = dma_alloc_coherent_mask(hwdev, flags);

	if (ret) {
		if (xen_create_contiguous_region(vstart, order,
						 fls64(dma_mask)) != 0) {
			free_pages(vstart, order);
			return NULL;
		}
		memset(ret, 0, size);
		*dma_handle = virt_to_machine(ret).maddr;
	}
	return ret;
}
EXPORT_SYMBOL(xen_swiotlb_alloc_coherent);

void
xen_swiotlb_free_coherent(struct device *hwdev, size_t size, void *vaddr,
		      dma_addr_t dev_addr)
{
	int order = get_order(size);

	if (dma_release_from_coherent(hwdev, order, vaddr))
		return;

	xen_destroy_contiguous_region((unsigned long)vaddr, order);
	free_pages((unsigned long)vaddr, order);
}
EXPORT_SYMBOL(xen_swiotlb_free_coherent);


static int max_dma_bits = 32;

static int 
xen_swiotlb_fixup(void *buf, size_t size, unsigned long nslabs)
{
	int i, rc;
	int dma_bits;

	printk(KERN_INFO "xen_swiotlb_fixup: buf=%p size=%zu\n",
		buf, size);

	dma_bits = get_order(IO_TLB_SEGSIZE << IO_TLB_SHIFT) + PAGE_SHIFT;

	i = 0;
	do {
		int slabs = min(nslabs - i, (unsigned long)IO_TLB_SEGSIZE);

		do {
			rc = xen_create_contiguous_region(
				(unsigned long)buf + (i << IO_TLB_SHIFT),
				get_order(slabs << IO_TLB_SHIFT),
				dma_bits);
		} while (rc && dma_bits++ < max_dma_bits);
		if (rc)
			return rc;

		i += slabs;
	} while(i < nslabs);
	return 0;
}

void __init xen_swiotlb_init(int verbose)
{
	int rc = 0;

	swiotlb_init_early(64 * (1<<20), verbose);

  	if ((rc = xen_swiotlb_fixup(io_tlb_start,
			  io_tlb_nslabs << IO_TLB_SHIFT,
			  io_tlb_nslabs)))
		goto error;

	if ((rc = xen_swiotlb_fixup(io_tlb_overflow_buffer,
			io_tlb_overflow,
			io_tlb_overflow >> IO_TLB_SHIFT)))
		goto error;

	return;
error:	
	panic("DMA(%d): Failed to exchange pages allocated for DMA with Xen! "\
	      "We either don't have the permission or you do not have enough"\
	      "free memory under 4GB!\n", rc);
}

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.  The
 * physical address to use is returned.
 *
 * Once the device is given the dma address, the device owns this memory until
 * either xen_swiotlb_unmap_page or xen_swiotlb_dma_sync_single is performed.
 */
dma_addr_t xen_swiotlb_map_page(struct device *dev, struct page *page,
			    unsigned long offset, size_t size,
			    enum dma_data_direction dir,
			    struct dma_attrs *attrs)
{
	unsigned long start_dma_addr;
	phys_addr_t phys = page_to_phys(page) + offset;
	dma_addr_t dev_addr = xen_phys_to_bus(phys);
	void *map;

	BUG_ON(dir == DMA_NONE);
	/*
	 * If the address happens to be in the device's DMA window,
	 * we can safely return the device addr and not worry about bounce
	 * buffering it.
	 */
	if (dma_capable(dev, dev_addr, size) &&
	    !range_straddles_page_boundary(phys, size) && !swiotlb_force)
		return dev_addr;

	/*
	 * Oh well, have to allocate and map a bounce buffer.
	 */
	start_dma_addr = xen_virt_to_bus(io_tlb_start);
	map = do_map_single(dev, phys, start_dma_addr, size, dir);
	if (!map) {
		swiotlb_full(dev, size, dir, 1);
		map = io_tlb_overflow_buffer;
	}

	dev_addr = xen_virt_to_bus(map);

	/*
	 * Ensure that the address returned is DMA'ble
	 */
	if (!dma_capable(dev, dev_addr, size))
		panic("DMA: xen_swiotlb_map_single: bounce buffer  is not " \
		      "DMA'ble\n");
	return dev_addr;
}
EXPORT_SYMBOL_GPL(xen_swiotlb_map_page);

/*
 * Unmap a single streaming mode DMA translation.  The dma_addr and size must
 * match what was provided for in a previous xen_swiotlb_map_page call.  All
 * other usages are undefined.
 *
 * After this call, reads by the cpu to the buffer are guaranteed to see
 * whatever the device wrote there.
 */
static void unmap_single(struct device *hwdev, dma_addr_t dev_addr,
			 size_t size, int dir)
{
	phys_addr_t paddr = xen_bus_to_phys(dev_addr);

	BUG_ON(dir == DMA_NONE);

	/* NOTE: We use dev_addr here, not paddr! */
	if (is_xen_swiotlb_buffer(dev_addr)) {
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

void xen_swiotlb_unmap_page(struct device *hwdev, dma_addr_t dev_addr,
			size_t size, enum dma_data_direction dir,
			struct dma_attrs *attrs)
{
	unmap_single(hwdev, dev_addr, size, dir);
}
EXPORT_SYMBOL_GPL(xen_swiotlb_unmap_page);

/*
 * Make physical memory consistent for a single streaming mode DMA translation
 * after a transfer.
 *
 * If you perform a xen_swiotlb_map_page() but wish to interrogate the buffer
 * using the cpu, yet do not wish to teardown the dma mapping, you must
 * call this function before doing so.  At the next point you give the dma
 * address back to the card, you must first perform a
 * xen_swiotlb_dma_sync_for_device, and then the device again owns the buffer
 */
static void
xen_swiotlb_sync_single(struct device *hwdev, dma_addr_t dev_addr,
		    size_t size, int dir, int target)
{
	phys_addr_t paddr = xen_bus_to_phys(dev_addr);

	BUG_ON(dir == DMA_NONE);

	if (is_xen_swiotlb_buffer(dev_addr)) {
		do_sync_single(hwdev, phys_to_virt(paddr), size, dir, target);
		return;
	}

	if (dir != DMA_FROM_DEVICE)
		return;

	dma_mark_clean(phys_to_virt(paddr), size);
}

void
xen_swiotlb_sync_single_for_cpu(struct device *hwdev, dma_addr_t dev_addr,
			    size_t size, enum dma_data_direction dir)
{
	xen_swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_CPU);
}
EXPORT_SYMBOL(xen_swiotlb_sync_single_for_cpu);

void
xen_swiotlb_sync_single_for_device(struct device *hwdev, dma_addr_t dev_addr,
			       size_t size, enum dma_data_direction dir)
{
	xen_swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_DEVICE);
}
EXPORT_SYMBOL(xen_swiotlb_sync_single_for_device);

/*
 * Same as above, but for a sub-range of the mapping.
 */
static void
xen_swiotlb_sync_single_range(struct device *hwdev, dma_addr_t dev_addr,
			  unsigned long offset, size_t size,
			  int dir, int target)
{
	xen_swiotlb_sync_single(hwdev, dev_addr + offset, size, dir, target);
}

void
xen_swiotlb_sync_single_range_for_cpu(struct device *hwdev, dma_addr_t dev_addr,
				  unsigned long offset, size_t size,
				  enum dma_data_direction dir)
{
	xen_swiotlb_sync_single_range(hwdev, dev_addr, offset, size, dir,
				  SYNC_FOR_CPU);
}
EXPORT_SYMBOL_GPL(xen_swiotlb_sync_single_range_for_cpu);

void
xen_swiotlb_sync_single_range_for_device(struct device *hwdev,
					 dma_addr_t dev_addr,
					 unsigned long offset, size_t size,
					 enum dma_data_direction dir)
{
	xen_swiotlb_sync_single_range(hwdev, dev_addr, offset, size, dir,
				  SYNC_FOR_DEVICE);
}
EXPORT_SYMBOL_GPL(xen_swiotlb_sync_single_range_for_device);

/*
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * This is the scatter-gather version of the above xen_swiotlb_map_page
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
 * Device ownership issues as mentioned above for xen_swiotlb_map_page are the
 * same here.
 */
int
xen_swiotlb_map_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
			 int nelems, enum dma_data_direction dir,
			 struct dma_attrs *attrs)
{
	unsigned long start_dma_addr;
	struct scatterlist *sg;
	int i;
	BUG_ON(dir == DMA_NONE);

	start_dma_addr = xen_virt_to_bus(io_tlb_start);
	for_each_sg(sgl, sg, nelems, i) {
		phys_addr_t paddr = sg_phys(sg);
		dma_addr_t dev_addr = xen_phys_to_bus(paddr);

		if (swiotlb_force || 
		    !dma_capable(hwdev, dev_addr, sg->length) ||
		    range_straddles_page_boundary(paddr, sg->length)) {
			void *map = do_map_single(hwdev, sg_phys(sg),
						  start_dma_addr,
						  sg->length, dir);
			if (!map) {
				/* Don't panic here, we expect map_sg users
				   to do proper error handling. */
				swiotlb_full(hwdev, sg->length, dir, 0);
				xen_swiotlb_unmap_sg_attrs(hwdev, sgl, i, dir,
						       attrs);
				sgl[0].dma_length = 0;
				return 0;
			}
			sg->dma_address = xen_virt_to_bus(map);
		} else
			sg->dma_address = dev_addr;
		sg->dma_length = sg->length;
	}
	return nelems;
}
EXPORT_SYMBOL(xen_swiotlb_map_sg_attrs);

int
xen_swiotlb_map_sg(struct device *hwdev, struct scatterlist *sgl, int nelems,
	       int dir)
{
	return xen_swiotlb_map_sg_attrs(hwdev, sgl, nelems, dir, NULL);
}
EXPORT_SYMBOL(xen_swiotlb_map_sg);

/*
 * Unmap a set of streaming mode DMA translations.  Again, cpu read rules
 * concerning calls here are the same as for xen_swiotlb_unmap_page() above.
 */
void
xen_swiotlb_unmap_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
			   int nelems, enum dma_data_direction dir,
			   struct dma_attrs *attrs)
{
	struct scatterlist *sg;
	int i;

	BUG_ON(dir == DMA_NONE);

	for_each_sg(sgl, sg, nelems, i)
		unmap_single(hwdev, sg->dma_address, sg->dma_length, dir);

}
EXPORT_SYMBOL(xen_swiotlb_unmap_sg_attrs);

void
xen_swiotlb_unmap_sg(struct device *hwdev, struct scatterlist *sgl, int nelems,
		 int dir)
{
	return xen_swiotlb_unmap_sg_attrs(hwdev, sgl, nelems, dir, NULL);
}
EXPORT_SYMBOL(xen_swiotlb_unmap_sg);

/*
 * Make physical memory consistent for a set of streaming mode DMA translations
 * after a transfer.
 *
 * The same as xen_swiotlb_sync_single_* but for a scatter-gather list,
 * same rules and usage.
 */
static void
xen_swiotlb_sync_sg(struct device *hwdev, struct scatterlist *sgl,
		int nelems, int dir, int target)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nelems, i)
		xen_swiotlb_sync_single(hwdev, sg->dma_address,
				    sg->dma_length, dir, target);
}

void
xen_swiotlb_sync_sg_for_cpu(struct device *hwdev, struct scatterlist *sg,
			int nelems, enum dma_data_direction dir)
{
	xen_swiotlb_sync_sg(hwdev, sg, nelems, dir, SYNC_FOR_CPU);
}
EXPORT_SYMBOL(xen_swiotlb_sync_sg_for_cpu);

void
xen_swiotlb_sync_sg_for_device(struct device *hwdev, struct scatterlist *sg,
			   int nelems, enum dma_data_direction dir)
{
	xen_swiotlb_sync_sg(hwdev, sg, nelems, dir, SYNC_FOR_DEVICE);
}
EXPORT_SYMBOL(xen_swiotlb_sync_sg_for_device);

int
xen_swiotlb_dma_mapping_error(struct device *hwdev, dma_addr_t dma_addr)
{
	return (dma_addr == xen_virt_to_bus(io_tlb_overflow_buffer));
}
EXPORT_SYMBOL(xen_swiotlb_dma_mapping_error);

/*
 * Return whether the given device DMA address mask can be supported
 * properly.  For example, if your device can only drive the low 24-bits
 * during bus mastering, then you would pass 0x00ffffff as the mask to
 * this function.
 */
int
xen_swiotlb_dma_supported(struct device *hwdev, u64 mask)
{
	return xen_virt_to_bus(io_tlb_end - 1) <= mask;
}
EXPORT_SYMBOL(xen_swiotlb_dma_supported);
