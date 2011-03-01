#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/io.h>
#include <linux/bug.h>

#include <xen/interface/xen.h>
#include <xen/grant_table.h>
#include <xen/page.h>
#include <xen/xen-ops.h>

#include <asm/iommu.h>
#include <asm/swiotlb.h>
#include <asm/tlbflush.h>

#define IOMMU_BUG_ON(test)				\
do {							\
	if (unlikely(test)) {				\
		printk(KERN_ALERT "Fatal DMA error! "	\
		       "Please use 'swiotlb=force'\n");	\
		BUG();					\
	}						\
} while (0)

/* Print address range with message */
#define PAR(msg, addr, size)					\
do {							\
	printk(msg "[%#llx - %#llx]\n",			\
	(unsigned long long)addr,			\
	(unsigned long long)addr + size);		\
} while (0)

static inline int address_needs_mapping(struct device *hwdev,
						dma_addr_t addr)
{
	dma_addr_t mask = DMA_BIT_MASK(32);
	int ret;

	/* If the device has a mask, use it, otherwise default to 32 bits */
	if (hwdev)
		mask = *hwdev->dma_mask;

	ret = (addr & ~mask) != 0;

	if (ret) {
		printk(KERN_ERR "dma address needs mapping\n");
		printk(KERN_ERR "mask: %#llx\n address: [%#llx]\n", mask, addr);
	}
	return ret;
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

static inline void xen_dma_unmap_page(struct page *page)
{
	/* Xen TODO: 2.6.18 xen calls __gnttab_dma_unmap_page here
	 * to deal with foreign pages.  We'll need similar logic here at
	 * some point.
	 */
}

/* Gets dma address of a page */
static inline dma_addr_t xen_dma_map_page(struct page *page)
{
	/* Xen TODO: 2.6.18 xen calls __gnttab_dma_map_page here to deal
	 * with foreign pages.  We'll need similar logic here at some
	 * point.
	 */
	return ((dma_addr_t)pfn_to_mfn(page_to_pfn(page))) << PAGE_SHIFT;
}

static int xen_map_sg(struct device *hwdev, struct scatterlist *sg,
		      int nents,
		      enum dma_data_direction direction,
		      struct dma_attrs *attrs)
{
	struct scatterlist *s;
	struct page *page;
	int i, rc;

	BUG_ON(direction == DMA_NONE);
	WARN_ON(nents == 0 || sg[0].length == 0);

	for_each_sg(sg, s, nents, i) {
		BUG_ON(!sg_page(s));
		page = sg_page(s);
		s->dma_address = xen_dma_map_page(page) + s->offset;
		s->dma_length = s->length;
		IOMMU_BUG_ON(range_straddles_page_boundary(
				page_to_phys(page), s->length));
	}

	rc = nents;

	flush_write_buffers();
	return rc;
}

static void xen_unmap_sg(struct device *hwdev, struct scatterlist *sg,
			 int nents,
			 enum dma_data_direction direction,
			 struct dma_attrs *attrs)
{
	struct scatterlist *s;
	struct page *page;
	int i;

	for_each_sg(sg, s, nents, i) {
		page = pfn_to_page(mfn_to_pfn(PFN_DOWN(s->dma_address)));
		xen_dma_unmap_page(page);
	}
}

static void *xen_alloc_coherent(struct device *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t gfp)
{
	void *ret;
	unsigned int order = get_order(size);
	unsigned long vstart;
	u64 mask;

	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_HIGHMEM);

	if (dma_alloc_from_coherent(dev, size, dma_handle, &ret))
		return ret;

	if (dev == NULL || (dev->coherent_dma_mask < DMA_BIT_MASK(32)))
		gfp |= GFP_DMA;

	vstart = __get_free_pages(gfp, order);
	ret = (void *)vstart;

	if (dev != NULL && dev->coherent_dma_mask)
		mask = dev->coherent_dma_mask;
	else
		mask = DMA_BIT_MASK(32);

	if (ret != NULL) {
		if (xen_create_contiguous_region(vstart, order,
						 fls64(mask)) != 0) {
			free_pages(vstart, order);
			return NULL;
		}
		memset(ret, 0, size);
		*dma_handle = virt_to_machine(ret).maddr;
	}
	return ret;
}

static void xen_free_coherent(struct device *dev, size_t size,
			      void *vaddr, dma_addr_t dma_addr)
{
	int order = get_order(size);

	if (dma_release_from_coherent(dev, order, vaddr))
		return;

	xen_destroy_contiguous_region((unsigned long)vaddr, order);
	free_pages((unsigned long)vaddr, order);
}

static dma_addr_t xen_map_page(struct device *dev, struct page *page,
			       unsigned long offset, size_t size,
			       enum dma_data_direction direction,
			       struct dma_attrs *attrs)
{
	dma_addr_t dma;

	BUG_ON(direction == DMA_NONE);

	WARN_ON(size == 0);

	dma = xen_dma_map_page(page) + offset;

	IOMMU_BUG_ON(address_needs_mapping(dev, dma));
	flush_write_buffers();
	return dma;
}

static void xen_unmap_page(struct device *dev, dma_addr_t dma_addr,
			   size_t size,
			   enum dma_data_direction direction,
			   struct dma_attrs *attrs)
{
	BUG_ON(direction == DMA_NONE);
	xen_dma_unmap_page(pfn_to_page(mfn_to_pfn(PFN_DOWN(dma_addr))));
}

static struct dma_map_ops xen_dma_ops = {
	.dma_supported = NULL,

	.alloc_coherent = xen_alloc_coherent,
	.free_coherent = xen_free_coherent,

	.map_page = xen_map_page,
	.unmap_page = xen_unmap_page,

	.map_sg = xen_map_sg,
	.unmap_sg = xen_unmap_sg,

	.mapping_error = NULL,

	.is_phys = 0,
};

static struct dma_map_ops xen_swiotlb_dma_ops = {
	.dma_supported = swiotlb_dma_supported,

	.alloc_coherent = xen_alloc_coherent,
	.free_coherent = xen_free_coherent,

	.map_page = swiotlb_map_page,
	.unmap_page = swiotlb_unmap_page,

	.map_sg = swiotlb_map_sg_attrs,
	.unmap_sg = swiotlb_unmap_sg_attrs,

	.mapping_error = swiotlb_dma_mapping_error,

	.is_phys = 0,
};

void __init xen_iommu_init(void)
{
	if (!xen_pv_domain())
		return;

	printk(KERN_INFO "Xen: Initializing Xen DMA ops\n");

	force_iommu = 0;
	dma_ops = &xen_dma_ops;

	if (swiotlb) {
		printk(KERN_INFO "Xen: Enabling DMA fallback to swiotlb\n");
		dma_ops = &xen_swiotlb_dma_ops;
	}
}

