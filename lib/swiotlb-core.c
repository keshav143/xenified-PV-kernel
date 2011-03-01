/*
 * Dynamic DMA mapping support.
 *
 * This implementation is a fallback for platforms that do not support
 * I/O TLBs (aka DMA address translation hardware).
 * Copyright (C) 2000 Asit Mallick <Asit.K.Mallick@intel.com>
 * Copyright (C) 2000 Goutham Rao <goutham.rao@intel.com>
 * Copyright (C) 2000, 2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * 03/05/07 davidm	Switch from PCI-DMA to generic device DMA API.
 * 00/12/13 davidm	Rename to swiotlb.c and add mark_clean() to avoid
 *			unnecessary i-cache flushing.
 * 04/07/.. ak		Better overflow handling. Assorted fixes.
 * 05/09/10 linville	Add support for syncing ranges, support syncing for
 *			DMA_BIDIRECTIONAL mappings, miscellaneous cleanup.
 * 08/12/11 beckyb	Add highmem support
 */

#include <linux/cache.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/swiotlb.h>
#include <linux/pfn.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/highmem.h>

#include <linux/io.h>
#include <asm/dma.h>
#include <linux/scatterlist.h>

#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/iommu-helper.h>

#define OFFSET(val, align) ((unsigned long)	((val) & ((align) - 1)))

#define SLABS_PER_PAGE (1 << (PAGE_SHIFT - IO_TLB_SHIFT))

/*
 * Minimum IO TLB size to bother booting with.  Systems with mainly
 * 64bit capable cards will only lightly use the swiotlb.  If we can't
 * allocate a contiguous 1MB, we're probably in trouble anyway.
 */
#define IO_TLB_MIN_SLABS ((1<<20) >> IO_TLB_SHIFT)

int swiotlb_force;

/*
 * Used to do a quick range check in do_unmap_single and
 * do_sync_single_*, to see if the memory was in fact allocated by this
 * API.
 */
char *io_tlb_start, *io_tlb_end;

/*
 * The number of IO TLB blocks (in groups of 64) betweeen io_tlb_start and
 * io_tlb_end.  This is command line adjustable via setup_io_tlb_npages.
 */
unsigned long io_tlb_nslabs;

/*
 * When the IOMMU overflows we return a fallback buffer. This sets the size.
 */
unsigned long io_tlb_overflow = 32*1024;

void *io_tlb_overflow_buffer;

/*
 * This is a free list describing the number of free entries available from
 * each index
 */
static unsigned int *io_tlb_list;
static unsigned int io_tlb_index;

/*
 * We need to save away the original address corresponding to a mapped entry
 * for the sync operations.
 */
static phys_addr_t *io_tlb_orig_addr;

/*
 * Protect the above data structures in the map and unmap calls
 */
static DEFINE_SPINLOCK(io_tlb_lock);

static int late_alloc;

static int __init
setup_io_tlb_npages(char *str)
{
	int get_value(const char *token, char *str, char **endp)
	{
		ssize_t len;
		int val = 0;

		len = strlen(token);
		if (!strncmp(str, token, len)) {
			str += len;
			if (*str == '=')
				++str;
			if (*str != '\0')
				val = simple_strtoul(str, endp, 0);
		}
		*endp = str;
		return val;
	}

	int val;

	while (*str) {
		/* The old syntax */
		if (isdigit(*str)) {
			io_tlb_nslabs = simple_strtoul(str, &str, 0);
			/* avoid tail segment of size < IO_TLB_SEGSIZE */
			io_tlb_nslabs = ALIGN(io_tlb_nslabs, IO_TLB_SEGSIZE);
		}
		if (!strncmp(str, "force", 5))
			swiotlb_force = 1;
		/* The new syntax: swiotlb=nslabs=16384,overflow=32768,force */
		val = get_value("nslabs", str, &str);
		if (val)
			io_tlb_nslabs = ALIGN(val, IO_TLB_SEGSIZE);

		val = get_value("overflow", str, &str);
		if (val)
			io_tlb_overflow = val;
		str = strpbrk(str, ",");
		if (!str)
			break;
		str++; /* skip ',' */
	}
	return 1;
}
__setup("swiotlb=", setup_io_tlb_npages);

void swiotlb_print_info(void)
{
	unsigned long bytes = io_tlb_nslabs << IO_TLB_SHIFT;
	phys_addr_t pstart, pend;

	pstart = virt_to_phys(io_tlb_start);
	pend = virt_to_phys(io_tlb_end);

	printk(KERN_INFO "DMA: Placing %luMB software IO TLB between %p - %p\n",
	       bytes >> 20, io_tlb_start, io_tlb_end);
	printk(KERN_INFO "DMA: software IO TLB at phys %#llx - %#llx\n",
	       (unsigned long long)pstart,
	       (unsigned long long)pend);
}

/*
 * Statically reserve bounce buffer space and initialize bounce buffer data
 * structures for the software IO TLB used to implement the DMA API.
 */
void __init
swiotlb_init_early(size_t default_size, int verbose)
{
	unsigned long i, bytes;

	if (!io_tlb_nslabs) {
		io_tlb_nslabs = (default_size >> IO_TLB_SHIFT);
		io_tlb_nslabs = ALIGN(io_tlb_nslabs, IO_TLB_SEGSIZE);
	}

	bytes = io_tlb_nslabs << IO_TLB_SHIFT;

	/*
	 * Get IO TLB memory from the low pages
	 */
	io_tlb_start = alloc_bootmem_low_pages(bytes);
	if (!io_tlb_start)
		panic("DMA: Cannot allocate SWIOTLB buffer");
	io_tlb_end = io_tlb_start + bytes;

	/*
	 * Allocate and initialize the free list array.  This array is used
	 * to find contiguous free memory regions of size up to IO_TLB_SEGSIZE
	 * between io_tlb_start and io_tlb_end.
	 */
	io_tlb_list = alloc_bootmem(io_tlb_nslabs * sizeof(int));
	for (i = 0; i < io_tlb_nslabs; i++)
		io_tlb_list[i] = IO_TLB_SEGSIZE - OFFSET(i, IO_TLB_SEGSIZE);
	io_tlb_index = 0;
	io_tlb_orig_addr = alloc_bootmem(io_tlb_nslabs * sizeof(phys_addr_t));

	/*
	 * Get the overflow emergency buffer
	 */
	io_tlb_overflow_buffer = alloc_bootmem_low(io_tlb_overflow);
	if (!io_tlb_overflow_buffer)
		panic("DMA: Cannot allocate SWIOTLB overflow buffer!\n");
	if (verbose)
		swiotlb_print_info();
}

void __init
swiotlb_init(int verbose)
{
	swiotlb_init_early(64 * (1<<20), verbose);	/* default to 64MB */
}

/*
 * Systems with larger DMA zones (those that don't support ISA) can
 * initialize the swiotlb later using the slab allocator if needed.
 * This should be just like above, but with some error catching.
 */
int
swiotlb_init_late(size_t default_size)
{
	unsigned long i, bytes, req_nslabs = io_tlb_nslabs;
	unsigned int order;

	if (!io_tlb_nslabs) {
		io_tlb_nslabs = (default_size >> IO_TLB_SHIFT);
		io_tlb_nslabs = ALIGN(io_tlb_nslabs, IO_TLB_SEGSIZE);
	}

	/*
	 * Get IO TLB memory from the low pages
	 */
	order = get_order(io_tlb_nslabs << IO_TLB_SHIFT);
	io_tlb_nslabs = SLABS_PER_PAGE << order;
	bytes = io_tlb_nslabs << IO_TLB_SHIFT;

	while ((SLABS_PER_PAGE << order) > IO_TLB_MIN_SLABS) {
		io_tlb_start = (void *)__get_free_pages(GFP_DMA | __GFP_NOWARN,
							order);
		if (io_tlb_start)
			break;
		order--;
	}

	if (!io_tlb_start)
		goto cleanup1;

	if (order != get_order(bytes)) {
		printk(KERN_WARNING "DMA: Warning: only able to allocate %ld MB"
		       " for software IO TLB\n", (PAGE_SIZE << order) >> 20);
		io_tlb_nslabs = SLABS_PER_PAGE << order;
		bytes = io_tlb_nslabs << IO_TLB_SHIFT;
	}
	io_tlb_end = io_tlb_start + bytes;
	memset(io_tlb_start, 0, bytes);

	/*
	 * Allocate and initialize the free list array.  This array is used
	 * to find contiguous free memory regions of size up to IO_TLB_SEGSIZE
	 * between io_tlb_start and io_tlb_end.
	 */
	io_tlb_list = (unsigned int *)__get_free_pages(GFP_KERNEL,
					get_order(io_tlb_nslabs * sizeof(int)));
	if (!io_tlb_list)
		goto cleanup2;

	for (i = 0; i < io_tlb_nslabs; i++)
		io_tlb_list[i] = IO_TLB_SEGSIZE - OFFSET(i, IO_TLB_SEGSIZE);
	io_tlb_index = 0;

	io_tlb_orig_addr = (phys_addr_t *) __get_free_pages(GFP_KERNEL,
				get_order(io_tlb_nslabs * sizeof(phys_addr_t)));
	if (!io_tlb_orig_addr)
		goto cleanup3;

	memset(io_tlb_orig_addr, 0, io_tlb_nslabs * sizeof(phys_addr_t));

	/*
	 * Get the overflow emergency buffer
	 */
	io_tlb_overflow_buffer = (void *)__get_free_pages(GFP_DMA,
					 get_order(io_tlb_overflow));
	if (!io_tlb_overflow_buffer)
		goto cleanup4;

	swiotlb_print_info();

	late_alloc = 1;

	return 0;

cleanup4:
	free_pages((unsigned long)io_tlb_orig_addr,
		   get_order(io_tlb_nslabs * sizeof(phys_addr_t)));
	io_tlb_orig_addr = NULL;
cleanup3:
	free_pages((unsigned long)io_tlb_list,
		   get_order(io_tlb_nslabs * sizeof(int)));
	io_tlb_list = NULL;
cleanup2:
	io_tlb_end = NULL;
	free_pages((unsigned long)io_tlb_start, order);
	io_tlb_start = NULL;
cleanup1:
	io_tlb_nslabs = req_nslabs;
	return -ENOMEM;
}

void __init swiotlb_free(void)
{
	if (!io_tlb_overflow_buffer)
		return;

	if (late_alloc) {
		free_pages((unsigned long)io_tlb_overflow_buffer,
			   get_order(io_tlb_overflow));
		free_pages((unsigned long)io_tlb_orig_addr,
			   get_order(io_tlb_nslabs * sizeof(phys_addr_t)));
		free_pages((unsigned long)io_tlb_list, get_order(io_tlb_nslabs *
								 sizeof(int)));
		free_pages((unsigned long)io_tlb_start,
			   get_order(io_tlb_nslabs << IO_TLB_SHIFT));
	} else {
		free_bootmem_late(__pa(io_tlb_overflow_buffer),
				  io_tlb_overflow);
		free_bootmem_late(__pa(io_tlb_orig_addr),
				  io_tlb_nslabs * sizeof(phys_addr_t));
		free_bootmem_late(__pa(io_tlb_list),
				  io_tlb_nslabs * sizeof(int));
		free_bootmem_late(__pa(io_tlb_start),
				  io_tlb_nslabs << IO_TLB_SHIFT);
	}
}

int is_swiotlb_buffer(phys_addr_t paddr)
{
	return paddr >= virt_to_phys(io_tlb_start) &&
		paddr < virt_to_phys(io_tlb_end);
}

/*
 * Bounce: copy the swiotlb buffer back to the original dma location
 */
void swiotlb_bounce(phys_addr_t phys, char *dma_addr, size_t size,
			   enum dma_data_direction dir)
{
	unsigned long pfn = PFN_DOWN(phys);

	if (PageHighMem(pfn_to_page(pfn))) {
		/* The buffer does not have a mapping.  Map it in and copy */
		unsigned int offset = phys & ~PAGE_MASK;
		char *buffer;
		unsigned int sz = 0;
		unsigned long flags;

		while (size) {
			sz = min_t(size_t, PAGE_SIZE - offset, size);

			local_irq_save(flags);
			buffer = kmap_atomic(pfn_to_page(pfn),
					     KM_BOUNCE_READ);
			if (dir == DMA_TO_DEVICE)
				memcpy(dma_addr, buffer + offset, sz);
			else
				memcpy(buffer + offset, dma_addr, sz);
			kunmap_atomic(buffer, KM_BOUNCE_READ);
			local_irq_restore(flags);

			size -= sz;
			pfn++;
			dma_addr += sz;
			offset = 0;
		}
	} else {
		if (dir == DMA_TO_DEVICE)
			memcpy(dma_addr, phys_to_virt(phys), size);
		else
			memcpy(phys_to_virt(phys), dma_addr, size);
	}
}

/*
 * Allocates bounce buffer and returns its kernel virtual address.
 */
void *
do_map_single(struct device *hwdev, phys_addr_t phys,
	       unsigned long start_dma_addr, size_t size, int dir)
{
	unsigned long flags;
	char *dma_addr;
	unsigned int nslots, stride, index, wrap;
	int i;
	unsigned long mask;
	unsigned long offset_slots;
	unsigned long max_slots;

	mask = dma_get_seg_boundary(hwdev);
	start_dma_addr = start_dma_addr & mask;
	offset_slots = ALIGN(start_dma_addr, 1 << IO_TLB_SHIFT) >> IO_TLB_SHIFT;

	/*
	 * Carefully handle integer overflow which can occur when mask == ~0UL.
	 */
	max_slots = mask + 1
		    ? ALIGN(mask + 1, 1 << IO_TLB_SHIFT) >> IO_TLB_SHIFT
		    : 1UL << (BITS_PER_LONG - IO_TLB_SHIFT);

	/*
	 * For mappings greater than a page, we limit the stride (and
	 * hence alignment) to a page size.
	 */
	nslots = ALIGN(size, 1 << IO_TLB_SHIFT) >> IO_TLB_SHIFT;
	if (size > PAGE_SIZE)
		stride = (1 << (PAGE_SHIFT - IO_TLB_SHIFT));
	else
		stride = 1;

	BUG_ON(!nslots);

	/*
	 * Find suitable number of IO TLB entries size that will fit this
	 * request and allocate a buffer from that IO TLB pool.
	 */
	spin_lock_irqsave(&io_tlb_lock, flags);
	index = ALIGN(io_tlb_index, stride);
	if (index >= io_tlb_nslabs)
		index = 0;
	wrap = index;

	do {
		while (iommu_is_span_boundary(index, nslots, offset_slots,
					      max_slots)) {
			index += stride;
			if (index >= io_tlb_nslabs)
				index = 0;
			if (index == wrap)
				goto not_found;
		}

		/*
		 * If we find a slot that indicates we have 'nslots' number of
		 * contiguous buffers, we allocate the buffers from that slot
		 * and mark the entries as '0' indicating unavailable.
		 */
		if (io_tlb_list[index] >= nslots) {
			int count = 0;

			for (i = index; i < (int) (index + nslots); i++)
				io_tlb_list[i] = 0;
			for (i = index - 1; (OFFSET(i, IO_TLB_SEGSIZE)
				!= IO_TLB_SEGSIZE - 1) && io_tlb_list[i]; i--)
				io_tlb_list[i] = ++count;
			dma_addr = io_tlb_start + (index << IO_TLB_SHIFT);

			/*
			 * Update the indices to avoid searching in the next
			 * round.
			 */
			io_tlb_index = ((index + nslots) < io_tlb_nslabs
					? (index + nslots) : 0);

			goto found;
		}
		index += stride;
		if (index >= io_tlb_nslabs)
			index = 0;
	} while (index != wrap);

not_found:
	spin_unlock_irqrestore(&io_tlb_lock, flags);
	return NULL;
found:
	spin_unlock_irqrestore(&io_tlb_lock, flags);

	/*
	 * Save away the mapping from the original address to the DMA address.
	 * This is needed when we sync the memory.  Then we sync the buffer if
	 * needed.
	 */
	for (i = 0; i < nslots; i++)
		io_tlb_orig_addr[index+i] = phys + (i << IO_TLB_SHIFT);
	if (dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL)
		swiotlb_bounce(phys, dma_addr, size, DMA_TO_DEVICE);

	return dma_addr;
}

/*
 * dma_addr is the kernel virtual address of the bounce buffer to unmap.
 */
void
do_unmap_single(struct device *hwdev, char *dma_addr, size_t size, int dir)
{
	unsigned long flags;
	int i, count, nslots = ALIGN(size, 1 << IO_TLB_SHIFT) >> IO_TLB_SHIFT;
	int index = (dma_addr - io_tlb_start) >> IO_TLB_SHIFT;
	phys_addr_t phys = io_tlb_orig_addr[index];

	/*
	 * First, sync the memory before unmapping the entry
	 */
	if (phys && ((dir == DMA_FROM_DEVICE) || (dir == DMA_BIDIRECTIONAL)))
		swiotlb_bounce(phys, dma_addr, size, DMA_FROM_DEVICE);

	/*
	 * Return the buffer to the free list by setting the corresponding
	 * entries to indicate the number of contigous entries available.
	 * While returning the entries to the free list, we merge the entries
	 * with slots below and above the pool being returned.
	 */
	spin_lock_irqsave(&io_tlb_lock, flags);
	{
		count = ((index + nslots) < ALIGN(index + 1, IO_TLB_SEGSIZE) ?
			 io_tlb_list[index + nslots] : 0);
		/*
		 * Step 1: return the slots to the free list, merging the
		 * slots with superceeding slots
		 */
		for (i = index + nslots - 1; i >= index; i--)
			io_tlb_list[i] = ++count;
		/*
		 * Step 2: merge the returned slots with the preceding slots,
		 * if available (non zero)
		 */
		for (i = index - 1; (OFFSET(i, IO_TLB_SEGSIZE) !=
				IO_TLB_SEGSIZE - 1) && io_tlb_list[i]; i--)
			io_tlb_list[i] = ++count;
	}
	spin_unlock_irqrestore(&io_tlb_lock, flags);
}

void
do_sync_single(struct device *hwdev, char *dma_addr, size_t size,
	    int dir, int target)
{
	int index = (dma_addr - io_tlb_start) >> IO_TLB_SHIFT;
	phys_addr_t phys = io_tlb_orig_addr[index];

	phys += ((unsigned long)dma_addr & ((1 << IO_TLB_SHIFT) - 1));

	switch (target) {
	case SYNC_FOR_CPU:
		if (likely(dir == DMA_FROM_DEVICE || dir == DMA_BIDIRECTIONAL))
			swiotlb_bounce(phys, dma_addr, size, DMA_FROM_DEVICE);
		else
			BUG_ON(dir != DMA_TO_DEVICE);
		break;
	case SYNC_FOR_DEVICE:
		if (likely(dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL))
			swiotlb_bounce(phys, dma_addr, size, DMA_TO_DEVICE);
		else
			BUG_ON(dir != DMA_FROM_DEVICE);
		break;
	default:
		BUG();
	}
}
void
swiotlb_full(struct device *dev, size_t size, int dir, int do_panic)
{
	/*
	 * Ran out of IOMMU space for this operation. This is very bad.
	 * Unfortunately the drivers cannot handle this operation properly.
	 * unless they check for dma_mapping_error (most don't)
	 * When the mapping is small enough return a static buffer to limit
	 * the damage, or panic when the transfer is too big.
	 */
	dev_err(dev, "DMA: Out of SW-IOMMU space for %zu bytes.", size);

	if (size <= io_tlb_overflow || !do_panic)
		return;

	if (dir == DMA_BIDIRECTIONAL)
		panic("DMA: Random memory could be DMA accessed\n");
	if (dir == DMA_FROM_DEVICE)
		panic("DMA: Random memory could be DMA written\n");
	if (dir == DMA_TO_DEVICE)
		panic("DMA: Random memory could be DMA read\n");
}
