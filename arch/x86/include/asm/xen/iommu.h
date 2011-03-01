#ifndef ASM_X86__XEN_IOMMU_H

#ifdef CONFIG_PCI_XEN
extern void xen_iommu_init(void);
#else
static inline void xen_iommu_init(void)
{
}
#endif

#endif

