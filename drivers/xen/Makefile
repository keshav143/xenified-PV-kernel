obj-y	+= grant-table.o features.o events.o manage.o biomerge.o pcpu.o
obj-y	+= xenbus/

nostackp := $(call cc-option, -fno-stack-protector)
CFLAGS_features.o			:= $(nostackp)

obj-$(CONFIG_PCI)			+= pci.o
obj-$(CONFIG_HOTPLUG_CPU)		+= cpu_hotplug.o
obj-$(CONFIG_XEN_XENCOMM)		+= xencomm.o
obj-$(CONFIG_XEN_BALLOON)		+= balloon.o
obj-$(CONFIG_XEN_DEV_EVTCHN)		+= xen-evtchn.o
obj-$(CONFIG_XEN_GNTDEV)		+= xen-gntdev.o
obj-$(CONFIG_XEN_PCIDEV_BACKEND)	+= pciback/
obj-$(CONFIG_XEN_BLKDEV_BACKEND)	+= blkback/
obj-$(CONFIG_XEN_BLKDEV_TAP)            += blktap/
obj-$(CONFIG_XEN_NETDEV_BACKEND)	+= netback/
obj-$(CONFIG_XENFS)			+= xenfs/
obj-$(CONFIG_XEN_SYS_HYPERVISOR)	+= sys-hypervisor.o
obj-$(CONFIG_XEN_MCE)		+= mce.o

obj-$(CONFIG_XEN_S3)           += acpi.o
obj-$(CONFIG_ACPI_PROCESSOR_XEN) += acpi_processor.o
obj-$(CONFIG_ACPI_HOTPLUG_MEMORY)  += xen_acpi_memhotplug.o
obj-$(CONFIG_XEN_PLATFORM_PCI)	+= platform-pci.o

xen-evtchn-y				:= evtchn.o
xen-gntdev-y				:= gntdev.o
