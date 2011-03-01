#include <xen/acpi.h>

#include <xen/interface/platform.h>
#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

int acpi_notify_hypervisor_state(u8 sleep_state,
				 u32 pm1a_cnt, u32 pm1b_cnt)
{
	struct xen_platform_op op = {
		.cmd = XENPF_enter_acpi_sleep,
		.interface_version = XENPF_INTERFACE_VERSION,
		.u = {
			.enter_acpi_sleep = {
				.pm1a_cnt_val = (u16)pm1a_cnt,
				.pm1b_cnt_val = (u16)pm1b_cnt,
				.sleep_state = sleep_state,
			},
		},
	};

	return HYPERVISOR_dom0_op(&op);
}
