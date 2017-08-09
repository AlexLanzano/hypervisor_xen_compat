
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/xen/hypercall.h>
#include <asm/processor.h>
#include <stdbool.h>

MODULE_LICENSE("GPL");


static inline uint32_t hypervisor_cpuid_base2(const char *sig, uint32_t leaves)
{
	uint32_t base, eax, signature[3];

	for (base = 0x40000000; base < 0x40010000; base += 0x100) {
		cpuid(base, &eax, &signature[0], &signature[1], &signature[2]);

		if (!memcmp(sig, signature, 12) &&
		    (leaves == 0 || ((eax - base) >= leaves)))
			return base;
	}

	return 0;
}

static int __init driver_start(void)
{
	static char hello[] = "Hello";

	// Check if bareflank is running
	if (hypervisor_cpuid_base2("XenVMMXenVMM", 2) == 0) {
	    printk(KERN_ERR "[CONSOLE_IO]: Bareflank is not running. Aborting.\n");
		goto abort;
	}
    printk(KERN_INFO "Bareflank is running\n");
	wrmsrl(0x40000000, (long)hypercall_page);

	/* Check if hypercall_page was populated by Bareflank */
    if ((char *)hypercall_page == 0) {
		printk(KERN_ERR "[CONSOLE_IO]: hypercall_page was not populated. Aborting.\n");
		goto abort;
	}

	printk(KERN_INFO "Making vmcall: console_io\n");
    HYPERVISOR_console_io(CONSOLEIO_write, strlen(hello), hello);
	printk(KERN_INFO "vmcall completed: console_io\n");
	
 abort:
	return 0;
}

static void __exit driver_end(void)
{
	
}





module_init(driver_start);
module_exit(driver_end);
