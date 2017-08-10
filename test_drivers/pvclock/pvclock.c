
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kthread.h>

#include <asm/io.h>
#include <asm/xen/hypercall.h>
#include <asm/processor.h>
#include <stdbool.h>
#include <xen/interface/xen.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/mutex.h>



MODULE_LICENSE("GPL");

typedef struct thread_args {
    struct shared_info *shared_info;
} thread_args_t;

struct mutex clock_mutex;
static struct task_struct *update_clock_thread;


int64_t start_time = -1;

inline void make_hypercall(unsigned long rax, unsigned long rdx)
{
    asm volatile (
                  "vmcall\n\t"
                  :
                  : "D" (rdx), "a" (rax)
                  : "memory"
                  );
}

uint64_t get_elapsed_time(struct shared_info *shared_info)
{
    uint64_t current_time;
    if (start_time < 0) 
        start_time = shared_info->wc.sec;
    current_time = shared_info->wc.sec;
    return current_time - start_time;

}


int update_fake_clock(void *data)
{
    thread_args_t *args = (thread_args_t*)data;
    struct shared_info *shared_info = args->shared_info;
    struct timespec ts;
    while (!kthread_should_stop()) {
        uint64_t elapsed_time;
        getnstimeofday(&ts);
        make_hypercall(102, (unsigned long)ts.tv_sec);
        elapsed_time = get_elapsed_time(shared_info);
        printk(KERN_INFO "[PVCLOCK]: %llu second(s) elapsed\n", elapsed_time);
        ssleep(1);
    }
    do_exit(0);
    return 0;
}


static inline uint32_t hypervisor_cpuid_base2(const char *sig, uint32_t leaves)
{
	uint32_t base, eax, signature[3];

	for (base = 0x40000000; base < 0x40010000; base += 0x100) {
		cpuid(base, &eax, &signature[0], &signature[1], &signature[2]);
        printk(KERN_INFO "%d", eax - base >= leaves);
        printk(KERN_INFO "%s", (char*)signature);

		if (!memcmp(sig, signature, 12) &&
		    (leaves == 0 || ((eax - base) >= leaves)))
			return base;
 	}

	return 0;
}

static int __init driver_start(void)
{
    struct shared_info *shared_info;
    thread_args_t args;
    struct start_info *start_info;

    mutex_init(&clock_mutex);
	// Check if bareflank is running
	if (hypervisor_cpuid_base2("XenVMMXenVMM", 2) == 0) {
	    printk(KERN_ERR "[PVCLOCK]: Bareflank is not running. Aborting.\n");
		goto abort;
	}
    
    printk(KERN_INFO "[PVCLOCK]: initializing shared_info page.\n");
    shared_info = kzalloc(sizeof(struct shared_info), GFP_KERNEL);
    
    if (shared_info == NULL) {
        printk(KERN_ERR "[PVCLOCK]: shared_info is NULL. Aborting.\n");
        goto abort;
    }

    make_hypercall(100, (unsigned long)shared_info);
    
    args.shared_info = shared_info;
    update_clock_thread = kthread_run(update_fake_clock, &args, "update_clock");

    start_info = kzalloc(sizeof(struct start_info), GFP_KERNEL);
	printk(KERN_INFO "Making vmcall: INIT_START_INFO\n");
    
  
    if (start_info == NULL) {
        printk(KERN_ERR "[PVCLOCK]: start_info is NULL. Aborting.\n");
        goto abort;
    }
    printk(KERN_INFO "start_info: %p\n", start_info);
    make_hypercall(101, (unsigned long)start_info);
    printk(KERN_INFO "start_info: %p\n", start_info);

    
	printk(KERN_INFO "[PVCLOCK]: initializing start_info page\n");
    if (strcmp(start_info->magic, "xen-TEST-TEST")) {
        printk(KERN_ERR "[PVCLOCK]: failed to initialize start_info page. Aborting.\n");
        goto abort;
    }
    printk(KERN_INFO "[PVCLOCK]: start_info page initialization success.\n");

    
 abort:
	return 0;
}

static void __exit driver_end(void)
{
	kthread_stop(update_clock_thread);
}





module_init(driver_start);
module_exit(driver_end);
