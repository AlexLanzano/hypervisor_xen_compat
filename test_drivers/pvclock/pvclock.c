
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
#include <asm/tsc.h>
#include <linux/clocksource.h>
#include <asm/msr.h>

MODULE_LICENSE("GPL");

#define NANOSECONDS(delta) ((1000000ULL * delta) / tsc_khz)

typedef struct thread_args {
    struct shared_info *shared_info;
} thread_args_t;

struct shared_info *shared_info;
struct start_info *start_info;
static struct task_struct *update_clock_thread;
spinlock_t lock;


/**
 * clocks_calc_mult_shift - calculate mult/shift factors for scaled math of clocks
 * @mult:	pointer to mult variable
 * @shift:	pointer to shift variable
 * @from:	frequency to convert from
 * @to:		frequency to convert to
 * @maxsec:	guaranteed runtime conversion range in seconds
 *
 * The function evaluates the shift/mult pair for the scaled math
 * operations of clocksources and clockevents.
 *
 * @to and @from are frequency values in HZ. For clock sources @to is
 * NSEC_PER_SEC == 1GHz and @from is the counter frequency. For clock
 * event @to is the counter frequency and @from is NSEC_PER_SEC.
 *
 * The @maxsec conversion range argument controls the time frame in
 * seconds which must be covered by the runtime conversion with the
 * calculated mult and shift factors. This guarantees that no 64bit
 * overflow happens when the input value of the conversion is
 * multiplied with the calculated mult factor. Larger ranges may
 * reduce the conversion accuracy by chosing smaller mult and shift
 * factors.
 */
void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
	u64 tmp;
	u32 sft, sftacc= 32;

	/*
	 * Calculate the shift factor which is limiting the conversion
	 * range:
	 */
	tmp = ((u64)maxsec * from) >> 32;
	while (tmp) {
		tmp >>=1;
		sftacc--;
	}

	/*
	 * Find the conversion shift/mult pair which has the best
	 * accuracy and fits the maxsec conversion range:
	 */
	for (sft = 32; sft > 0; sft--) {
		tmp = (u64) to << sft;
		tmp += from / 2;
		do_div(tmp, from);
		if ((tmp >> sftacc) == 0)
			break;
	}
	*mult = tmp;
	*shift = sft;
}





inline void make_hypercall0(unsigned long rax)
{
    asm volatile (
                  "vmcall\n\t"
                  :
                  : "a" (rax)
                  : "memory"
                  );
}

inline void make_hypercall1(unsigned long rax, unsigned long rdi)
{
    asm volatile (
                  "vmcall\n\t"
                  :
                  : "D" (rdi), "a" (rax)
                  : "memory"
                  );
}

inline void make_hypercall2(unsigned long rax, unsigned long rdi, unsigned long rsi)
{
    asm volatile (
                  "vmcall\n\t"
                  :
                  :  "a" (rax), "D" (rdi), "S" (rsi)
                  : "memory"
                  );
}
inline void make_hypercall3(unsigned long rax, unsigned long rdi,
                            unsigned long rsi, unsigned long rdx)
{
    asm volatile (
                  "vmcall\n\t"
                  :
                  :  "a" (rax), "D" (rdi), "S" (rsi), "d" (rdx)
                  : "memory"
                  );
}

uint64_t get_elapsed_time(void)
{
    uint64_t tsc, nsec_elapsed;
    unsigned long flags;
    uint64_t tsc_timestamp = shared_info->vcpu_info[0].time.tsc_timestamp; 
    
    spin_lock_irqsave(&lock, flags);
    tsc = rdtsc();
    spin_unlock_irqrestore(&lock, flags);

    tsc -= tsc_timestamp;
    nsec_elapsed = NANOSECONDS(tsc);
    return nsec_elapsed / 1000000000;
}


int update_fake_clock(void *data)
{
    thread_args_t *args = (thread_args_t*)data;
    
    shared_info = args->shared_info;

    
    
    while (!kthread_should_stop()) {
        uint64_t sec;
        make_hypercall1(102, (unsigned long)shared_info);
        
        sec = get_elapsed_time();
        printk(KERN_INFO "[PVCLOCK]: %llu second(s) elapsed\n", sec);
        msleep(500);
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

bool bareflank_is_running(void)
{
    if (hypervisor_cpuid_base("XenVMMXenVMM", 2) == 0) {
	    printk(KERN_ERR "[PVCLOCK]: Bareflank is not running. Aborting.\n");
		return false;
	}
    return true;
    
}

bool init_shared_info(void)
{
    uint64_t tsc;
    uint32_t mult, shift;
    unsigned long flags;
    struct timespec ts;

    printk(KERN_INFO "[PVCLOCK]: initializing shared_info page.\n");
    shared_info = kzalloc(sizeof(struct shared_info), GFP_KERNEL);
    
    if (shared_info == NULL) {
        printk(KERN_ERR "[PVCLOCK]: shared_info is NULL. Aborting.\n");
        return false;
    }

    clocks_calc_mult_shift(&mult, &shift, tsc_khz, NSEC_PER_MSEC, 0);

    shared_info->vcpu_info[0].time.tsc_to_system_mul = mult;
    shared_info->vcpu_info[0].time.tsc_shift = (uint8_t)shift;

    spin_lock_irqsave(&lock, flags);
    getnstimeofday(&ts);
    tsc = rdtsc();
    spin_unlock_irqrestore(&lock, flags);
    shared_info->vcpu_info[0].time.tsc_timestamp = tsc;
    shared_info->wc.sec = ts.tv_sec;
    shared_info->wc.nsec = ts.tv_nsec;
   
    make_hypercall2(100, (unsigned long)shared_info, tsc_khz);
    return true;
    
}

bool init_start_info(void)
{
	printk(KERN_INFO "[PVCLOCK]: initializing start_info page\n");

    start_info = kzalloc(sizeof(struct start_info), GFP_KERNEL);
  
    if (start_info == NULL) {
        printk(KERN_ERR "[PVCLOCK]: start_info is NULL. Aborting.\n");
        return false;
    }

    make_hypercall1(101, (unsigned long)start_info);

    if (strcmp(start_info->magic, "xen-TEST-TEST")) {
        printk(KERN_ERR "[PVCLOCK]: failed to initialize start_info page. Aborting.\n");
        return false;
    }

    return true;
}




static int __init driver_start(void)
{

    thread_args_t args;
   
    spin_lock_init(&lock);

    if (bareflank_is_running() == false)
        goto abort;
    
    if (init_shared_info() == false)
        goto abort;
    
    args.shared_info = shared_info;
    update_clock_thread = kthread_run(update_fake_clock, &args, "update_clock");

    if (init_start_info() == false)
        goto abort;

 abort:
	return 0;
}

static void __exit driver_end(void)
{
	kthread_stop(update_clock_thread);
}





module_init(driver_start);
module_exit(driver_end);
