
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

typedef struct thread_args {
    struct shared_info *shared_info;
} thread_args_t;

struct shared_info *shared_info;
struct mutex clock_mutex;
static struct task_struct *update_clock_thread;


int64_t start_time = -1;

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

#define NANOSECONDS(tsc) (((tsc << shared_info->vcpu_info[0].time.tsc_shift) \
                           * shared_info->vcpu_info[0].time.tsc_to_system_mul) >> 32)

#define RDTSC(x)     asm volatile ("RDTSC":"=A"(tsc))

int gettimeofday(struct timeval *tp)
{
	uint64_t tsc;
	/* Get the time values from the shared info page */
	uint32_t version, wc_version;
	uint32_t seconds, nanoseconds;
	uint64_t old_tsc, system_time;

#if 1
	/* Loop until we can read all required values from the same update */
	do
	{
		/* Spin if the time value is being updated */
		do
		{
			wc_version = shared_info->wc.version;
			version = shared_info->vcpu_info[0].time.version;
		} while(
				version & (1 == 1)
				||
				wc_version & (1 == 1));
		/* Read the values */
		seconds = shared_info->wc.sec;
		nanoseconds = shared_info->wc.nsec;
		system_time = shared_info->vcpu_info[0].time.system_time;
		old_tsc = shared_info->vcpu_info[0].time.tsc_timestamp;
	} while(
			version != shared_info->vcpu_info[0].time.version
			||
			wc_version != shared_info->wc.version
			);
#else
    seconds = 0;
    nanoseconds = 0;
    system_time = 0;
    old_tsc = rdtsc();
    msleep(500);
#endif
    
	/* Get the current TSC value */
	tsc = rdtsc();
	/* Get the number of elapsed cycles */
	tsc -= old_tsc;
	/* Update the system time */
	system_time += NANOSECONDS(tsc);
	/* Update the nanosecond time */
	nanoseconds += system_time;
	/* Move complete seconds to the second counter */
	seconds += nanoseconds / 1000000000;
	nanoseconds = nanoseconds % 1000000000;
	/* Return second and millisecond values */
	tp->tv_sec = seconds;
	tp->tv_usec = nanoseconds * 1000;
	return 0;
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

uint64_t get_elapsed_time(void)
{
    uint64_t current_time;
    if (start_time < 0) 
        start_time = shared_info->wc.sec;
    current_time = shared_info->wc.sec;
    return current_time - start_time;

}


int update_fake_clock(void *data)
{
    uint64_t tsc;
    uint32_t mult;
    uint32_t shift;
    thread_args_t *args = (thread_args_t*)data;
    
    shared_info = args->shared_info;

    
    clocks_calc_mult_shift(&mult, &shift, tsc_khz, NSEC_PER_MSEC, 0);
    
    
    while (!kthread_should_stop()) {
        uint64_t elapsed_time;
        tsc = rdtsc();
        make_hypercall1(102, (unsigned long)tsc);
        elapsed_time = get_elapsed_time();
        printk(KERN_INFO "[PVCLOCK]: %llu second(s) elapsed\n", elapsed_time);
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


bool init_shared_info(void)
{
    uint32_t tsc = rdtsc();

    
    printk(KERN_INFO "[PVCLOCK]: initializing shared_info page.\n");
    shared_info = kzalloc(sizeof(struct shared_info), GFP_KERNEL);
    
    if (shared_info == NULL) {
        printk(KERN_ERR "[PVCLOCK]: shared_info is NULL. Aborting.\n");
        return false;
    }
    make_hypercall2(100, (unsigned long)shared_info, tsc);
    return true;
    
}

static int __init driver_start(void)
{
    thread_args_t args;
    struct start_info *start_info;
    /*
    uint32_t mult;
    uint32_t shift;
    clocks_calc_mult_shift(&mult, &shift, tsc_khz, NSEC_PER_MSEC, 0);
    
    printk(KERN_INFO "%u\n", tsc_khz);
    printk(KERN_INFO "%u\n", mult);
    printk(KERN_INFO "%u\n", shift);

    printk(KERN_INFO "%llu\n", rdtsc());
    
    return 0;
    */
    mutex_init(&clock_mutex);
	// Check if bareflank is running
	if (hypervisor_cpuid_base2("XenVMMXenVMM", 2) == 0) {
	    printk(KERN_ERR "[PVCLOCK]: Bareflank is not running. Aborting.\n");
		goto abort;
	}
    
    if (init_shared_info() == false)
        goto abort;
    
    args.shared_info = shared_info;
    update_clock_thread = kthread_run(update_fake_clock, &args, "update_clock");

    start_info = kzalloc(sizeof(struct start_info), GFP_KERNEL);
	printk(KERN_INFO "Making vmcall: INIT_START_INFO\n");
    
  
    if (start_info == NULL) {
        printk(KERN_ERR "[PVCLOCK]: start_info is NULL. Aborting.\n");
        goto abort;
    }
    printk(KERN_INFO "start_info: %p\n", start_info);
    make_hypercall1(101, (unsigned long)start_info);
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
