#ifndef XEN_HYPERCALLS_H
#define XEN_HYPERCALLS_H

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

namespace xen_hypercall {
	const int set_trap_table = 0;
	const int mmu_update = 1;
	const int set_gdt = 2;
	const int stack_switch = 3;
	const int set_callbacks = 4;
	const int fpu_taskswitch = 5;
	const int sched_op_compat = 6;
	
	const int platform_op = 7;
	namespace platform_op_cmd {
		const int settime32 = 17;
		const int settime64 = 62;
		const int add_memtype = 31;
		const int del_memtype = 32;
		const int read_memtype = 33;
		const int microcode_update = 35;
		const int platform_quirk = 39;
		const int efi_runtime_call = 49;
		const int firmware_info = 50;
		const int enter_apci_sleep = 51;
		const int change_freq = 52;
		const int getidletime = 53;
		const int set_processor_pminfo = 54;
		const int get_cpuinfo = 55;
		const int get_cpu_version = 48;
		const int cpu_online = 56;
		const int cpu_offline = 57;
		const int cpu_hotadd = 58;
		const int mem_hotadd =59;
		const int core_parking = 60;
		const int resource_op = 61;
		const int get_symbol = 63;
		 
	}; 
	
	const int set_debugreg = 8;
	const int get_debugreg = 9;
	const int update_descriptor = 10;
	const int memory_op = 12;
	const int multicall = 13;
	const int update_va_mapping = 14;
	const int set_timer_op = 15;
	const int event_channel_op_compat = 16;
	const int xen_version = 17;

	const int console_io = 18;
	namespace console_io_cmd {
		const int write = 0;
		const int read = 1;
	};
	
	const int physdev_op_compat = 19;
	const int grant_table_op = 20;
	const int vm_assist = 21;
	const int update_va_mapping_otherdomain = 22;
	const int iret = 23;
	const int vcpu_op = 24;
	const int set_segment_base = 25;
	const int mmuext_op = 26;
	const int xsm_op = 27;
	const int nmi_op = 28;
	const int sched_op = 29;
	const int callback_op = 30;
	const int xenoprof_op = 31;
	
	const int event_channel_op = 32;
	namespace event_channel_op_cmd{
		const int bind_interdomain = 0;
		const int bind_virq = 1;
		const int bing_pirq = 2;
		const int close = 3;
		const int send = 4;
		const int status = 5;
		const int alloc_unbound = 6;
		const int bind_ipi = 7;
		const int bind_vcpu = 8;
		const int unmask = 9;
		const int reset = 10;
		const int init_control = 11;
		const int expand_array = 12;
		const int set_priority = 13;
		
	};
	
	const int physdev_op = 33;
	const int hvm_op = 34;
	const int sysctl = 35;
	const int domctl = 36;
	const int kexec_op = 37;
	const int tmem_op = 38;
	const int xc_reserved_op = 39;
	const int xenpmu_op = 40;
	const int dm_op = 41;
	
};

void xen_vmcall(struct vmcall_registers_t *regs);



#ifdef __cplusplus
}
#endif

#pragma pack(pop)
	
#endif
