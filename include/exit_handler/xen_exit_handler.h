#ifndef XEN_EXIT_HANDLER_H
#define XEN_EXIT_HANDLER_H


#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_debug.h>

#include <exit_handler/exit_handler_intel_x64.h>

using namespace intel_x64;


#define NANOSECONDS(delta) ((1000000ULL * delta) / tsc_khz)

#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC 1000000000ULL

#define PAGE_SIZE 4096
#define XEN_CPUID_FIRST_LEAF 0x40000000
#define XEN_CPUID_MAX_NUM_LEAVES 4

uint64_t rdtsc(void);
void init_hypercall_page(void *hypercall_page);

class xen_exit_handler : public exit_handler_intel_x64
{
 public:


    void handle_exit(intel_x64::vmcs::value_type reason) override;

    void handle_xen_cpuid();    
    void handle_xen_vmcall();
    void handle_xen_wrmsr();    

    void complete_xen_vmcall(ret_type ret, vmcall_registers_t &regs);

    
    void init_start_info(vmcall_registers_t &regs);
    void init_shared_info(vmcall_registers_t &regs);
    void update_fake_clock(vmcall_registers_t &regs);
    void handle_vmcall_console_io(uintptr_t rdi, uintptr_t rsi, uintptr_t rdx);
    void handle_test_vmcall();
    

    void handle_console_io_write(uintptr_t rsi, uintptr_t rdx);
    void handle_console_io_read();


};



#endif

// Local Variables:
// Mode: c++
// End:
