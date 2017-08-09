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
#include <test_hypercalls.h>
#include <xen.h>
#include <xen_hypercalls.h>
using namespace intel_x64;

shared_info_t *shared_info = NULL;
uintptr_t shared_info_addr = NULL;

class xen_exit_handler : public exit_handler_intel_x64
{
 public:


    void update_fake_clock(vmcall_registers_t &regs)
    {
        auto imap = bfn::make_unique_map_x64<shared_info_t>(shared_info_addr, vmcs::guest_cr3::get(),
                                                            sizeof(shared_info_t),
                                                            vmcs::guest_ia32_pat::get());
        shared_info = imap.get();
        shared_info->wc.sec = regs.r01;
        /*
          if (shared_info)
          shared_info->wc.sec = regs.r01;
        */
    }
    
    void init_shared_info(vmcall_registers_t &regs)
    {
        auto imap = bfn::make_unique_map_x64<shared_info_t>(regs.r01, vmcs::guest_cr3::get(),
                                                            sizeof(shared_info_t),
                                                            vmcs::guest_ia32_pat::get());
        shared_info = imap.get();
        memset(shared_info, 0, sizeof(shared_info_t));
        shared_info_addr = regs.r01;
    }
    
    void init_start_info(vmcall_registers_t &regs)
    {
        bfdebug << "RETRIEVED: " << std::hex << regs.r01 << bfendl;
        auto imap = bfn::make_unique_map_x64<start_info_t>(regs.r01, vmcs::guest_cr3::get(),
                                                           sizeof(start_info_t),
                                                           vmcs::guest_ia32_pat::get());
        start_info_t *start_info = imap.get();
        
        strncpy(start_info->magic, "xen-TEST-TEST", 31);
    }
    
    void test_vmcall(vmcall_registers_t &regs)
    {
        auto imap = bfn::make_unique_map_x64<char>(regs.r01, vmcs::guest_cr3::get(), 6,
                                                   vmcs::guest_ia32_pat::get());
        
        bfdebug << vmcs::guest_cr3::get() << bfendl;
        char *str = imap.get();
        bfdebug << str << bfendl;
    }

    void handle_vmcall_console_io(uintptr_t rdi, uintptr_t rsi, uintptr_t rdx)
    {
        bfdebug << "console io" << bfendl;
        
        switch(rdi) {
        case xen_hypercall::console_io_cmd::write:
            handle_console_io_write(rsi, rdx);
            break;
            
        case xen_hypercall::console_io_cmd::read:
            handle_console_io_read(rsi, rdx);
            break;
        }
    }
    

    void handle_console_io_write(uintptr_t rsi, uintptr_t rdx)
    {
        
        auto imap = bfn::make_unique_map_x64<char>(rdx, vmcs::guest_cr3::get(), rsi,
                                                   vmcs::guest_ia32_pat::get());
        bfdebug << std::string(imap.get(), rsi) << bfendl;
        
        
        
    }
    
    void handle_console_io_read(uintptr_t rsi, uintptr_t rdx)
    {
        bfdebug << "Do console io: read" << bfendl;
    }
    
    
    
    void handle_vmcall()
    {
        auto &&regs = vmcall_registers_t{};
        
        if (m_state_save->rdx != VMCALL_MAGIC_NUMBER) {
            
            /* Handle xen vmcalls */
            
            regs.r00 = m_state_save->rax;
            regs.r01 = m_state_save->rdi;
            regs.r02 = m_state_save->rsi;
            regs.r03 = m_state_save->rdx;
            regs.r04 = m_state_save->r10;
            regs.r05 = m_state_save->r08;
            regs.r06 = m_state_save->r09;
            
            auto &&ret = guard_exceptions(BF_VMCALL_FAILURE, [&] {
                    switch (m_state_save->rax)
                        {
                            
                        case test_hypercall::init_start_info:
                            init_start_info(regs);
                            break;
                            
                        case test_hypercall::init_shared_info:
                            init_shared_info(regs);
                            break;
                            
                        case test_hypercall::update_fake_clock:
                            update_fake_clock(regs);
                            break;
                            
                        case xen_hypercall::console_io:
                            handle_vmcall_console_io(regs.r01, regs.r02, regs.r03);
                            break;
                            
                            
                        default:
                            throw std::runtime_error("unknown vmcall opcode");
                        };
                });
            complete_vmcall(ret, regs);

        } else {
            
            /* Handle Bareflank vmcalls */
            
            regs.r02 = m_state_save->rcx;
            regs.r03 = m_state_save->rbx;
            regs.r04 = m_state_save->rsi;
            regs.r05 = m_state_save->r08;
            regs.r06 = m_state_save->r09;
            regs.r07 = m_state_save->r10;
            regs.r08 = m_state_save->r11;
            regs.r09 = m_state_save->r12;
            regs.r10 = m_state_save->r13;
            regs.r11 = m_state_save->r14;
            regs.r12 = m_state_save->r15;
            
            auto &&ret = guard_exceptions(BF_VMCALL_FAILURE, [&] {
                    switch (m_state_save->rax)
                        {
                        case VMCALL_VERSIONS:
                            handle_vmcall_versions(regs);
                            break;
                            
                        case VMCALL_REGISTERS:
                            handle_vmcall_registers(regs);
                            break;
                            
                        case VMCALL_DATA:
                            handle_vmcall_data(regs);
                            break;
                            
                        case VMCALL_EVENT:
                            handle_vmcall_event(regs);
                            break;
                            
                        case VMCALL_START:
                            handle_vmcall_start(regs);
                            break;
                            
                        case VMCALL_STOP:
                            handle_vmcall_stop(regs);
                            break;
                            
                        default:
                            throw std::runtime_error("unknown vmcall opcode");
                        };
                });

            complete_vmcall(ret, regs);

        }
        
        
        
        
    }

    
};

#endif

// Local Variables:
// Mode: c++
// End:
