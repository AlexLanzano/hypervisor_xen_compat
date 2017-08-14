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
uintptr_t shared_info_addr = 0;

#define NANOSECONDS(tsc) (((tsc << shared_info->vcpu_info[0].time.tsc_shift) \
                           * shared_info->vcpu_info[0].time.tsc_to_system_mul) >> 32)
#define NSEC_PER_MSEC 1000000L

#define PAGE_SIZE 4096
#define XEN_CPUID_FIRST_LEAF 0x40000000
#define XEN_CPUID_MAX_NUM_LEAVES 4


class xen_exit_handler : public exit_handler_intel_x64
{
 public:


    void handle_exit(intel_x64::vmcs::value_type reason) override
    {
        if (reason == vmcs::exit_reason::basic_exit_reason::cpuid) {
            if (m_state_save->rax == 0x40000000) {
                handle_xen_cpuid();
                m_vmcs->resume();
                return;
            }
        }
        
        else if (reason == vmcs::exit_reason::basic_exit_reason::vmcall) {
            if (m_state_save->rdx != VMCALL_MAGIC_NUMBER) {
                handle_xen_vmcall();
                m_vmcs->resume();
                return;
            }

        }

        else if (reason == vmcs::exit_reason::basic_exit_reason::wrmsr) {
            if (m_state_save->rcx == 0x40000000) {
                handle_xen_wrmsr();
                m_vmcs->resume();
                return;
            }
        }

        exit_handler_intel_x64::handle_exit(reason);
        
    }
    
    void handle_xen_cpuid()
    {
        bfdebug << "Entered correctly" << bfendl; 
        m_state_save->rax = XEN_CPUID_FIRST_LEAF + XEN_CPUID_MAX_NUM_LEAVES;
        m_state_save->rbx = 0x566e6558;
        m_state_save->rcx = 0x65584d4d;
        m_state_save->rdx = 0x4d4d566e;
        advance_rip();
    }
    
    void handle_xen_vmcall()
    {
        auto &&regs = vmcall_registers_t{};
        
        
        
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
        complete_xen_vmcall(ret, regs);
        
    }

    void complete_xen_vmcall(ret_type ret, vmcall_registers_t &regs)
    {
        m_state_save->rax = regs.r00;
        m_state_save->rdi = regs.r01;
        m_state_save->rsi = regs.r02;
        m_state_save->rdx = regs.r03;
        m_state_save->r10 = regs.r04;
        m_state_save->r08 = regs.r05;
        m_state_save->r09 = regs.r06;
        advance_rip();
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

# define do_div(n, base) ({						\
	unsigned int __base = (base);					\
	unsigned int __rem;						\
	__rem = ((unsigned long long)(n)) % __base;			\
	(n) = ((unsigned long long)(n)) / __base;			\
	__rem;								\
})

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


    
    void init_shared_info(vmcall_registers_t &regs)
    {
        auto imap = bfn::make_unique_map_x64<shared_info_t>(regs.r01, vmcs::guest_cr3::get(),
                                                            sizeof(shared_info_t),
                                                            vmcs::guest_ia32_pat::get());
        shared_info = imap.get();
        memset(shared_info, 0, sizeof(shared_info_t));
        shared_info_addr = regs.r01;

        shared_info->wc.version = 1;
        shared_info->vcpu_info[0].time.version = 1;

        uint32_t mult;
        uint32_t shift;
        clocks_calc_mult_shift(&mult, &shift, regs.r02, NSEC_PER_MSEC, 0);
        shared_info->vcpu_info[0].time.tsc_to_system_mul = mult;
        shared_info->vcpu_info[0].time.tsc_shift = static_cast<uint8_t>(shift);
        shared_info->vcpu_info[0].time.tsc_timestamp = static_cast<uint64_t>(regs.r02);
        shared_info->vcpu_info[0].time.system_time = NANOSECONDS(static_cast<uint64_t>(regs.r02));
        
        
    }
    
    void update_fake_clock(vmcall_registers_t &regs)
    {
        auto imap = bfn::make_unique_map_x64<shared_info_t>(shared_info_addr, vmcs::guest_cr3::get(),
                                                            sizeof(shared_info_t),
                                                            vmcs::guest_ia32_pat::get());
        shared_info = imap.get();
        uint64_t tsc = regs.r01;
        uint64_t new_tsc = tsc;
        uint64_t old_tsc = shared_info->vcpu_info[0].time.tsc_timestamp;
        uint32_t seconds = shared_info->wc.sec;
        uint32_t nanoseconds = shared_info->wc.nsec;
        uint64_t system_time = shared_info->vcpu_info[0].time.system_time;
        
        tsc -= old_tsc;
        system_time += NANOSECONDS(tsc);
        nanoseconds += system_time;
        seconds += nanoseconds / 1000000000;

        shared_info->vcpu_info[0].time.tsc_timestamp = new_tsc;
        shared_info->wc.sec = seconds;
        shared_info->wc.nsec = nanoseconds;
    }
    
   
    
    void handle_vmcall_console_io(uintptr_t rdi, uintptr_t rsi, uintptr_t rdx)
    {
        bfdebug << "console io" << bfendl;
        
        switch(rdi) {
        case xen_hypercall::console_io_cmd::write:
            handle_console_io_write(rsi, rdx);
            break;
            
        case xen_hypercall::console_io_cmd::read:
            handle_console_io_read();
            break;
        }
    }
    

    void handle_console_io_write(uintptr_t rsi, uintptr_t rdx)
    {
        
        auto imap = bfn::make_unique_map_x64<char>(rdx, vmcs::guest_cr3::get(), rsi,
                                                   vmcs::guest_ia32_pat::get());
        bfdebug << std::string(imap.get(), rsi) << bfendl;

    }
    
    void handle_console_io_read()
    {
        bfdebug << "Do console io: read" << bfendl;
    }



    void handle_xen_wrmsr()
    {
        auto val = 0ULL;
        
        val |= ((m_state_save->rax & 0x00000000FFFFFFFF) << 0x00);
        val |= ((m_state_save->rdx & 0x00000000FFFFFFFF) << 0x20);
           
        bfdebug << vmcs::guest_cr3::get() << bfendl;
        bfdebug << "hypervisor: " << std::hex << val << bfendl;
        uintptr_t phys_addr = bfn::virt_to_phys_with_cr3(val, vmcs::guest_cr3::get());
        
        auto imap = bfn::make_unique_map_x64<uintptr_t>(phys_addr);
        uintptr_t *page = imap.get();
        
        init_hypercall_page(page);
        advance_rip();
    }

    static void init_hypercall_page(void *hypercall_page)
    {
        uint8_t *p;
        uint32_t i;
        
        for ( i = 0; i < (PAGE_SIZE / 32); i++ )
            {
                if ( i == 23 ) // skip iret
                    continue;
                
                p = (static_cast<uint8_t*>(hypercall_page) + (i * 32));
                *static_cast<uint8_t*>(p + 0) = 0xb8; /* mov imm32, %eax */
                *reinterpret_cast<uint32_t*>(p + 1) = i;
                *static_cast<uint8_t*>(p + 5) = 0x0f; /* vmcall */
                *static_cast<uint8_t*>(p + 6) = 0x01;
                *static_cast<uint8_t*>(p + 7) = 0xc1;
                *static_cast<uint8_t*>(p + 8) = 0xc3; /* ret */
            }
        
    }

};






#endif

// Local Variables:
// Mode: c++
// End:
