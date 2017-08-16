#include <vcpu/vcpu_factory.h>
#include <vcpu/vcpu_intel_x64.h>
#include <exit_handler/xen_exit_handler.h>

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, user_data *data)
{
    auto &&my_exit_handler = std::make_unique<xen_exit_handler>();

    (void) data;
    return std::make_unique<vcpu_intel_x64>(
               vcpuid,
               nullptr,                         // default debug_ring
               nullptr,                         // default vmxon
               nullptr,                         // default vmcs
               std::move(my_exit_handler),
               nullptr,                         // default vmm_state
               nullptr);                        // default guest_state
}
