# Bareflank Xen Compatibility Extension

## Description

This is just a rough start on making Bareflank compatible with Xen guests.


## Compilation / Usage

To setup our extension, run the following (assuming Linux):

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor
git clone https://github.com/AlexLanzano/hypervisor_xen_compat.git

./tools/scripts/setup-<xxx>.sh --no-configure
sudo reboot

./configure -m ./hypervisor_xen_compat/bin/xen_compat.modules
make
```

To test out our extended version of Bareflank, all we need to do is run the
following make shortcuts:

```
make driver_load
make quick

cd ./hypervisor_xen_compat/test_drivers/console_io/

make
sudo insmod console_io.ko

cd ../
make dump

make stop
make driver_unload

cd ./hypervisor_xen_compat/test_drivers/console_io/
sudo rmmod console_io.ko

```
