

### Usage:
```
cd ~/hypervsor/build/
make driver_quick
make quick

cd ~/xen_linux_drivers/console_io/
make

sudo insmod console_io.ko


cd ~/hypervisor/build/
make dump

make unload
make driver_unload

cd ~/xen_linux_drivers/console_io/
sudo rmmod console_io.ko
```
