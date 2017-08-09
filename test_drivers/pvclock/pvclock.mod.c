#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x21fac097, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xbfee3e0, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xa3139123, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xb03d0b06, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x9e617f71, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xbab4d16f, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xc47d9f0b, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0xbe21a0b1, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x211f68f1, __VMLINUX_SYMBOL_STR(getnstimeofday64) },
	{ 0x952664c5, __VMLINUX_SYMBOL_STR(do_exit) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

