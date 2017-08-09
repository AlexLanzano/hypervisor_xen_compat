#ifndef XEN_STRUCTS_H
#define XEN_STRUCTS_H


#define XEN_LEGACY_MAX_VCPUS 32


struct pvclock_wall_clock {
	uint32_t   version;
	uint32_t   sec;
	uint32_t   nsec;
} __attribute__((__packed__));


typedef unsigned long xen_ulong_t;

typedef struct shared_info {
	struct vcpu_info vcpu_info[MAX_VIRT_CPUS];

	/*
	 * A domain can create "event channels" on which it can send and receive
	 * asynchronous event notifications. There are three classes of event that
	 * are delivered by this mechanism:
	 *  1. Bi-directional inter- and intra-domain connections. Domains must
	 *     arrange out-of-band to set up a connection (usually by allocating
	 *     an unbound 'listener' port and avertising that via a storage service
	 *     such as xenstore).
	 *  2. Physical interrupts. A domain with suitable hardware-access
	 *     privileges can bind an event-channel port to a physical interrupt
	 *     source.
	 *  3. Virtual interrupts ('events'). A domain can bind an event-channel
	 *     port to a virtual interrupt source, such as the virtual-timer
	 *     device or the emergency console.
	 *
	 * Event channels are addressed by a "port index". Each channel is
	 * associated with two bits of information:
	 *  1. PENDING -- notifies the domain that there is a pending notification
	 *     to be processed. This bit is cleared by the guest.
	 *  2. MASK -- if this bit is clear then a 0->1 transition of PENDING
	 *     will cause an asynchronous upcall to be scheduled. This bit is only
	 *     updated by the guest. It is read-only within Xen. If a channel
	 *     becomes pending while the channel is masked then the 'edge' is lost
	 *     (i.e., when the channel is unmasked, the guest must manually handle
	 *     pending notifications as no upcall will be scheduled by Xen).
	 *
	 * To expedite scanning of pending notifications, any 0->1 pending
	 * transition on an unmasked channel causes a corresponding bit in a
	 * per-vcpu selector word to be set. Each bit in the selector covers a
	 * 'C long' in the PENDING bitfield array.
	 */
	xen_ulong_t evtchn_pending[sizeof(xen_ulong_t) * 8];
	xen_ulong_t evtchn_mask[sizeof(xen_ulong_t) * 8];

	/*
	 * Wallclock time: updated only by control software. Guests should base
	 * their gettimeofday() syscall on this wallclock-base value.
	 */
	struct pvclock_wall_clock wc;

	//struct arch_shared_info arch;

}shared_info_t;

shared_info_t *shared_info;

typedef uint32_t xen_pfn_t;

#define MAX_GUEST_CMDLINE 1024
typedef struct start_info {
	/* THE FOLLOWING ARE FILLED IN BOTH ON INITIAL BOOT AND ON RESUME.    */
	char magic[32];             /* "xen-<version>-<platform>".            */
	unsigned long nr_pages;     /* Total pages allocated to this domain.  */
	unsigned long shared_info;  /* MACHINE address of shared info struct. */
	uint32_t flags;             /* SIF_xxx flags.                         */
	xen_pfn_t store_mfn;        /* MACHINE page number of shared page.    */
	uint32_t store_evtchn;      /* Event channel for store communication. */
	union {
		struct {
			xen_pfn_t mfn;      /* MACHINE page number of console page.   */
			uint32_t  evtchn;   /* Event channel for console page.        */
		} domU;
		struct {
			uint32_t info_off;  /* Offset of console_info struct.         */
			uint32_t info_size; /* Size of console_info struct from start.*/
		} dom0;
	} console;
	/* THE FOLLOWING ARE ONLY FILLED IN ON INITIAL BOOT (NOT RESUME).     */
	unsigned long pt_base;      /* VIRTUAL address of page directory.     */
	unsigned long nr_pt_frames; /* Number of bootstrap p.t. frames.       */
	unsigned long mfn_list;     /* VIRTUAL address of page-frame list.    */
	unsigned long mod_start;    /* VIRTUAL address of pre-loaded module.  */
	unsigned long mod_len;      /* Size (bytes) of pre-loaded module.     */
	int8_t cmd_line[MAX_GUEST_CMDLINE];
	/* The pfn range here covers both page table and p->m table frames.   */
	unsigned long first_p2m_pfn;/* 1st pfn forming initial P->M table.    */
	unsigned long nr_p2m_frames;/* # of pfns forming initial P->M table.  */
}start_info_t;


#endif
