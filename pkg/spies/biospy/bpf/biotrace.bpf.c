#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "biotrace.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct biotrace_key_t);
	__type(value, u32);
	__uint(max_entries, BIOTRACE_MAPS_SIZE);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, BIOTRACE_MAPS_SIZE);
} stacks SEC(".maps");

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)



SEC("kprobe/blk_account_io_start")
int trace_io_start(struct pt_regs *ctx)
{
	void *req = (void *)ctx;
	return 0;
}

char _license[] SEC("license") = "GPL"; //todo
