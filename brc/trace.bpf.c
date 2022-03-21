#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u32);
} progs SEC(".maps");


SEC("kprobe/__seccomp_filter")
int BPF_KPROBE(__seccomp_filter, int this_syscall, const struct seccomp_data *sd, const bool recheck_after_trace)
{	
	// 这里注意ebpf程序栈空间只有512字节，太大这里会报错的，可以自己调大一点看看
	char comm_name[30];
	bpf_get_current_comm(comm_name, sizeof(comm_name));
	// 调用失败以后会直接 fall through
    bpf_tail_call(ctx, &progs, this_syscall);

	char fmt[] = "syscall=%d common=%s\n";
	bpf_trace_printk(fmt, sizeof(fmt), this_syscall, comm_name);
    return 0;
}

/* we jump here when syscall number == __NR_write */
SEC("kprobe/SYS__NR_write")
int bpf_func_SYS__NR_write(struct pt_regs *ctx)
{
	struct seccomp_data sd;
	bpf_probe_read(&sd, sizeof(sd), (void *)PT_REGS_PARM2(ctx));
	if (sd.args[2] > 0) {
		char fmt[] = "write(fd=%d, buf=%p, size=%d)\n";
		bpf_trace_printk(fmt, sizeof(fmt),
				 sd.args[0], sd.args[1], sd.args[2]);
	}
	return 0;
}

SEC("kprobe/SYS__NR_read")
int bpf_func_SYS__NR_read(struct pt_regs *ctx)
{	
	struct seccomp_data sd;
	bpf_probe_read(&sd, sizeof(sd), (void *)PT_REGS_PARM2(ctx));
	if (sd.args[2] > 0 && sd.args[2] <= 1024) {
		char fmt[] = "read(fd=%d, buf=%p, size=%d)\n";
		bpf_trace_printk(fmt, sizeof(fmt),
				 sd.args[0], sd.args[1], sd.args[2]);
	}
	return 0;
}

SEC("kprobe/SYS__NR_open")
int bpf_func_SYS__NR_open(struct pt_regs *ctx)
{	
	struct seccomp_data sd;
	bpf_probe_read(&sd, sizeof(sd), (void *)PT_REGS_PARM2(ctx));
	char fmt[] = "open(fd=%d, path=%p)\n";
	bpf_trace_printk(fmt, sizeof(fmt), sd.args[0], sd.args[1]);
	return 0;
}