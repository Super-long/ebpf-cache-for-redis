#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <bpf/libbpf.h>
#include "trace.skel.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

enum {
    SYS__NR_read = 3,
    SYS__NR_write = 4,
	SYS__NR_open = 5,
};

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	int map_prog_idx;
	struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
	{"kprobe/__seccomp_filter", BPF_PROG_TYPE_KPROBE, -1, NULL},
	{"kprobe/SYS__NR_read", BPF_PROG_TYPE_KPROBE, SYS__NR_read, NULL},
	{"kprobe/SYS__NR_write", BPF_PROG_TYPE_KPROBE, SYS__NR_write, NULL},
	{"kprobe/SYS__NR_open", BPF_PROG_TYPE_KPROBE, SYS__NR_open, NULL},
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct trace_bpf *skel;
    int map_progs_fd, main_prog_fd, prog_count;
	int err;

	// 设置一些debug信息的回调
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Load and verify BPF application 
	skel = trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// Load and verify BPF programs 
	err = trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    map_progs_fd = bpf_object__find_map_fd_by_name(skel->obj, "progs");
    prog_count = sizeof(progs) / sizeof(progs[0]);
    for (int i = 0; i < prog_count; i++) {
		progs[i].prog = bpf_object__find_program_by_title(skel->obj, progs[i].name);
		if (!progs[i].prog) {
			fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
			return 1;
		}
		bpf_program__set_type(progs[i].prog, progs[i].type);
    }

    for (int i = 0; i < prog_count; i++) {
        int prog_fd = bpf_program__fd(progs[i].prog);
		if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}
        
        // -1指的是主程序
		if (progs[i].map_prog_idx != -1) {
			unsigned int map_prog_idx = progs[i].map_prog_idx;
			if (map_prog_idx < 0) {
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
				return 1;
			}
            // 给 progs map 的 map_prog_idx 插入 prog_fd
			err = bpf_map_update_elem(map_progs_fd, &map_prog_idx, &prog_fd, 0);
			if (err) {
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				return 1;
			}
		}
    }

	// 只载入主程序，尾调用不载入，所以不可以调用trace_bpf__attach
	struct bpf_link* link = bpf_program__attach(skel->progs.__seccomp_filter);
	if (link == NULL) {
		fprintf(stderr, "Error: bpf_program__attach failed\n");
		return 1;
	}

	while(exiting){
		// 写个裸循环会吃巨多CPU的
		sleep(1);
	}

cleanup:
	// Clean up
	trace_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
