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

#include "brc_common.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>	// bpf_map_update_elem

#include "brc.skel.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"
#define STATS_PATH "/tmp/brc_stats.txt"
#define STATS_INTERVAL_PATH "/tmp/brc_stats_interval.txt"

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
    int pin;
	int map_prog_idx;
	struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
	{"tc/brc_rx_filter",       	BPF_PROG_TYPE_SCHED_CLS, -1,                          	NULL},
	{"tc/brc_hash_keys",       	BPF_PROG_TYPE_SCHED_CLS, BRC_PROG_XDP_HASH_KEYS,      	NULL},
    {"tc/brc_prepare_packet",   BPF_PROG_TYPE_SCHED_CLS, BRC_PROG_XDP_PREPARE_PACKET, 	NULL},
	{"tc/brc_write_reply",      BPF_PROG_TYPE_SCHED_CLS, BRC_PROG_XDP_WRITE_REPLY,    	NULL},
	{"tc/brc_maintain_tcp",     BPF_PROG_TYPE_SCHED_CLS, BRC_PORG_XDP_MAINTAIN_TCP,   	NULL},
    {"tc/brc_invalidate_cache", BPF_PROG_TYPE_SCHED_CLS, BRC_PROG_XDP_INVALIDATE_CACHE,	NULL},
    {"tc/brc_tx_filter",       	BPF_PROG_TYPE_SCHED_CLS, -1,                          	NULL},
    {"tc/brc_update_cache",		BPF_PROG_TYPE_SCHED_CLS, BRC_PROG_TC_UPDATE_CACHE,    	NULL},
};

static int cpu_nums = 0;


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
	exiting = true;
}

void construct_mount_path(char* pathame, char* prog_name) {
	int len = snprintf(pathame, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, prog_name);
	printf("mount path : %s\n", pathame);
	if (len < 0) {
		fprintf(stderr, "Error: Program name '%s' is invalid\n", prog_name);
		exit(1);
	} else if (len >= PATH_MAX) {
		fprintf(stderr, "Error: Path name '%s' is too long\n", prog_name);
		exit(1);
	}
	return;
}

int write_stats_to_file(char *filename, int map_fd) {
	printf("lizhoalong\n");
}

int write_stat_line(FILE *fp, int map_fd) {
	printf("yunwenqi\n");
}

int main(int argc, char **argv) {
    struct rlimit mem_limit = {RLIM_INFINITY, RLIM_INFINITY};
	struct brc_bpf *skel;
    int map_tc_progs_fd, prog_count, map_progs_fd, map_stats_fd, tc_main_fd;
    // 目前写死，后续可以再修改
    int interface_idx;
    int stats_poll_count = 5, stats_poll_interval = 5;
	int err;

	// 设置一些debug信息的回调
	libbpf_set_print(libbpf_print_fn);

	// libbpf不会默认调节锁定的内存
	if (setrlimit(RLIMIT_MEMLOCK, &mem_limit)) {
		perror("setrlimit failed");
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Load and verify BPF application 
	skel = brc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// Load and verify BPF programs 
	err = brc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    //======================填充progs数组====================================
    prog_count = sizeof(progs) / sizeof(progs[0]);
    for (int i = 0; i < prog_count; i++) {
		printf("progs[i].name %s\n", progs[i].name);
		progs[i].prog = bpf_object__find_program_by_title(skel->obj, progs[i].name);
		if (!progs[i].prog) {
			fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
			return 1;
		}
		bpf_program__set_type(progs[i].prog, progs[i].type);
    }
    //===================================================================

    //======================用于尾调用====================================
	map_tc_progs_fd = bpf_object__find_map_fd_by_name(skel->obj, "tc_progs");
	if (map_tc_progs_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}
    //===================================================================

    //======================用于填充prog_map==============================
    for (int i = 0; i < prog_count; i++) {
        int prog_fd = bpf_program__fd(progs[i].prog);
		if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}
        // -1指的是主程序
		if (progs[i].map_prog_idx != -1) {
            switch (progs[i].type) {
            case BPF_PROG_TYPE_SCHED_CLS:
                map_progs_fd = map_tc_progs_fd;
                break;
            default:
                fprintf(stderr, "Error: Program type doesn't correspond to any prog array map\n");
                return 1;
            }
            // 给 progs map 的 map_prog_idx 插入 prog_fd
			err = bpf_map_update_elem(map_progs_fd, &progs[i].map_prog_idx, &prog_fd, 0);
			if (err) {
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				return 1;
			}
		} else {
			// TC相关,bpf_tc_attach的例子太少了,现在也没时间看libbpf的代码,所以pin下,命令行手动挂载
			char pathname[PATH_MAX];
			construct_mount_path(pathname, progs[i].name);
retry:
			if (bpf_program__pin(progs[i].prog, pathname)) {
				fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", progs[i].name, pathname);
				if (errno == EEXIST) {
					fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", progs[i].name);
					if (bpf_program__unpin(progs[i].prog, pathname)) {
						fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", progs[i].name, pathname);
						return -1;
					}
					printf("Retry mount TC bpf to %s\n", pathname);
					goto retry;
				}
				return -1;
			}
        }
    }
    //===========================================================================

    //============================brc_tx_filter载入================================
	// https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/prog_tests/tc_bpf.c#L36
	// https://lwn.net/Articles/856041/
    // tc_main_fd = bpf_object__find_map_fd_by_name(skel->obj, "tc/brc_rx_filter");

    // struct bpf_tc_hook tc_main_hook = {
    //         .attach_point = BPF_TC_EGRESS, 
    //         .ifindex = interface_idx,
	// 		.sz = sizeof(struct bpf_tc_hook)};
    // struct bpf_tc_opts tc_main_opts = {
    //         .sz = sizeof(struct bpf_tc_opts),
	// 		.handle = 1,
    //         .priority = 1, 
    //         .prog_fd = tc_main_fd};

	// getchar(); // 用于GDB

    // if (bpf_tc_hook_create(&tc_main_hook) != 0) {
    //     fprintf(stderr, "bpf_tc_hook_create invalid hook ifindex == %d\n", interface_idx);
    //     goto cleanup;
    // } else {
	// 	printf("sucess for create hook\n");
	// }

    // if (bpf_tc_attach(&tc_main_hook, &tc_main_opts) != 0) {
    //     fprintf(stderr, "bpf_tc_attach invalid hook ifindex == %d\n", interface_idx);
    //     goto cleanup;
    // }
    //===================================================================

    //============================注册对应的信号处理函数================================

    cpu_nums = libbpf_num_possible_cpus();

	map_stats_fd = bpf_object__find_map_fd_by_name(skel->obj, "map_stats");
	if (map_stats_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	int sig, cur_poll_count = 0, quit = 0;
	FILE *fp = NULL;

	if (stats_poll_count > 0 && stats_poll_interval > 0) {
		fp = fopen(STATS_INTERVAL_PATH, "w+");
		if (fp == NULL) {
			fprintf(stderr, "Error: failed to open file '%s'\n", STATS_INTERVAL_PATH);
			return -1;
		}
		// 隔这么长时间触发一次SIGALRM信号
		//alarm(stats_poll_interval);
	}

	int ret = 0;
	while (!quit) {
        // 是否可能出现信号丢失的情况
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
			case SIGINT:
			case SIGTERM:
				// 按了 ctrl+c 以后就把map_stats中的数据写到目标文件中
				ret = write_stats_to_file(STATS_PATH, map_stats_fd);
				//quit = 1;
				break;

			case SIGALRM:
				ret |= write_stat_line(fp, map_stats_fd);
				if (++cur_poll_count < stats_poll_count) {
					alarm(stats_poll_interval);
				} else {
					ret |= write_stats_to_file(STATS_PATH, map_stats_fd);
					if (fp != NULL) {
						fclose(fp);
					}
					//quit = 1;
				}
				break;
			default:
				fprintf(stderr, "Unknown signal\n");
				break;
		}
	}

cleanup:
	// Clean up
    // if (bpf_tc_hook_destroy(&tc_main_hook) == -EINVAL) {
    //     fprintf(stderr, "bpf_tc_hook_destroy invalid hook ifindex == 0\n");
    //     return 1;
    // }

    // struct bpf_tc_opts opts = {
    //         .handle = 1,
    //         .priority = 1,
	// 		.sz = sizeof(struct bpf_tc_opts)};

    // if (bpf_tc_detach(&tc_main_hook, &opts) == -EINVAL) {
    //     fprintf(stderr, "bpf_tc_detach invalid hook ifindex == 0\n");
    //     return 1;
    // }
	brc_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
