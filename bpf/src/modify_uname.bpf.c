#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "modify_uname.h"
#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, tid_t);
  __type(value, u64);
} utsname_p_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_newuname")
int handle_enter_uname(struct trace_event_raw_sys_enter *ctx) {
  tid_t tid = bpf_get_current_pid_tgid();

  char comm[16];
  bpf_get_current_comm(comm, 16);

  if ((!comm_filter(comm)) && (__builtin_memcmp("unam", comm, 4) != 0)) {
    return 0;
  }

  struct new_utsname *utsname_p =
      (struct new_utsname *)ctx->args[0];
  if (utsname_p == NULL) {
    return 0;
  }

  long success = bpf_map_update_elem(&utsname_p_map, &tid, &utsname_p, BPF_NOEXIST);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_newuname")
int handle_exit_uname() {
  tid_t tid = bpf_get_current_pid_tgid();

  char comm[16];
  bpf_get_current_comm(comm, 16);

  if (!comm_filter(comm) && (__builtin_memcmp("unam", comm, 4) != 0)) {
    return 0;
  }

  long unsigned int *utsname_pp = bpf_map_lookup_elem(&utsname_p_map, &tid);
  if (utsname_pp == NULL) {
    return 0;
  }

  struct new_utsname *utsname_p = (struct new_utsname *)*utsname_pp;
  struct new_utsname retval;

  long success =
      bpf_probe_read_user(&retval, sizeof(struct new_utsname), utsname_p);

  bpf_map_delete_elem(&utsname_p_map, &tid);

  bpf_printk("[sys_exit_uname] OVERWRITING struct timeval at \
    %p from (%s, %s, %s, %s, %s, %s)",
             utsname_p, retval.sysname, retval.nodename, retval.release, retval.version, retval.machine, retval.domainname);

  char release[] = "6.0.0";

  retval.nodename[0] = '\0';
  __builtin_memcpy(retval.release, release, 6);
  retval.version[0] = '\0';
  retval.domainname[0] = '\0';

  bpf_printk("[sys_exit_uname] OVERWRITING struct timeval at \
    %p to (%s, %s, %s, %s, %s, %s)",
             utsname_p, retval.sysname, retval.nodename, retval.release, retval.version, retval.machine, retval.domainname);

  success = bpf_probe_write_user((char *)utsname_p, (char *)&retval,
                                 sizeof(struct new_utsname));
  bpf_printk("[sys_exit_uname] RESULT %d", success);

  return 0;
}
