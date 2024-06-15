#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"


SEC("raw_tp/")
int hello(void *ctx) {
    long uid;
    long counter = 0;
    long *procid;
    
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    proc = 
    return 0;
}