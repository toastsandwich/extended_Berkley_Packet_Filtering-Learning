#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("trace")
int hello(void* ctx) {
    char* str = "HelloWorld";
    bpf_trace_printk(str, sizeof(str));
    return 0;
}
