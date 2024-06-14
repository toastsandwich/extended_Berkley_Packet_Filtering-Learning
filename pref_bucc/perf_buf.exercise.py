from bcc import BPF

program = """
struct data_t {
    int pid;
    int uid;
    char message[20];
    char command[20];
};

BPF_PERF_OUTPUT(output);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.command, sizeof(data.command));

    if (data.pid % 2 == 0) {
        __builtin_strncpy(data.message, "even pid", sizeof(data.message));
    } else {
        __builtin_strncpy(data.message, "odd pid", sizeof(data.message));
    }

    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} -> {data.message.decode()}")

b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()