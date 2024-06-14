#!/usr/bin/python3

from bcc import BPF
from time import sleep

# -----------------KERNEL--------------------
# we are masking the top 32 bits from grp id to get uid
program = r"""
    BPF_HASH(counter_table);
    
    int basic_map(void *ctx) {
        u64 uid;
        u64 counter = 0;
        u64 *p;

        uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        p = counter_table.lookup(&uid);

        if(p != 0) {
            counter = *p;
        }
        counter++;
        counter_table.update(&uid, &counter);
        return 0;
    }
"""
b = BPF(text=program)
syscall =b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="basic_map")

# -----------------USER SPACE--------------------
while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)

# is this working ?
# it did work