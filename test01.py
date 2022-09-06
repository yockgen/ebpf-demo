from bcc import BPF
from bcc.utils import printb

BPF_SOURCE_CODE = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
   bpf_trace_printk("yockgen!! kill process detected: %s\n", args);
   return 0;
}
"""

bpf = BPF(text = BPF_SOURCE_CODE)

print("To test, open another shell window and create a directory, e.g.")
print(" mkdir frodo")
print("CTRL-C to exit")

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        printb(b"%-6d %s" % (pid, msg))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break

