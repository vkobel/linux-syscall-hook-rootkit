obj-m += syscall_hook_rootkit.o
all:
	make -C ~/laab/linux M=$(PWD) modules
clean:
	make -C ~/laab/linux M=$(PWD) clean
