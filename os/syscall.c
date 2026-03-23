#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"
#include "vm.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	TimeVal temp;
	
	uint64 cycle = get_cycle();
	temp.sec = cycle / CPU_FREQ;
	temp.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	
	if (copyout(curr_proc()->pagetable, (uint64)val, (char *)&temp, sizeof(TimeVal)) < 0) {
		return -1;
	}
	
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

/*
* LAB1: you may need to define sys_task_info here
*/
int sys_task_info(struct TaskInfo *ti)
{
	struct proc *p = curr_proc();
	struct TaskInfo temp;
	
	temp.status = Running;
	
	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		temp.syscall_times[i] = p->syscall_times[i];
	}
	
	uint64 current_cycle = get_cycle();
	temp.time = (int)((current_cycle - p->start_time) * 1000 / CPU_FREQ);
	
	if (copyout(p->pagetable, (uint64)ti, (char *)&temp, sizeof(struct TaskInfo)) < 0) {
		return -1;
	}
	
	return 0;
}
/*
* End LAB1
*/

uint64 sys_mmap(uint64 start, uint64 len, int prot, int flags, int fd)
{
	struct proc *p = curr_proc();
	
	if (start % PGSIZE != 0) {
		return -1;
	}
	
	if (len == 0) {
		return 0;
	}
	
	if ((prot & ~0x7) != 0) {
		return -1;
	}
	
	if ((prot & 0x7) == 0) {
		return -1;
	}
	
	len = PGROUNDUP(len);
	
	for (uint64 addr = start; addr < start + len; addr += PGSIZE) {
		if (walkaddr(p->pagetable, addr) != 0) {
			return -1;
		}
	}
	
	int pte_flags = PTE_V | PTE_U;
	if (prot & 0x1) pte_flags |= PTE_R;
	if (prot & 0x2) pte_flags |= PTE_W;
	if (prot & 0x4) pte_flags |= PTE_X;
	
	for (uint64 addr = start; addr < start + len; addr += PGSIZE) {
		void *pa = kalloc();
		
		if (pa == 0) {
			uvmunmap(p->pagetable, start, (addr - start) / PGSIZE, 1);
			return -1;
		}
		
		memset(pa, 0, PGSIZE);
		
		if (mappages(p->pagetable, addr, PGSIZE, (uint64)pa, pte_flags) != 0) {
			kfree(pa);
			uvmunmap(p->pagetable, start, (addr - start) / PGSIZE, 1);
			return -1;
		}
	}
	
	return 0;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	struct proc *p = curr_proc();
	
	if (start % PGSIZE != 0) {
		return -1;
	}
	
	if (len == 0) {
		return 0;
	}
	
	len = PGROUNDUP(len);
	
	for (uint64 addr = start; addr < start + len; addr += PGSIZE) {
		if (walkaddr(p->pagetable, addr) == 0) {
			return -1;
		}
	}
	
	uvmunmap(p->pagetable, start, len / PGSIZE, 1);
	
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}
	/*
	* End LAB1
	*/
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
		ret = sys_task_info((struct TaskInfo *)args[0]);
		break;
	/*
	* End LAB1
	*/
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}