#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	//printf ("system call number: %d\n", f->R.rax);
	//printf ("rdi = %d, rsi = %p, rdx = %d\n", f->R.rdi, (void *)f->R.rsi, f->R.rdx);
	//hex_dump(0, (void *)f->R.rsi, f->R.rdx, true);

	switch(f->R.rax) { //system call number. Refer to lib/user/syscall.c for each system call functions.
		
		case SYS_HALT: {                  /* Halt the operating system. */
			
			break;
		}
		case SYS_EXIT: {                  /* Terminate this process. */
			int status = f->R.rdi;
			thread_exit();
			break;
		}
		case SYS_FORK: {                  /* Clone current process. */
			
			break;
		}
		case SYS_EXEC: {                  /* Switch current process. */
			
			break;
		}
		case SYS_WAIT: {                  /* Wait for a child process to die. */
			
			break;
		}
		case SYS_CREATE: {                /* Create a file. */
			
			break;
		}
		case SYS_REMOVE: {                /* Delete a file. */
			
			break;
		}
		case SYS_OPEN: {                  /* Open a file. */
			
			break;
		}
		case SYS_FILESIZE: {              /* Obtain a file's size. */
			
			break;
		}
		case SYS_READ: {                  /* Read from a file. */
			
			break;
		}
		case SYS_WRITE: {                  /* Write to a file. */
			int fd = f->R.rdi;
			const void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;

			// temporary code to handle printf, msg calls in user program.
			putbuf(buffer, size); // defined in lib/kernel/console.c
			f->R.rax = size;
			break;
		}
		case SYS_SEEK: {                  /* Change position in a file. */
			
			break;
		}
		case SYS_TELL: {                  /* Report current position in a file. */
			
			break;
		}
		case SYS_CLOSE: {                 /* Close a file. */
			
			break;
		}
	}
	

	// thread_exit ();
}
