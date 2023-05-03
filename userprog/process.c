#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define MAX_ARGC 128
//max. number of command line arguments

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

struct waiter {
	struct semaphore *sema_wait;	/* for synchronization */
	struct lock *lock;				/* for accessing exited and exit_code */
	bool *exited;					/* has the parent(or child) already exited? */
	int *exit_code;					/* exit code of parent(or child) */
	tid_t tid;						/* tid of parent(or child) */
	struct list_elem elem;
};

tid_t initd_tid;
struct semaphore sema_main_initd;
struct semaphore sema_create_initd;
int initd_status;

//extern struct lock user_lock;

/* General process initializer for initd and other process. */
static bool
process_init (void) {
	struct thread *current = thread_current ();
	current->print_exit_code = true;

	// 여기서 stdin, stdout을 넣어주자구요, stdin과 stdout은 NULL이 기본입니다. 가르킬 곳이 없거등
	// stdin의 파일 사이즈는 -1, stdout의 파일 사이즈는 -2.

	// msg("%s is starting...", current->name);
	if (list_size( &current->fd_list) == 0) {
		struct file_descriptor *fd;
		fd =  (struct file_descriptor *) malloc (sizeof(*fd));
		struct my_int *fds = (struct my_int *) malloc (sizeof (struct my_int));
		if (fd && fds) {
			list_init(&fd->int_list);
			fds->n = current->next_fd++;
			fd->file = NULL;
			fd->file_size = -1;
			list_push_back(&fd->int_list, &fds->elem);
			list_push_back(&current->fd_list, &fd->elem);
		} 
		fd =  (struct file_descriptor *) malloc (sizeof(*fd));
		fds = (struct my_int *) malloc (sizeof (struct my_int));
		if (fd && fds) {
			list_init(&fd->int_list);
			fds->n = current->next_fd++;
			fd->file = NULL;
			fd->file_size = -2;
			list_push_back(&fd->int_list, &fds->elem);
			list_push_back(&current->fd_list, &fd->elem);
		}
		if(fd){
			return true;
		} else {
			return false;
		}
	}
	return false;


}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	//msg("get page again = %p", palloc_get_page(0));`
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	sema_init(&sema_main_initd, 0); // sync. between main and initd.
	sema_init(&sema_create_initd, 0); //sync. between this function and initd.

	char *saveptr;
	file_name = strtok_r(file_name, " ", &saveptr); //truncates any arguments following actual file name.
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	
	initd_tid = tid; // remember this tid..
	sema_up(&sema_create_initd);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();
	sema_down(&sema_create_initd);
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct semaphore sema_fork; // synchronization: __do_fork done -> process_fork done
	sema_init(&sema_fork, 0); 

	/* for process_wait() */
	struct waiter *w = (struct waiter *)malloc(sizeof (struct waiter));
	struct semaphore *sema_wait = (struct semaphore *)malloc(sizeof (struct semaphore));
	struct lock *lock = (struct lock *)malloc(sizeof (struct lock));
	bool *exited = (bool *)malloc(sizeof (bool));
	int *exit_code = (int *)malloc(sizeof (int));
	if(!w || !sema_wait || !lock || !exited || !exit_code) {
		//msg("malloc error!");
		goto error; //malloc failed.
	}
	//msg("malloc successful");
	sema_init(sema_wait, 0);
	lock_init(lock);
	*exited = false;

	w->sema_wait = sema_wait;
	w->lock = lock;
	w->exited = exited;
	w->exit_code = exit_code;
	//printf("Hi\n");
	struct thread *cur = thread_current();
	void *args[] = {cur, if_, &sema_fork, w};
	tid_t tid = thread_create (name,
			PRI_DEFAULT, __do_fork, (void *)args);
	// PRI_DEFAULT, __do_fork, thread_current ());

	//printf("Hi\n");
	if(tid == TID_ERROR) {
		//msg("tid error!");
		goto error;
	}
	//printf("Hi\n");
	sema_down(&sema_fork);
	if(cur->fork_error) {
		//msg("fork error!");
		goto error;
	}

	//printf("Hi\n");
	w->tid = tid;
	list_push_back(&cur->down_list, &w->elem);
	return tid;

error:
	//msg("fork error!");
	free(w);
	free(sema_wait);
	free(lock);
	free(exited);
	free(exit_code);
	return TID_ERROR;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	/*
	if (parent->pml4 == NULL) {
		return true;
	}
	*/
	if(is_kernel_vaddr(va)) {
		return true;
	}

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER); 

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = (*pte) & PTE_W;
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false; 
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	// struct thread *parent = (struct thread *) aux;
	void **args = (void **) aux;
	struct thread *parent = (struct thread *) args[0];
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = (struct intr_frame *) args[1]; // &parent->tf;
	struct semaphore *sema_fork = (struct semaphore *) args[2];
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	
	if (current->pml4 == NULL) {
		//msg("pml4 error!");
		goto error;
	}

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) {
		//msg("pml4 duplicate error!");
		goto error;
	}
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	//should change

	// if (!process_init ()){
	// 	// msg("process_init error!");
	// 	goto error;
	// }

	current->print_exit_code = true;

	struct list *fd_list = &parent->fd_list;

	user_lock_acquire();
	for(struct list_elem *e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) { 
		struct file_descriptor *parent_fd = list_entry(e, struct file_descriptor, elem); 
		struct file *file_copy = NULL;
		if (parent_fd->file) {
			if( !(file_copy = file_duplicate(parent_fd->file)) ) {
				goto error; 
			} 
		}
		struct file_descriptor *curr_fd = (struct file_descriptor *)malloc(sizeof (struct file_descriptor));
		if (!curr_fd) {
			file_close(file_copy);
			goto error;
		}
		//should copy int_list, since parent may have closed some files.
		list_init(&curr_fd->int_list);
		for (struct list_elem *e1 = list_begin(&parent_fd->int_list); e1 != list_end(&parent_fd->int_list); e1 = list_next(e1)){
			struct my_int *parent_n = list_entry(e1, struct my_int, elem);
			struct my_int *child_n = (struct my_int *) malloc (sizeof (struct my_int));
			if (!child_n) {
				goto error;
			}
			child_n->n = parent_n->n;
			if(child_n->n >= current->next_fd) { //should increment next_fd!!
				current->next_fd = child_n->n + 1;
			}
			list_push_back(&curr_fd->int_list, &child_n->elem);
		}
		curr_fd->file = file_copy;
		curr_fd->file_size = parent_fd->file_size;
		list_push_back(&current->fd_list, &curr_fd->elem);

		
	}
	user_lock_release();

	/* for process_wait() */
	struct waiter *w = (struct waiter *) args[3];
	struct waiter *w_child = (struct waiter *) malloc(sizeof(struct waiter)); //__do_fork never fails from this point
	if(!w_child) {
		goto error;
	}
	memcpy(w_child, w, sizeof (struct waiter));
	w_child->tid = parent->tid;
	list_push_back(&current->up_list, &w_child->elem);
	if_.R.rax = 0; // return value for child = 0.


	/* Finally, switch to the newly created process. */
	if (succ) {
		parent->fork_error = false;
		sema_up(sema_fork);
		do_iret (&if_);	
	}
error:
	//msg("__do_fork error!");
	user_lock_release();
	parent->fork_error = true;
	sema_up(sema_fork);
	thread_exit_with_status(-1);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);
	//printf("Load result = %d\n", success);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	//for(int x = 0; x <= 500000000; x++); //waits for reasonable amount of time.
	//return -1;
	if(child_tid == TID_ERROR) { //if process_create_initd failed..
		return TID_ERROR;
	}

	if(child_tid == initd_tid) { //handle special case.. (did like this because initd was not created by fork.)
		sema_down(&sema_main_initd); //wait for initd to terminate..
		return initd_status;
	}

	struct thread *parent = thread_current(); //as a parent thread..
	struct list *down_list = &parent->down_list;
	for(struct list_elem *e = list_begin(down_list); e != list_end(down_list);) {
		//msg("Hi!");
		struct waiter *w = list_entry(e, struct waiter, elem);
		if(w->tid != child_tid) {
			e = list_next(e);
			continue;
		}

		lock_acquire(w->lock);
		if(!(*w->exited)) { //child has not exited 
			lock_release(w->lock);
			sema_down(w->sema_wait); //wait for child to sema_up (i.e. exit)
			lock_acquire(w->lock);
			ASSERT(*w->exited);
		}
		int exit_code = *w->exit_code;
		lock_release(w->lock);

		//msg("1");
		free(w->sema_wait);
		free(w->lock);
		free(w->exited);
		free(w->exit_code);
		//msg("1");

		e = list_remove(e);
		free(w);

		return exit_code;
	}
	return -1; //no child with child_tid.

}

//helper for thread_exit.
void
thread_exit_with_status (int status) {
	thread_current()->exit_code = status;
	thread_exit();
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	if(curr->print_exit_code) {
		printf ("%s: exit(%d)\n", curr->name, curr->exit_code);
	}

	//close all open files.
	//free some dynamically-allocated memory.
	
	struct list *fd_list = &curr->fd_list;
	// msg("let's free %s's fd_list of size %d", curr->name, list_size(&curr->fd_list));

	user_lock_acquire();
	for(struct list_elem *e = list_begin(fd_list); e != list_end(fd_list);) {
		struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
		for (struct list_elem *e1 = list_begin(&fd->int_list); e1 != list_end(&fd->int_list);){
			struct my_int *cur_n = list_entry(e1, struct my_int, elem);
 			e1 = list_remove(e1);
			free(cur_n);
		}		
		file_close(fd->file);
		e = list_remove(e);
		free(fd);
	}
	user_lock_release();


	/* for process_wait() */
	struct list *up_list = &curr->up_list;
	for(struct list_elem *e = list_begin(up_list); e != list_end(up_list);) { //there's only 1 parent for each thread, though.
		struct waiter *w = list_entry(e, struct waiter, elem);
		lock_acquire(w->lock);
		if(*w->exited) { //if the parent has already exited, it's the current thread's responsibility to free.
			struct semaphore *sema = list_entry(e, struct semaphore, elem);
			lock_release(w->lock);
			free(w->sema_wait);
			free(w->lock);
			free(w->exited);
			free(w->exit_code);
		}
		else { //otherwise, let the parent free.
			*w->exited = true;
			*w->exit_code = curr->exit_code;
			lock_release(w->lock);
			sema_up(w->sema_wait);

		}
		e = list_remove(e);
		free(w);
	}

	struct list *down_list = &curr->down_list;
	for(struct list_elem *e = list_begin(down_list); e != list_end(down_list);) {
		struct waiter *w = list_entry(e, struct waiter, elem);
		lock_acquire(w->lock);
		if(*w->exited) { //if the child has already exited, it's the current thread's responsibility to free.
			lock_release(w->lock);
			free(w->sema_wait);
			free(w->lock);
			free(w->exited);
			free(w->exit_code);

		}
		else { //otherwise, let the child free.
			*w->exited = true;
			*w->exit_code = curr->exit_code;
			lock_release(w->lock);
			sema_up(w->sema_wait);
		}
		e = list_remove(e);

		free(w);

	}

	
	if(curr->tid == initd_tid) { //this process was initd..
		sema_up(&sema_main_initd); //let main wake up.. (?)
		initd_status = curr->exit_code;
	}
	

	process_cleanup ();	
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	char **args = NULL;
	char **args_stack_addr = NULL;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* parse file_name before we open the file. */
	char *token, *saveptr;
	args = (char **)malloc(MAX_ARGC * sizeof(char *)); //array of arguments, used malloc to prevent possible stack overflow
	if(!args) {
		goto done;
	}
	i = 0;
	for(token = strtok_r(file_name, " ", &saveptr); token != NULL; token = strtok_r(NULL, " ", &saveptr)) {
		ASSERT(i < MAX_ARGC);
		args[i++] = token; //store i-th argument
	}
	int argc = i;

	user_lock_acquire();
	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
	//msg("open success");

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable)) {
						//msg("load_segment error!");
						goto done;
					}
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	args_stack_addr = (char **)malloc(MAX_ARGC * sizeof(char *));
	if(!args_stack_addr) {
		goto done;
	}
	char *p = (char *)if_->rsp; // for writing characters on the stack.
	// char *p = pml4e_walk(thread_current()->pml4, (uint8_t *)if_->rsp - PGSIZE, 0);
	// ASSERT(p);
	for(i = argc-1; i >= 0; i--) {
		for(int j = strlen(args[i]); j >= 0; j--) {
			*(--p) = args[i][j];
		}
		args_stack_addr[i] = p; // address of the i-th argument on stack.
	}
	while((uintptr_t)p % 8 != 0) *(--p) = 0; // word-align

	char **q = (char **)p; // for writing addresses on the stack.

	*(--q) = 0; // null pointer sentinel
	for(i = argc-1; i >= 0; i--) {
		*(--q) = args_stack_addr[i];
	}
	char **argv = q;
	*(--q) = 0; //return address

	if_->rsp = (uintptr_t) q;
	if_->R.rdi = argc;
	if_->R.rsi = (uint64_t) argv;

	// hex_dump(0, (void *)if_->rsp, USER_STACK - if_->rsp, true);

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	free(args);
	free(args_stack_addr);
	file_close (file);
	user_lock_release();
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	struct args *args = (struct args *)aux;
	struct file *file = args->file;
	off_t ofs = args->ofs;
	uint8_t *upage = args->upage;
	size_t page_read_bytes = args->page_read_bytes;
	size_t page_zero_bytes = args->page_zero_bytes;
	bool writable = args->writable;
	free(args);

	// Copied from #ifndef VM load_segment

	/* Get a page of memory. */
	struct frame *frame = page->frame;
	void *kpage = frame->kva;

	//msg("%p -> %p", page->va, frame->kva);
	user_lock_acquire();
	file_seek(file, ofs);
	/* Load this page. */
	off_t bytes = file_read (file, kpage, page_read_bytes);
	file_close(file);
	user_lock_release();
	if (bytes != (int) page_read_bytes) {
		msg("Hi");
		return false;
	}
	memset (kpage + page_read_bytes, 0, page_zero_bytes);
	/* Add the page to the process's address space. */
	uint64_t *pml4 = thread_current()->pml4;
	if (!pml4_set_page(pml4, upage, kpage, writable)) { // ?
		return false;
	}
	
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct args *args = (struct args *)malloc(sizeof (struct args));
		struct file *file_copy = file_duplicate(file); //user lock already held in load()
		*args = (struct args) {
			.file = file_copy, 
			.ofs = ofs, 
			.upage = upage, 
			.page_read_bytes = page_read_bytes, 
			.page_zero_bytes = page_zero_bytes, 
			.writable = writable
		}; // ?
		void *aux = (void *)args;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += PGSIZE; // ?
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	vm_alloc_page(VM_ANON, stack_bottom, true);

	if(success = vm_claim_page(stack_bottom)) {
		if_->rsp = USER_STACK;
	}

	return success;
}
#endif /* VM */
