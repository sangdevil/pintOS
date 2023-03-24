#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/fixed_points.c"
#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
// static struct list block_list;
extern struct list sleeping_threads;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };


// load_avg는 여기에 정의해 줍니다.
static fixed_point_t load_avg = 0;

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	// list_init (&block_list);
	list_init (&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	// list_remove(&initial_thread->elem);
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();
	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started); 
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
// 여기서 load_avg를 업데이트 해야 할 것 같아서 여기서 수정합니다. 

void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else {
		kernel_ticks++;	
	}
	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	// nice와 recent_cpu 설정해줍시다.

	t->nice = 0;
	t->recent_cpu = 0;
	// msg("지금 스레드 생성됨 : %s", name);
	/* Add to run queue. */
	thread_unblock (t);

	thread_yield(); // 한번 지워봣음

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	struct thread *cur = thread_current();
	cur->status = THREAD_BLOCKED;
	// list_remove(&cur->elem); // ready_list에서 빼자
	// list_push_back(&block_list, &cur->elem);
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	// list_remove(&t->elem);
	list_push_back (&ready_list, &t->elem);
	
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING); //schedule() call하는 함수에서 printf하면 여기서 fail.

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_push_back (&ready_list, &curr->elem);
		// list_sort(&ready_list, compare_priority_reverse, NULL);
	// msg("지금 스레드의 우선순위는 %d", thread_current()->priority);
	do_schedule (THREAD_READY);

	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	thread_current() -> priority = new_priority;
	if(!intr_context())  {
		// struct thread *cur = thread_current();
		// if (cur->priority < new_priority) {
		// 	cur->priority = new_priority;
		// 	thread_yield();
		// } else{
		// 	cur->priority = new_priority;
		// }
		thread_yield();
	}
	else intr_yield_on_return();
}

int max(int a, int b) {return a > b ? a : b;}

int _thread_get_priority(struct thread *t) {
	//enum intr_level old_level = intr_disable();
	int priority = t->priority;
	
	if(!thread_mlfqs) {
		for(struct list_elem *sema_elem = list_begin(&t->lock_list); sema_elem != list_end(&t->lock_list); sema_elem = list_next(sema_elem)) {
			struct semaphore *sema = list_entry(sema_elem, struct semaphore, elem);
			for(struct list_elem *waiter_elem = list_begin(&sema->waiters); waiter_elem != list_end(&sema->waiters); waiter_elem = list_next(waiter_elem)) {
				struct thread *waiter = list_entry(waiter_elem, struct thread, elem);
				priority = max(priority, _thread_get_priority(waiter));
			}
		}
	}
	//intr_set_level(old_level);
	return priority;
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	//return thread_current() -> priority;
	if (thread_mlfqs) {
		return thread_current()->priority;
	} else {
		return _thread_get_priority(thread_current());
	}

}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	if (thread_mlfqs) {
		thread_current()->nice = nice;
		int new_priority = PRI_MAX 
			- convert_to_int(div(thread_current()->recent_cpu, convert_to_fix(4)))
			- (nice * 2);
		if (new_priority > 63) {
			new_priority = 63;
		} else if (new_priority < 0) {
			new_priority = 0;
		}
		thread_set_priority(new_priority); //only when we test mlfqs
	}
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return thread_current()->nice;
}

void update_priority_blocked(struct thread *t) { //update itself, and blocked threads.
	int new_priority = PRI_MAX 
			- convert_to_int(div(t->recent_cpu , convert_to_fix(4)))
			- t->nice * 2;
	t->priority = new_priority;
	
	for(struct list_elem *sema_elem = list_begin(&t->lock_list); sema_elem != list_end(&t->lock_list); sema_elem = list_next(sema_elem)) {
		struct semaphore *sema = list_entry(sema_elem, struct semaphore, elem);
		for(struct list_elem *waiter_elem = list_begin(&sema->waiters); waiter_elem != list_end(&sema->waiters); waiter_elem = list_next(waiter_elem)) {
			struct thread *waiter = list_entry(waiter_elem, struct thread, elem);
			update_priority_blocked(waiter);
		}
	}
}

void update_priority_running() {
	update_priority_blocked(thread_current());
}

void update_priority_ready() {
	for (struct  list_elem *e = list_begin(&ready_list); e != list_end(&ready_list); e = list_next(e)) {
		struct thread *t = list_entry(e, struct thread, elem); 
		update_priority_blocked(t); 
	}
}

void update_priority_sleeping() {
	for(struct list_elem *sema_elem = list_begin(&sleeping_threads); sema_elem != list_end(&sleeping_threads); sema_elem = list_next(sema_elem)) {
		struct semaphore *sema = list_entry (sema_elem, struct semaphore, elem);
		struct thread *t = list_entry(list_front(&sema->waiters), struct thread, elem);
		update_priority_blocked(t);
	}
}

void update_priority() {
	update_priority_running();
	update_priority_ready();
	update_priority_sleeping();
}

// load_avg update 해주는 함수, load_avg는 17.14 형식 정수입니다.
void
update_load_avg(){
	int ready_num;
	if (thread_current() == idle_thread) {
		ready_num = list_size(&ready_list);
	} else {
		ready_num = list_size(&ready_list) + 1;
	}
	fixed_point_t div59_60 = div(convert_to_fix(59),convert_to_fix(60));
	fixed_point_t div1_60 = div(convert_to_fix(1),convert_to_fix(60));
	load_avg = add(mul(div59_60, load_avg), mul(div1_60, convert_to_fix(ready_num)));
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */

	return convert_to_int( mul(convert_to_fix(100), load_avg));
}

void update_recent_cpu_blocked (struct thread *t) {
	if (t != idle_thread) {
			fixed_point_t c = div(mul( convert_to_fix(2),load_avg),add(mul(convert_to_fix(2), load_avg),convert_to_fix(1)));
			t->recent_cpu = add(mul(c,t->recent_cpu),convert_to_fix(t->nice));
	}
	
	for(struct list_elem *sema_elem = list_begin(&t->lock_list); sema_elem != list_end(&t->lock_list); sema_elem = list_next(sema_elem)) {
		struct semaphore *sema = list_entry(sema_elem, struct semaphore, elem);
		for(struct list_elem *waiter_elem = list_begin(&sema->waiters); waiter_elem != list_end(&sema->waiters); waiter_elem = list_next(waiter_elem)) {
			struct thread *waiter = list_entry(waiter_elem, struct thread, elem);
			update_recent_cpu_blocked(waiter);
		}
	}
}

void update_recent_cpu_sleeping() {
	for(struct list_elem *sema_elem = list_begin(&sleeping_threads); sema_elem != list_end(&sleeping_threads); sema_elem = list_next(sema_elem)) {
		struct semaphore *sema = list_entry (sema_elem, struct semaphore, elem);
		struct thread *t = list_entry(list_front(&sema->waiters), struct thread, elem);

		fixed_point_t c = div(mul( convert_to_fix(2),load_avg),add(mul(convert_to_fix(2), load_avg),convert_to_fix(1)));
		t->recent_cpu = add(mul(c,t->recent_cpu),convert_to_fix(t->nice));
	}
}

// // recent_cpu update 해주는 함수, recent_cpu는 17.14 형식 정수입니다.
void
update_recent_cpu(){
	for (struct  list_elem *e = list_begin(&ready_list); e != list_end(&ready_list); e = list_next(e)) { //update running threads
		struct thread *t = list_entry(e, struct thread, elem); 
		/*
		// c=  2 * load_avg / (2 * load_avg + 1)
		if (t!= idle_thread) {
			fixed_point_t c = div(mul( convert_to_fix(2),load_avg),add(mul(convert_to_fix(2), load_avg),convert_to_fix(1)));
			t->recent_cpu = add(mul(c,t->recent_cpu),convert_to_fix(t->nice));
		}
		*/
		update_recent_cpu_blocked(t);
	}
	update_recent_cpu_sleeping(); //update sleeping threads.
	// block_list에 대해서 업데이트
	// for (struct  list_elem *e = list_begin(&block_list); e != list_end(&block_list); e = list_next(e)) {
	// 	struct thread *t = e;
	// 	// c=  2 * load_avg / (2 * load_avg + 1)
	// 	fixed_point_t c = div(mul( convert_to_fix(2),load_avg),add(mul(convert_to_fix(2), load_avg),convert_to_fix(1)));
	// 	t->recent_cpu = add(mul(c,t->recent_cpu),convert_to_fix(t->nice));
	// }
	struct thread *t = thread_current();
	update_recent_cpu_blocked(t); //update currently running thread
	// c=  2 * load_avg / (2 * load_avg + 1)

	// msg("load_avg 는 : %d, nice는 : %d", load_avg, convert_to_fix(t->nice));
	// msg("계산 전 : %d", t->recent_cpu);
	/*
	fixed_point_t c = div(mul(convert_to_fix(2),load_avg),add(mul(convert_to_fix(2), load_avg),convert_to_fix(1)));
	t->recent_cpu = add(mul(c,t->recent_cpu),convert_to_fix(t->nice));
	*/
	// msg("계산 후 : %d", t->recent_cpu);
	

}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return convert_to_int(mul(convert_to_fix(100),thread_current()->recent_cpu));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	//msg("thread_exit() by %d\n", thread_current()->priority);
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED; 
	// list_push_back(&block_list, &t->elem);
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	list_init(&t->lock_list);
	t->waiting_for = NULL;
	t->magic = THREAD_MAGIC;

}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else {
		struct thread *t = list_entry(list_max (&ready_list, compare_priority, NULL), struct thread, elem);
		list_remove(&t->elem);
		//struct thread *t = list_entry(list_pop_front(&ready_list), struct thread, elem);
		return t;
	}
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		// nested donation handling code
		/*
		struct thread *t = curr->waiting_for;
		while(t != NULL) {
			t->priority = curr->priority;
			t = t->waiting_for;
		}
		*/

		//printf("Hi: %d\n", next->priority);

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
