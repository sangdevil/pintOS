/* vm.c: Generic interface for virtual memory objects. */
#define MAX_STACK_SIZE (1<<20)

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/vm.h"
#include "vm/inspect.h"

uint64_t page_hash(const struct hash_elem *e, void *aux UNUSED);
bool page_less(const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED);
struct list frame_table;
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	struct page *page = NULL;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		//msg("%d, %p, %d", thread_current()->tid, upage, writable);

		page = (struct page *) malloc(sizeof (struct page));
		if(!page) {
			//printf("malloc error");
			goto err;
		}
		switch(type) {
			case VM_ANON:
				uninit_new(page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new(page, upage, init, type, aux, file_backed_initializer);
				break;
			default:
				//printf("type error");
				goto err;
				break;
		}

		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		if(!spt_insert_page(spt, page)) {
			//printf("spt_insert_page error");
			goto err;
		}

		return true;
	}
err:
	//msg(" at vm_alloc_page_with_initializer !");
	free(page);
	return false;
}



/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	/* TODO: Fill this function. */
	struct page page;
	page.va = pg_round_down(va);
	struct hash_elem *e = hash_find(&spt->pages, &page.elem);
	if (!e) {
		return NULL;
	} else {
		return hash_entry(e, struct page, elem);
	}
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
	succ = spt_find_page(spt, page->va) == NULL;
	if(succ) {
		hash_insert(&spt->pages, &page->elem);
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	//naive FIFO implementation
	struct list_elem *e = list_pop_front(&frame_table);
	victim = list_entry(e, struct frame, elem);
	list_push_back(&frame_table, e);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	struct page *page = victim->page;
	//msg("evicted: %p -> %p", page->va, victim->kva);
	if(!swap_out(page)) {
		return NULL;
	}
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER);
	if (!kva) {
		//PANIC("TODO");
		//msg("palloc failed.");
		frame = vm_evict_frame();
	}
	else {
		//msg("palloc successful.");
		frame = (struct frame *) malloc(sizeof(struct frame));
		if (!frame){
			// this should not happen.
			// return NULL;
			PANIC("vm_get_frame error!");
		}
		frame->kva = kva;
		frame->page = NULL;
		
		list_push_back(&frame_table, &frame->elem);
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	addr = pg_round_down(addr);
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;
	do {
		//msg("%p", addr);
		ASSERT((uintptr_t)addr >= USER_STACK - MAX_STACK_SIZE);
		vm_alloc_page(VM_ANON, addr, true);
		if(!vm_claim_page(addr)) {
			PANIC("vm_stack_growth error!"); //?
		}
		addr = (void *) ((uintptr_t)addr + PGSIZE);
		page = spt_find_page(spt, addr);
	} while(page == NULL);
}


/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user UNUSED, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(!is_user_vaddr(addr) || (write && !not_present)) { //writing r/o page.
		return false;
	}
	//msg("faulting address: %p, user = %d, write = %d, not_present = %d", addr, user, write, not_present);
retry:
	page = spt_find_page(spt, addr);
	if(page == NULL) {
		uintptr_t rsp = f->rsp;
		if(rsp-8 <= (uintptr_t)addr && (uintptr_t)addr < USER_STACK) { //stack growth. rsp-8 for push instruction.
			vm_stack_growth(addr);
			goto retry;
		}

		return false; // user tried to access unallocated page.
	}
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;

	/* TODO: Fill this function */
	struct supplemental_page_table *spt = &thread_current()->spt;
	page = spt_find_page(spt, va);

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	/* Set links */
	frame->page = page;
	page->frame = frame;
	//msg("%p -> %p", page->va, frame->kva);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	uint64_t *pml4 = thread_current()->pml4; // ?
	if (!pml4_set_page(pml4, page->va, frame->kva, page->writable)){ // ?
		return false;
	}
	//msg("name = %s, %p -> %p, %d", thread_current()->name, page->va, frame->kva, VM_TYPE(page->operations->type));
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct hash_iterator i;
	hash_first (&i, &src->pages);
	while (hash_next (&i)) {
		struct page *page = hash_entry (hash_cur (&i), struct page, elem); 
		switch(VM_TYPE(page->operations->type)) { //VM_UNINIT, VM_ANON or VM_FILE
			case VM_UNINIT: {
				struct args *args = NULL;
				void *aux = page->uninit.aux;
				if(aux) {
					args = (struct args *)malloc(sizeof (struct args));
					memcpy(args, (struct args *)aux, sizeof (struct args));
					user_lock_acquire();
					args->file = file_duplicate(((struct args *)aux)->file);
					user_lock_release();
				}
				if(!vm_alloc_page_with_initializer(page_get_type(page), page->va, page->writable, page->uninit.init, (void *)args)) {
					return false;
				}
				break;
			}
			default: {
				if(!vm_alloc_page(page_get_type(page), page->va, page->writable)) { //VM_ANON or VM_FILE
					return false;
				}
				if(!vm_claim_page(page->va)) {
					return false;
				}
				struct page *page_copy = spt_find_page(dst, page->va);
				memcpy(page_copy->frame->kva, page->frame->kva, PGSIZE);
				break;
			}
		}
	}
	
	return true;
}

static void 
page_free (struct hash_elem *element, void *aux UNUSED) {
	struct page *page = hash_entry(element, struct page, elem);
	vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->pages, page_free);
}


/* page hash function, hashing by virtual address */
uint64_t
page_hash(const struct hash_elem *e, void *aux UNUSED) {
	struct page *p = hash_entry (e, struct page, elem);
    return hash_bytes (&p->va, sizeof p->va);
}

/* page less function, compare the virtual address */
bool
page_less(const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED) {
	struct page *p1 = hash_entry(e1, struct page, elem);
	struct page *p2 = hash_entry(e2, struct page, elem);
	return p1->va < p2->va;
}

struct frame *ft_find_frame(void *kva) {
	for(struct list_elem *e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
		struct frame *frame = list_entry(e, struct frame, elem);
		if(frame->kva == kva) {
			return frame;
		}
	}
	return NULL;
}