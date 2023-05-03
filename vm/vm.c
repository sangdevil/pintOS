/* vm.c: Generic interface for virtual memory objects. */

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
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
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
	if (!kva){
		frame = vm_evict_frame();
		PANIC("TODO");
	}

	frame = (struct frame *) malloc(sizeof(struct frame));
	if (!frame){
		// this should not happen.
		return NULL;
	}

	frame->kva = kva;
	frame->page = NULL;
	list_push_back(&frame_table, &frame->elem);
	
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}


/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(!is_user_vaddr(addr)) {
		return false;
	}
	page = spt_find_page(spt, addr);
	if(page == NULL) {
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
	// msg("%p -> %p", page->va, frame->kva);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	uint64_t *pml4 = thread_current()->pml4;
	if (!pml4_set_page(pml4, page->va, frame->kva, page->writable)){ // ?
		//msg("vm_do_clam_page returns false.");
		return false;
	}
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


// 왜 spt_find_page, vm_claim_page, vm_do_claim_page 세가지 함수를 만들었을까? 
// 결국 세 개를 하나로 합쳐도 될 것 같은데... 일단 구현하라는데 하긴 했는데, 3개가 거의 이어짐.
// spt_find_page는 주어진 va로부터 page를 return, vm_claim_page는 vm_do_claim 호출,
// vm_do_claim_page는 주어진 페이지가 이미 프레임과 연결이 됐는지를 확인.
// 그리고 swap in을 통해 물리 메모리에 올림. 근데 swap in은 어디에 ?