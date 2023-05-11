/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	// msg("here 11");
	page->operations = &file_ops;
	struct args *args = page->uninit.aux;
	struct file *file = args->file;
	// msg("file init : %p",file);
	// msg("file length, init : %d", file_length(file));
	// msg("here 12");
	off_t ofs = args->ofs;
	uint8_t *upage = args->upage;
	size_t page_read_bytes = args->page_read_bytes;
	size_t page_zero_bytes = args->page_zero_bytes;
	bool writable = args->writable;
	// msg("here 13");

	struct file_page *file_page = &page->file;
	file_page->pml4 = thread_current()->pml4;
	// msg("here 14");
	file_page->file = file;
	file_page->ofs = ofs;
	file_page->page_read_bytes = page_read_bytes;
	file_page->page_zero_bytes = page_zero_bytes;
	file_page->writable = writable;
	// msg("here 15");
	
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	// msg("here 16");
	//simillar as do_mmap, lazy_load
	struct file_page *file_page = &page->file;
	struct file *file = file_page->file;

	off_t ofs = file_page->ofs;
	uint8_t *upage = file_page->upage;
	size_t page_read_bytes = file_page->page_read_bytes;
	size_t page_zero_bytes = file_page->page_zero_bytes;
	bool writable = file_page->writable;

	//msg("%p -> %p", page->va, frame->kva);
	bool user_lock_held;
	if(!(user_lock_held = lock_held_by_current_thread(&user_lock))) {
		user_lock_acquire();
	}
	/* Load this page. */
	off_t bytes = file_read_at(file, kva, page_read_bytes, ofs);
	if(!user_lock_held) {
		user_lock_release();
	}
	if (bytes != (int) page_read_bytes) {
		msg("Hi");
		return false;
	}
	memset (kva + page_read_bytes, 0, page_zero_bytes);

	uint64_t *pml4 = file_page->pml4;
	if(!pml4_set_page(pml4, page->va, kva, page->writable)) {
		return false;
	}
	// msg("here17");
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	// msg("here18");
	struct file_page *file_page = &page->file;
	// msg("fileum : %p", page_info->file);
	// msg("file length, m : %d", file_length(page_info->file));
	if (pml4_is_dirty( file_page->pml4, page->va)) {
		// msg("dirty");
		// msg("kva : %p", mapped_page->frame->kva);
		// msg("addr : %p", addr);
		// msg("kva data : %s", mapped_page->frame->kva);
		// msg("addr data : %s", addr);
		// msg("page addr : %p", mapped_page->va);
		off_t x = file_write_at( file_page->file, page->frame->kva, file_page->page_read_bytes, file_page->ofs);
		if (x != file_page->page_read_bytes)
			return false;
		// msg("fileum : %p", page_info->file);
		// msg("file length, m : %d", file_length(page_info->file));
		// msg("actually read byte : %lld", x);
		pml4_set_dirty(file_page->pml4, page->va, false);
	}
	// msg("4");
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(file_page->pml4,page->va);
	// msg("here19");
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;
	// file_close(file_page->file);
}


/* process.h include 하고, process.h에 lazy 추가해도 안 돼서 그냥 가져옴. */
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
	/* Get a page of memory. */
	struct frame *frame = page->frame;
	void *kpage = frame->kva;

	//msg("%p -> %p", page->va, frame->kva);
	bool user_lock_held;
	if(!(user_lock_held = lock_held_by_current_thread(&user_lock))) {
		user_lock_acquire();
	}
	/* Load this page. */
	off_t bytes = file_read_at(file, kpage, page_read_bytes, ofs);
	if(!user_lock_held) {
		user_lock_release();
	}
	if (bytes != (int) page_read_bytes) {
		msg("Hi");
		return false;
	}
	memset (kpage + page_read_bytes, 0, page_zero_bytes);
	/* Add the page to the process's address space. */
	// uint64_t *pml4 = thread_current()->pml4;
	// if (!pml4_set_page(pml4, upage, kpage, writable)) { // ?
	// 	return false;
	// }
	// msg("file, lazy : %p", file);
	// msg("file length, lazy : %d", file_length(file));
	return true;
}

/* Do the mmap, load_segment와 거의 유사 */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {	
	// invalid한 호출은 체크된 상태로 들어온다고 가정 <- 이 부분은 syscall.c에 구현
	off_t file_offs = offset;
	struct file *open_f = file;
	void *current_addr = addr;
	// 이 과정에서 lock을 걸어야 하는지 아닌지는 test case 돌려보면서 생각
	open_f = file_reopen (file);
	// msg("filem : %p",open_f);
	// msg("file length, m : %d", file_length(open_f));
	if ( !open_f ) {
		return NULL;
	}	
	// if (writable) {
	// 	file_allow_write(open_f);
	// }
	length = length < file_length(file) ? length : file_length(file) ;
	while (length > 0) {
		// msg("fukc you %d", length);
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		// 그 파일에서 얼마나 진행했는 지에 대한 offset
		// reopen으로 열기

		// aux에 해당하는, file_page = args 에 해당하는 구조를 삽입
		struct args *current_args = (struct args *) malloc (sizeof (struct args));
		if ( !current_args ) {
			file_close (open_f);
			return NULL;
		}
		// msg("current off : %lld", file_offs);
		// msg("current read : %lld", page_read_bytes);
		// msg("current zero : %lld", page_zero_bytes);
		// msg("current addr : %p", current_addr);
		current_args->file = open_f;
		current_args->ofs = file_offs;
		current_args->page_read_bytes = page_read_bytes;
		current_args->page_zero_bytes = page_zero_bytes;
		current_args->writable = writable;
		// 좀 애매.. 왜 uint8 이지?
		current_args->upage = current_addr;
		if (!vm_alloc_page_with_initializer (VM_FILE, current_addr , writable, lazy_load_segment , current_args)) {
			free (current_args);
			return NULL;
		}
		// load_segment처럼 더해주기
		length -= page_read_bytes;
		file_offs += page_read_bytes;
		current_addr += PGSIZE;
		// msg("fukc you!! %d", length);
	}
	// msg("mmap finsih");
	return addr;
}
/* Do the munmap */
void
do_munmap (void *addr) {
	// msg("1");
	struct page *mapped_page = spt_find_page(&thread_current()->spt, addr);
	if (!mapped_page) {
		return;
	}
	// msg("2");
	struct file_page *page_info = &mapped_page->file;
	// msg("fileum : %p", page_info->file);
	// msg("file length, m : %d", file_length(page_info->file));
	if (pml4_is_dirty( page_info->pml4, addr)) {
		// msg("dirty");
		// msg("kva : %p", mapped_page->frame->kva);
		// msg("addr : %p", addr);
		// msg("kva data : %s", mapped_page->frame->kva);
		// msg("addr data : %s", addr);
		// msg("page addr : %p", mapped_page->va);
		off_t x = file_write_at( page_info->file, mapped_page->frame->kva, page_info->page_read_bytes, page_info->ofs);
		// msg("fileum : %p", page_info->file);
		// msg("file length, m : %d", file_length(page_info->file));
		// msg("actually read byte : %lld", x);
		pml4_set_dirty(page_info->pml4, addr, false);
	}
	// msg("4");
	pml4_clear_page(page_info->pml4,addr);
	return;
}
