/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

#define SECTOR_CNT (PGSIZE / DISK_SECTOR_SIZE)

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

struct bitmap *swap_table;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	disk_sector_t size = disk_size(swap_disk);
	swap_table = bitmap_create(size);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->pml4 = thread_current()->pml4;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	//msg("swap in: Hi!");

	//swap table
	disk_sector_t sec_no = anon_page->sec_no;
	for(disk_sector_t i = 0; i < SECTOR_CNT; i++) {
		disk_read(swap_disk, sec_no + i, ((uintptr_t)kva) + i*DISK_SECTOR_SIZE);
	}
	bitmap_set_multiple(swap_table, sec_no, SECTOR_CNT, false);

	//frame table
	struct frame *frame = ft_find_frame(kva);
	ASSERT(frame != NULL);
	page->frame = frame;
	frame->page = page;

	//page table
	uint64_t *pml4 = anon_page->pml4;
	if(!pml4_set_page(pml4, page->va, kva, page->writable)) {
		return false;
	}

	//msg("swap in: Bye!");

	return true;

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//msg("swap out: Hi!");
	//swap table
	disk_sector_t sec_no = bitmap_scan_and_flip(swap_table, 0, SECTOR_CNT, false);
	if(sec_no == BITMAP_ERROR) {
		return false; // swap space is full.
	}
	struct frame *frame = page->frame;
	for(disk_sector_t i = 0; i < SECTOR_CNT; i++) {
		disk_write(swap_disk, sec_no + i, ((uintptr_t)frame->kva) + i*DISK_SECTOR_SIZE); //todo: don't need to write when dirty = 0.
	}
	anon_page->sec_no = sec_no;

	//frame table
	page->frame = NULL;
	frame->page = NULL;

	//page table
	uint64_t *pml4 = anon_page->pml4;
	pml4_clear_page(pml4, page->va);

	//msg("swap out: Bye!");

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	struct frame *frame = page->frame;
	if(frame) {
		list_remove(&frame->elem);
		free(frame);	
	}
}
