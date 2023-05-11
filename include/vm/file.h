#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

// args랑 같은 구조를 가지도록 생성 
struct file_page {
    // disk_sector_t sec_no;   //이 page가 swap disk에 저장된 위치
    uint64_t *pml4;         //이 page를 소유한 thread의 pml4.
	struct file *file;
	off_t ofs;
	uint8_t *upage;
	size_t page_read_bytes;
	size_t page_zero_bytes;
	bool writable;	
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
