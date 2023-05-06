#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"

struct page;
enum vm_type;

struct anon_page {
    disk_sector_t sec_no; //이 page가 swap disk에 저장된 위치
    uint64_t *pml4; //이 page를 소유한 thread의 pml4.
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
