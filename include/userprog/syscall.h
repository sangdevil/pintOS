#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>
/* file descriptor. -> 배선우 추가*/
struct file_descriptor {
  	struct list int_list;                         /* File descriptor number. */
	int file_size;					/* file.c 수정하기 싫어서 file_size 변수 추가. */
  	struct file *file;              /* Pointer to the open file. */
  	struct list_elem elem;          /* List element. */
};

struct my_int {
	int n;
	struct list_elem elem;
};

struct lock user_lock;
void user_lock_acquire(void);
void user_lock_release(void);

int process_file_descriptor(struct file *fp);

void syscall_init (void);
struct file_descriptor *find_file_descriptor_by_fd(int fd);
bool remove_file_by_fd(int fd);

#endif /* userprog/syscall.h */
