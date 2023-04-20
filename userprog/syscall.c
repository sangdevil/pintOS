#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
// #include "threads/init.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
// #include "filesys/inode.h"
// #include "filesys/directory.h"
// #include "filesys/off_t.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/palloc.h"

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

struct lock user_lock;
/* 현재 파일 fp를 열어주고 적절한 file_descripter를 생성하는 함수 */
int process_file_descriptor(struct file *fp) {
	struct thread *cur = thread_current();
	struct file_descriptor *fd;
	// 스레드에 존재하는 open_file 들 중에서 이미 열려 있는 지 아닌 지를 확인

	// for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)){
	// 	fd = list_entry(e, struct file_descriptor, elem);
	// 	if (fd->file == fp) {
	// 		return fd->fd;
	// 	}
	// }
	// 여기서 fd 를 생성해 줍시다. 이 파일은 안 열렸으니까요
	fd = (struct file_descriptor *) malloc (sizeof *fd);
	struct my_int *fds = (struct my_int *) malloc (sizeof (struct my_int));
	if (fd && fds) {
		list_init(&fd->int_list);
		fds->n = cur->next_fd++;
		fd->file = fp;
		fd->file_size = file_length(fp);
		list_push_back(&fd->int_list, &fds->elem);
		list_push_back(&cur->fd_list, &fd->elem);
		//msg("%d", fd->fd);
		return fds->n; 
	} else {
		return -1;
	}

}

// fd가 현재 스레드에 존재하는 지 확인 후 삭제.
bool remove_file_by_fd(int fd) {

	struct thread *cur = thread_current();
	struct file_descriptor *cur_fd;
	struct my_int *cur_n;
	bool remove_cur = false;

	// printf("%s 가 %d 를 지우래요\n",cur->name , fd);
	// msg("지우기 전, ");
	// for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
	// 	cur_fd = list_entry(e, struct file_descriptor, elem);
	// 	for (struct list_elem *e1 = list_begin(&cur_fd->int_list); e1 != list_end(&cur_fd->int_list); e1 = list_next(e1)){
	// 		cur_n = list_entry(e1, struct my_int, elem);
	// 		printf("현재, fd : %d, file : %d\n", cur_n->n, cur_fd->file);
	// 	}
	// }
	for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
		bool found = false;
		cur_fd = list_entry(e, struct file_descriptor, elem);
		// msg("현재 파일의 int_list 크기 : %d", list_size(&cur_fd->int_list));
		for (struct list_elem *e1 = list_begin(&cur_fd->int_list); e1 != list_end(&cur_fd->int_list); e1 = list_next(e1)){
			cur_n = list_entry(e1, struct my_int, elem);
			// msg("현재 n : %d", cur_n->n);
			if (cur_n->n == fd) {
				if (list_size(&cur_fd->int_list) == 1) {
					remove_cur = true;
				} 
				found = true;
				list_remove(&cur_n->elem);
				free(cur_n);
				break;
			}
		}
		// printf("현재, fd : %d, file : %lld, ref_num : %d\n", cur_fd->fd, cur_fd->file, *cur_fd->ref_num);
		if (found){
			if (remove_cur) {
				file_close(cur_fd->file);
				e = list_remove(e);
				free(cur_fd);
			} 
			break;
		}

	}

	// msg("지운 후 , ");
	// for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
	// 	cur_fd = list_entry(e, struct file_descriptor, elem);
	// 	for (struct list_elem *e1 = list_begin(&cur_fd->int_list); e1 != list_end(&cur_fd->int_list); e1 = list_next(e1)){
	// 		cur_n = list_entry(e1, struct my_int, elem);
	// 		printf("현재, fd : %d, file : %d\n", cur_n->n, cur_fd->file);
	// 	}
	// }
	
	// 즉, 삭제 할 게 없으면 아무 것도 하지 않습니다. 
	return remove_cur;
}

struct file_descriptor *find_file_descriptor_by_fd(int fd) {

	struct thread *cur = thread_current();
	struct file_descriptor *cur_fd;
	for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
		cur_fd = list_entry(e, struct file_descriptor, elem);
		for (struct list_elem *e1 = list_begin(&cur_fd->int_list); e1 != list_end(&cur_fd->int_list); e1 = list_next(e1)){
			struct my_int *cur_n = list_entry(e1, struct my_int, elem);
			if (cur_n->n == fd){
				return cur_fd;
			}
		}
	}

	return NULL;
}

/*
bool valid_address(const void *name) {
	if (!is_user_vaddr(name)) {
		return false;
	}

	void *page = pg_round_down(name);
	uint64_t *pte = pml4e_walk(thread_current()->pml4, (uint64_t) page, false);
  	if (pte == NULL || !(*pte & PTE_P) || !is_user_pte(pte))
    	return false;

	return true;
}
*/

// modified from pml4_get_page.
// write = true for read(), when we write to buffer.
void *translate_address(void *vaddr, bool write) { 
	if(!is_user_vaddr(vaddr)) {
		return NULL;
	}

	uint64_t *pml4 = thread_current()->pml4;
	uint64_t *pte = pml4e_walk (pml4, (uint64_t) vaddr, 0);
	
	if (pte && (*pte & PTE_P)  && is_user_pte(pte) && (!write || is_writable(pte))) {
		return ptov (PTE_ADDR (*pte)) + pg_ofs (vaddr);
	}

	return NULL;
}


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

	lock_init(&user_lock);
}

/* The main system call interface */
/* 결국에 이놈은 f->R에 레지스터들을 적절하게 잘 넣어서 각 syscall에 해당하는 일들을 적절히 해준 뒤,
f->R.rax에 다시 넣어주는 것임. */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	//printf ("system call number: %d\n", f->R.rax);
	//printf ("rdi = %d, rsi = %p, rdx = %d\n", f->R.rdi, (void *)f->R.rsi, f->R.rdx);
	//hex_dump(0, (void *)f->R.rsi, f->R.rdx, true);
	switch(f->R.rax) { //system call number. Refer to lib/user/syscall.c for each system call functions.
		
		case SYS_HALT: {                  /* Halt the operating system. */
			power_off();
			break;
		}
		case SYS_EXIT: {                  /* Terminate this process. */
			int status = f->R.rdi;
			_thread_exit(status);
			// struct thread *cur = thread_current();
			// cur->exit_code = status;
			// thread_exit();
			break;
		}
		case SYS_FORK: {                  /* Clone current process. */
			const char *thread_name = (const char *) f->R.rdi;

			tid_t tid = process_fork(thread_name, f);

			// msg("here, tid is %d", tid);
			f->R.rax = tid;
			break;
		}
		case SYS_EXEC: {                  /* Switch current process. */
			const char *cmd_line = (const char *)f->R.rdi;
			cmd_line = translate_address((void *)cmd_line, 0);
			if(!cmd_line) {
				_thread_exit(-1);
			}
			char *fn_copy = palloc_get_page(0); //we need this because process_exec calls palloc_free_page on f_name.
			if (!fn_copy) {
				_thread_exit(-1); //terminate when fail.
			}
			strlcpy(fn_copy, cmd_line, PGSIZE); //page fault occurs here, probably because kernel can't translate user virtual address?

			// 현재 열린 파일들에 대해서 모두 파일 접근을 금지하자.
			struct thread *cur = thread_current();
			struct file_descriptor *cur_fd;
			for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
				cur_fd = list_entry(e, struct file_descriptor, elem);
				if (cur_fd->file)
					file_deny_write(cur_fd->file);
			}
			int fail = process_exec(fn_copy);
			for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
				cur_fd = list_entry(e, struct file_descriptor, elem);
				if (cur_fd->file)
					file_allow_write(cur_fd->file);
			}
			_thread_exit(fail);
			break;
		}
		case SYS_WAIT: {                  /* Wait for a child process to die. */
			tid_t tid = (tid_t) f->R.rdi;
			int status = process_wait(tid);
			f->R.rax = status;
			break;
		}
		case SYS_CREATE: {                /* Create a file. */
			const char *name = (const char *) f->R.rdi;
			bool success = false;
			// 먼저, 이 이름이 valid한지 확인 후, name이 가지고 있는 주소가 유효한 주소인지를 확인한다. 
			// 유효한 주소가 아니라면, exit 해야 함.
			if (name && (name = translate_address((void *)name, 0))) {
				success = filesys_create(name, f->R.rsi);  /*성공하면 1 아니면 0 */
			} else {
				f->R.rax = -1;
				_thread_exit(-1);
			}
			f->R.rax = success;
			break;
		}
		case SYS_REMOVE: {                /* Delete a file. */
			const char *name = (const char *) f->R.rdi;
			// 먼저, 이 이름이 valid한지 확인 후,
			if ( name = translate_address((void *)name, 0) ) {
				bool success = filesys_remove(name);
				f->R.rax = success;
			} 
			
			break;
		}
		case SYS_OPEN: {                  /* Open a file. */
			// printf ("system call!\n");
			const char *name = (const char *) f->R.rdi;
			struct file *fp = NULL;
			// 먼저, 이 이름이 valid한지 확인 후, name이 가지고 있는 주소가 유효한 주소인지를 확인한다. 
			// 유효한 주소가 아니라면, exit 해야 함.
			lock_acquire(&user_lock);
			if (name && (name = translate_address((void *) name, false))) {
				fp = filesys_open(name);
				if(!fp) {
					// printf("%s, file open error!", thread_current()->name);
					f->R.rax = -1;
					lock_release(&user_lock);
					return;
				}
				
				struct ELF64_hdr ehdr;
				off_t x = file_read_at (fp, &ehdr, sizeof ehdr, 0);
				if (x != sizeof ehdr 
				|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
				|| ehdr.e_type != 2
				|| ehdr.e_machine != 0x3E // amd64
				|| ehdr.e_version != 1
				|| ehdr.e_phentsize != sizeof (struct Phdr)
				|| ehdr.e_phnum > 1024) {
				; //do nothing
				}
				else {
					if(strcmp( thread_current()->name, name ) == 0 ) {
						file_deny_write(fp);
					}
				}
			} 	else {
				//f->R.rax = -1;	
				lock_release(&user_lock);
				_thread_exit(-1);
				return;
			}
			// valid한 경우에만 파일을 연다. 
			int file_descripter = process_file_descriptor(fp);
			f->R.rax = file_descripter;
			lock_release(&user_lock);
			// msg("succefully opened %s : %d", name, file_descripter);
			// printf("%d\n",file_descripter);
			break;
		}
		case SYS_FILESIZE: {              /* Obtain a file's size. */
			struct thread *cur = thread_current();
			struct file_descriptor *fd;
			// 스레드에 존재하는 open_file 들 중에서 이미 열려 있는 지 아닌 지를 확인
			// 만약 없으면 어떻게 처리할까? -> 미구현, 에러 케이스가 없는 거 보니 없지 않을까라는 게 생각이지만, 일단 구현은 해놓음 -1로.
			fd = find_file_descriptor_by_fd((int) f->R.rdi);
			if (fd) {
				f->R.rax = fd->file_size;
				return;
			}
			
			f->R.rax = -1;
			break;
		}
		case SYS_READ: {                  /* Read from a file. */
			struct thread *cur = thread_current();
			struct file_descriptor *fd;
			
			// 스레드에 존재하는 open_file 들 중에서 이미 열려 있는 지 아닌 지를 확인
			// 만약 없으면 어떻게 처리할까? -> 미구현
			// 디버깅용
			// printf("현재 스레드 : %s, 가지고 있는 파일은 ", cur->name);
			// for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)){
			// 	fd = list_entry(e, struct file_descriptor, elem);
			// 	printf("%d, ", fd->fd);
			// }
			// printf("\n");

			// 디버깅 마무리

			fd = find_file_descriptor_by_fd((int) f->R.rdi);
			if (fd) {
				void *buff = translate_address((void *)f->R.rsi, true);
				unsigned size = f->R.rdx;
				if (buff) {
					if (fd->file) {
						lock_acquire(&user_lock);
						// printf("current read request : %lld\n", (int64_t) buff);
						f->R.rax = file_read(fd->file, buff, size);
						lock_release(&user_lock);
					}
					return;
				} else {
					// printf("유효하지 않은 주소\n");
					f->R.rax = -1;
					_thread_exit(-1);
					return;
				}
			}
			// printf("파일이 없어요!\n");
			f->R.rax = -1;					/* 여기는 아마 실행되면 안 될 듯*/
			_thread_exit(-1);
			break;
		}
		case SYS_WRITE: {                  /* Write to a file. */
			int fd = f->R.rdi;
			const void *buffer = (const void *) f->R.rsi;
			unsigned size = (unsigned) f->R.rdx;
			if (translate_address((void *) buffer, true) == NULL) {
				_thread_exit(-1);	
				return;
			}
			// msg("try to write at : %d", fd);
			struct file_descriptor *fp = find_file_descriptor_by_fd(fd);
			if (fp == NULL) {
				f->R.rax = 0;
				return;
			} else {
				// file_size 가 -2, 즉 stdout일 때는 putbuf 사용
				lock_acquire(&user_lock);
				if (fp->file_size==-2) {
					putbuf(buffer, size); // defined in lib/kernel/console.c
					f->R.rax = size;
				} else {
					if (fp->file) {
						
						f->R.rax = file_write(fp->file, buffer, size);
						
					}
				}
				lock_release(&user_lock);
			}
			break;
		}
		case SYS_SEEK: {                  /* Change position in a file. */
			int fd = (int) f->R.rdi;
			unsigned position = (unsigned) f->R.rsi;
			struct file_descriptor *fp = find_file_descriptor_by_fd(fd);
			if (fp == NULL) {
				f->R.rax = -1;
				break;
			}
			if (fp->file)
				file_seek(fp->file, position);
			break;
		}
		case SYS_TELL: {                  /* Report current position in a file. */
			int fd = (int) f->R.rdi;
			struct file_descriptor *fp = find_file_descriptor_by_fd(fd);
			if (fp==NULL){
				f->R.rax = -1;
				// printf("fuck you\n");
				break;
			}
			if (fp->file)
				f->R.rax = file_tell(fp->file);
			break;
		}
		case SYS_CLOSE: {                 /* Close a file. */
			int fd = (int) f->R.rdi;
			bool suc = remove_file_by_fd(fd);
			break;
		}
		case SYS_DUP2: {
			int fd1 = (int) f->R.rdi;
			int fd2 = (int) f->R.rsi;

			struct thread *cur = thread_current();
			struct file_descriptor *cur_fd;
			struct my_int *cur_n;
			// msg("%s의 복사 요청 ! %d to %d",cur->name, fd1, fd2);
			// for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
			// 	cur_fd = list_entry(e, struct file_descriptor, elem);
			// 	for (struct list_elem *e1 = list_begin(&cur_fd->int_list); e1 != list_end(&cur_fd->int_list); e1 = list_next(e1)){
			// 		cur_n = list_entry(e1, struct my_int, elem);
			// 		printf("현재, fd : %d, file : %lld\n", cur_n->n, cur_fd->file);
			// 	}
			// }
			struct file_descriptor *file_descriptor1 = find_file_descriptor_by_fd(fd1);
			if (!file_descriptor1) {
				f->R.rax = -1;
				return;
			}
			if (fd1 == fd2) {
				f->R.rax = fd1;
				return;
			}
			// check if fd2 is already open
			struct file_descriptor* file_descriptor2 = find_file_descriptor_by_fd(fd2);
			
			if (file_descriptor2) {				
				// msg("%d를 닫습니다", fd2);
				remove_file_by_fd(fd2);
			}
			struct my_int *fds = (struct my_int *) malloc (sizeof (struct my_int));
			if (!fds) {
				f->R.rax = -1;
				_thread_exit(-1);
			}
			fds->n = fd2;
			list_push_back(&file_descriptor1->int_list, &fds->elem);
			f->R.rax = fd2;
			// msg("%s의 복사 요청 %d to %d : 완료",cur->name, fd1, fd2);
			// for (struct list_elem *e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
			// 	cur_fd = list_entry(e, struct file_descriptor, elem);
			// 	for (struct list_elem *e1 = list_begin(&cur_fd->int_list); e1 != list_end(&cur_fd->int_list); e1 = list_next(e1)){
			// 		cur_n = list_entry(e1, struct my_int, elem);
			// 		printf("현재, fd : %d, file : %lld\n", cur_n->n, cur_fd->file);
			// 	}
			// }
			break;
		}
	// thread_exit ();
	}
}
