#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "kernel/list.h"

static void syscall_handler (struct intr_frame *);
void * is_valid_addr(const void *vaddr);
struct process_file* search_fd(struct list* files, int fd);
void exit_process(int status);
void syscall_halt(void);
void syscall_exit(struct intr_frame *f);
int syscall_write(struct intr_frame *f);



void pop_stack(int *esp, int *a, int offset){
	int *tmp_esp = esp;
	*a = *((int *)is_valid_addr(tmp_esp + offset));
}

  /* Find fd and return process file struct in the list,
  if not exist return NULL. */
struct process_file *
search_fd(struct list* files, int fd)
{
	struct process_file *proc_f;
	struct list_elem *e;
	for (e = list_begin(files); e != list_end(files); e = list_next(e)) {
		proc_f = list_entry(e, struct process_file, elem);
		if (proc_f->fd == fd)
			return proc_f;
	}
	return NULL;
}


void syscall_halt(void){
	shutdown_power_off();
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int *p = f->esp;
  int system_call = *p;
  switch (system_call) {
    case SYS_HALT:
      syscall_halt();
      break;
    case SYS_EXIT:
      syscall_exit(f);
      break;
    case SYS_WRITE:
      f->eax = syscall_write(f);
      break;
    default:
      break;
  }
}


void * is_valid_addr(const void *vaddr)
{
	void *page_ptr = NULL;
	if (!is_user_vaddr(vaddr) || !(page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr)))
	{
		exit_process(-1);
		return 0;
	}
	return page_ptr;
}


void exit_process(int status)
{
	struct child_process *cp;
	struct thread *cur_thread = thread_current();

	enum intr_level old_level = intr_disable();
	struct list_elem *e;
	for (e = list_begin(&cur_thread->parent->children_list); e != list_end(&cur_thread->parent->children_list); e = list_next(e)) {
		cp = list_entry(e, struct child_process, child_elem);
		if (cp->tid == cur_thread->tid)
		{
			cp->if_waited = true;
			cp->exit_status = status;
		}
	}
	cur_thread->exit_status = status;
	intr_set_level(old_level);

	thread_exit();
}

  /* close and free all process files in the file list */
void
clean_all_files(struct list* files)
{
	struct process_file *proc_f;
	while(!list_empty(files))
	{
		proc_f = list_entry (list_pop_front(files), struct process_file, elem);
		file_close(proc_f->ptr);
		list_remove(&proc_f->elem);
		free(proc_f);
	}
}



void syscall_exit(struct intr_frame *f)
{
	int status;
	pop_stack(f->esp, &status, 1);
	exit_process(status);
}


int
syscall_write(struct intr_frame *f)
{
	int res;
	int size;
	void *buffer;
	int fd;

	pop_stack(f->esp, &size, 7);
	pop_stack(f->esp, &buffer, 6);
	pop_stack(f->esp, &fd, 5);

	if (!is_valid_addr(buffer))
		res = -1;

	if (fd == 1)
	{
		putbuf(buffer, size);
		res = size;
	}
	else
	{
		enum intr_level old_level = intr_disable();
		struct process_file *pf = search_fd(&thread_current()->opened_files, fd);
		intr_set_level (old_level);

		if (pf == NULL)
			res = -1;
		else
		{
			lock_acquire(&filesys_lock);
			res = file_write(pf->ptr, buffer, size);
			lock_release(&filesys_lock);
		}
	}

	return res;
}



