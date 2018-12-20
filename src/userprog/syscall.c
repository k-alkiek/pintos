#include "userprog/syscall.h"
#include <stdlib.h>
#include <stdio.h>
#include <syscall-nr.h>

#include "userprog/process.h"
#include <kernel/list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef uint32_t pid_t;
#define EXIT_ERROR -1

struct lock file_system_lock;

static void syscall_handler (struct intr_frame *);

static void halt_handler (void);
static void process_exit_handler (int status);
static pid_t process_execute_handler (const char *process_name);
static int process_wait_handler (pid_t pid);
static bool create_file_handler (const char *file_name, uint32_t initial_size); 
static bool remove_file_handler (const char *file_name);
static int open_file_handler (const char *file_name);
static int get_file_size_handler (int fd);
static int read_from_file_handler (int fd, char *buffer, uint32_t size);
static int write_into_file_handler (int fd, char *buffer, int size);
static void seek_handler (int fd, uint32_t position);
static uint32_t tell_handler (int fd);
static void close_file_handler (int fd);

bool check_for_valid_address (void *pointer);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&file_system_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = (int *)(f->esp);
  int syscall_type = * (int *) esp;

  switch (syscall_type)
    {
    // TODO Parsing arguments and handling memory accessing
    case SYS_HALT:
      {                   /* Halt the operating system. */
        halt_handler ();
        break;
      }
    case SYS_EXIT:                   /* Terminate this process. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int status = *(int *)(esp + 4);
          process_exit_handler (status);
        }
        break;
      }
    case SYS_EXEC:                   /* Start another process. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          char *prog_name = *(int *) (esp + 4);
          f->eax = process_execute_handler (prog_name);
        }
        break;
      }
    case SYS_WAIT:                   /* Wait for a child process to die. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int pid = *(int *)(esp + 4);
          f->eax = process_wait_handler (pid);
        }
        break;
      }
    case SYS_CREATE:                 /* Create a file. */
      {
        if (!check_for_valid_address (esp + 4) || 
                    !check_for_valid_address (esp + 8))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          char *file_name = *(int *)(esp + 4);
          uint32_t initial_size = *(uint32_t *)(esp + 8);
          f->eax = create_file_handler (file_name, initial_size);
        }
        break;
      }
    case SYS_REMOVE:                 /* Delete a file. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          char *file_name = *(int *)(esp + 4);
          f->eax = remove_file_handler (file_name);
        }
        break;
      }
    case SYS_OPEN:                   /* Open a file. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          char *file_name = *(int *)(esp + 4);
          f->eax = open_file_handler (file_name);
        }
        break;
      }
    case SYS_FILESIZE:               /* Obtain a file's size. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int file_handle = *(int *)(esp + 4);
          f->eax = get_file_size_handler (file_handle);
        }
        break;
      }
    case SYS_READ:                   /* Read from a file. */
      {
        if (!check_for_valid_address (esp + 4) || 
                    !check_for_valid_address (esp + 8) ||
                    !check_for_valid_address (esp + 12))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int fd = *(int *)(esp + 4);
          char *buffer = *(int *)(esp + 8);
          uint32_t size = *(int *)(esp + 12);
          f->eax = read_from_file_handler (fd, buffer, size);
        }
        break;
      }
    case SYS_WRITE:                  /* Write to a file. */
      {
        if (!check_for_valid_address (esp + 4) || 
                    !check_for_valid_address (esp + 8) ||
                    !check_for_valid_address (esp + 12))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int fd = *(int *)(esp + 4);
          char* buffer = *(int *)(esp + 8);
          int size = *(int *)(esp + 12);
          f->eax = write_into_file_handler (fd, buffer, size);
        }
        break;
      } 
    case SYS_SEEK:                   /* Change position in a file. */
      {
       if (!check_for_valid_address (esp + 4) || 
                    !check_for_valid_address (esp + 8))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int file_handle = *(int *)(esp + 4);
          uint32_t position = *(uint32_t *)(esp + 8);
          seek_handler (file_handle, position);
        }
        break;
      }
    case SYS_TELL:                   /* Report current position in a file. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int file_handle = *(int *)(esp + 4);
          f->eax = tell_handler (file_handle);
        }
        break;
      }
    case SYS_CLOSE:                  /* Close a file. */
      {
        if (!check_for_valid_address (esp + 4))
        {
          process_exit_handler (EXIT_ERROR);
        }
        else 
        {
          int file_handle = *(int *)(esp + 4);
          close_file_handler (file_handle);
        }
        break;
      }
    }

  // printf ("system call!\n");
  // thread_exit ();
}

bool check_for_valid_address (void *pointer) {
  if (!is_user_vaddr (pointer))
    return false;
  void *addr = pagedir_get_page (thread_current (), pointer);
  if (!addr)
    return false;
  return true;
}

static void
halt_handler (void)
{
  shutdown_power_off ();
}

static void
process_exit_handler (int status)
{
  /* Exit status */
  /* Close all files used by the current thread */
  while (!list_empty (&thread_current ()->file_descriptors))
  {
    struct list_elem *list_itr = list_pop_front (&thread_current ()->file_descriptors);
    struct file_descriptor *fd = list_entry (list_itr, struct file_descriptor, file_elem);
    close_file_handler (fd->file_handle);
  }

  thread_exit ();
}

static pid_t
process_execute_handler (const char *process_name)
{
  // Process name must be added to thread struct
  return process_execute (process_name);
}

static int
process_wait_handler (pid_t pid)
{
  return process_wait (pid);
}

static bool
create_file_handler (const char *file_name, uint32_t initial_size)
{
  lock_acquire (&file_system_lock);
  bool status = filesys_create (file_name, initial_size);
  lock_release (&file_system_lock);
  return status;
}

static bool
remove_file_handler (const char *file_name)
{
  lock_acquire (&file_system_lock);
  bool status = filesys_remove (file_name);
  lock_release (&file_system_lock);
  return status;
}

static int
open_file_handler (const char *file_name)
{
  lock_acquire (&file_system_lock);
  struct file *file = filesys_open (file_name);
  int status = -1;
  if (file != NULL)
  {
    struct file_descriptor *fd = malloc (sizeof (struct file_descriptor));
    file_descriptor_init (fd, file, thread_current ()->fd_counter);
    list_push_back (&thread_current ()->file_descriptors, &fd->file_elem);
    thread_current ()->fd_counter++;
    status = fd->file_handle;
  }
  lock_release (&file_system_lock);
  return status;
}

static int
get_file_size_handler (int fd)
{
  lock_acquire (&file_system_lock);
  struct file *file_pointer = get_file_descriptor (fd)->file_pointer;
  int size = 0;
  if (file_pointer != NULL)
  {
    size = file_length (file_pointer);
  }
  lock_release (&file_system_lock);
  return size;
}

static int
read_from_file_handler (int fd, char *buffer, uint32_t size)
{
  int status = -1;
  if (fd != 0)
  {
    lock_acquire (&file_system_lock);
    struct file *file_pointer = get_file_descriptor (fd)->file_pointer;
    if (file_pointer != NULL) 
    {
      status = file_read (file_pointer, buffer, size);
    }
    lock_release (&file_system_lock);
  }
  else
  {
    for (uint32_t i = 0; i < size; i++)
    {
      buffer[i] = input_getc ();
    }
    status = size;
  }
  return status;
}

static int
write_into_file_handler (int fd, char *buffer, int size)
{
  int status = -1;
  if (fd == 1)
  {
    putbuf(buffer, size);
    status = size;
  }
  else
  {
    lock_acquire (&file_system_lock);
    struct file *file_pointer = get_file_descriptor (fd)->file_pointer;
    if (file_pointer != NULL) 
    {
      status = file_write (file_pointer, buffer, size);
    }
    lock_release (&file_system_lock);
  }
  return status;
}

static void
seek_handler (int fd, uint32_t position)
{
  lock_acquire (&file_system_lock);
  struct file *file_pointer = get_file_descriptor (fd)->file_pointer;
  if (file_pointer)
  {
    file_seek (file_pointer, position);
  }
  lock_release (&file_system_lock);
}

static uint32_t
tell_handler (int fd)
{
  lock_acquire (&file_system_lock);
  struct file *file_pointer = get_file_descriptor (fd)->file_pointer;
  int next_byte_to_read = 0;
  if (file_pointer)
  {
    next_byte_to_read = file_tell (file_pointer);
  }
  lock_release (&file_system_lock);
  return next_byte_to_read;
}

static void
close_file_handler (int fd)
{
  lock_acquire (&file_system_lock);
  struct file_descriptor *file_desc = get_file_descriptor (fd);
  if (file_desc != NULL)
  {
    file_close (file_desc->file_pointer);
    list_remove (&file_desc->file_elem);
    free (file_desc);
  }
  lock_release (&file_system_lock);
}