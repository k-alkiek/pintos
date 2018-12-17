#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef uint32_t pid_t;

static void syscall_handler (struct intr_frame *);

static void halt_handler (void);
static void process_exit_handler (int status);
static pid_t process_execute_handler (const char *cmd_line);
static int process_wait_handler (pid_t pid);
static bool create_file_handler (const char *file_name, uint32_t initial_size); 
static bool remove_file_handler (const char *file_name);
static int open_file_handler (const char *file_name);
static int get_file_size_handler (int fd);
static int read_from_file_handler (int fd, void *buffer, uint32_t size);
static int write_into_file_handler (int fd, void *buffer, uint32_t size);
static int seek_handler (int fd, uint32_t position);
static uint32_t tell_handler (int fd);
static void close_file_handler (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = (int *)(f->esp);
  int syscall_type = * (int *) esp;

  switch (syscall_type)
    {
    // TODO Parsing arguments and handling memory accessing
    case SYS_HALT:                   /* Halt the operating system. */
      halt_handler ();
      break;
    case SYS_EXIT:                   /* Terminate this process. */
      {
        int status = *(int *)(esp + 4);
        process_exit_handler (status);
        break;
      }
    case SYS_EXEC:                   /* Start another process. */
      break;
    case SYS_WAIT:                   /* Wait for a child process to die. */
      {
        int pid = *(int *)(esp + 4);
        process_wait_handler (pid);
        break;
      }
    case SYS_CREATE:                 /* Create a file. */
      break;
    case SYS_REMOVE:                 /* Delete a file. */
      break;
    case SYS_OPEN:                   /* Open a file. */
      break;
    case SYS_FILESIZE:               /* Obtain a file's size. */
      break;
    case SYS_READ:                   /* Read from a file. */
      break;
    case SYS_WRITE:                  /* Write to a file. */
      ;
      int fd = *(int *)(esp + 4);
      char* buffer = *(int *)(esp + 8);
      int size = *(int *)(esp + 12);

      if (fd == 1)
      {
        putbuf(buffer, size);
      }  
      break;
    case SYS_SEEK:                   /* Change position in a file. */
      break;
    case SYS_TELL:                   /* Report current position in a file. */
      break;
    case SYS_CLOSE:                  /* Close a file. */
      break;
    }

  // printf ("system call!\n");
  thread_exit ();
}

static void
halt_handler (void)
{
  shutdown_power_off ();
}

static void
process_exit_handler (int status)
{

}

static pid_t
process_execute_handler (const char *cmd_line)
{

}

static int
process_wait_handler (pid_t pid)
{
  // Process wait needs to be implemented
  return process_wait (pid);
}

static bool
create_file_handler (const char *file_name, uint32_t initial_size)
{
  // TODO adding synchronization for file system
  return filesys_create (file_name, initial_size);
}

static bool
remove_file_handler (const char *file_name)
{
  // TODO adding synchronization for file system
  return filesys_remove (file_name);
}

static int
open_file_handler (const char *file_name)
{
  return -1;
}

static int
get_file_size_handler (int fd)
{
  return -1;
}

static int
read_from_file_handler (int fd, void *buffer, uint32_t size)
{
  return -1;
}

static int
write_into_file_handler (int fd, void *buffer, uint32_t size)
{
  return -1;
}

static int
seek_handler (int fd, uint32_t position)
{
  return -1;
}

static uint32_t
tell_handler (int fd)
{
  return 0;
}

static void
close_file_handler (int fd)
{

}