#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

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
    case SYS_HALT:                   /* Halt the operating system. */
      break;
    case SYS_EXIT:                   /* Terminate this process. */
      break;
    case SYS_EXEC:                   /* Start another process. */
      break;
    case SYS_WAIT:                   /* Wait for a child process to die. */
      break;
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
