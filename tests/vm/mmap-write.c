/* Writes to a file through a mapping, and unmaps the file,
   then reads the data in the file back using the read system
   call to verify. */

#include <string.h>
#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

#define ACTUAL ((void *) 0x10000000)

void
test_main (void)
{
  int handle;
  void *map;
  char buf[1024];

  /* Write file via mmap. */
  CHECK (create ("sample.txt", strlen (sample)), "create \"sample.txt\"");
  CHECK ((handle = open ("sample.txt")) > 1, "open \"sample.txt\"");
  CHECK ((map = mmap (ACTUAL, 4096, 1, handle, 0)) != MAP_FAILED, "mmap \"sample.txt\"");
  memcpy (ACTUAL, sample, strlen (sample));
  // msg("map address : %p", map);
  munmap (map);
  
  /* Read back via read(). */
  read (handle, buf, strlen (sample));
  // msg("sample : %s", sample);
  // msg("s : %s", buf);
  CHECK (!memcmp (buf, sample, strlen (sample)),
         "compare read data against written data");
  close (handle);
}
