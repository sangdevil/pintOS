/* Opens a file and then tries to close it twice.  The second
   close must either fail silently or terminate with exit code
   -1. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  int handle;
  close(0);
  CHECK ((handle = open ("sample.txt")) > 0, "open \"sample.txt\"");
  msg ("close \"sample.txt\"");
  close (handle);

  msg ("close \"sample.txt\" again");
  close (handle);
}
