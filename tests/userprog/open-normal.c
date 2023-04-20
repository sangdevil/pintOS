/* Open a file. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
void
test_main (void) 
{
  // 4.3 기준 아예 시작조차 안 됨.
  int handle = open ("sample.txt");
  if (handle < 2)
    fail ("open() returned %d", handle);
}
