#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>

typedef int fixed_point_t;
#define FIX 16384
fixed_point_t convert_to_fix(int x);
int convert_to_int(fixed_point_t x);

fixed_point_t add(fixed_point_t x, fixed_point_t y);
fixed_point_t sub(fixed_point_t x, fixed_point_t y);

fixed_point_t mul(fixed_point_t x, fixed_point_t y);

fixed_point_t div(fixed_point_t x, fixed_point_t y);