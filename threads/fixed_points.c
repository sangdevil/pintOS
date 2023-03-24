#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/fixed_points.h"

typedef int fixed_point_t;
#define FIX 16384
fixed_point_t convert_to_fix(int x) {
    return x * FIX;
}

int convert_to_int(fixed_point_t x) {
    if (x >= 0) {
        return (x + FIX / 2) / FIX;
    } else {
        return (x - FIX / 2) / FIX;
    }
}

fixed_point_t add(fixed_point_t x, fixed_point_t y){
    return x + y;
}
// 여기에 쓰고 있는데, 이거 보면 카톡으로 말해줘 
// 페이커 짱짱맨 쵸비 짱짱맨 제카 짱짱껄
fixed_point_t sub(fixed_point_t x, fixed_point_t y) {
    return x - y;
}

fixed_point_t mul(fixed_point_t x, fixed_point_t y) {
    long long prod = (long long) x * y;
    // if (prod > INT32_MAX || prod < INT32_MIN) {
    //     // Handle overflow error
    //     return ERROR_CODE;
    // }
    //ASSERT(prod / FIX < 1LL<<31);
    return prod / FIX;
}

fixed_point_t div(fixed_point_t x, fixed_point_t y) {
    long long prod = (long long) x * FIX;
    // if (prod > INT32_MAX || prod < INT32_MIN) {
    //     // Handle overflow error
    //     return ERROR_CODE;
    // }
    return prod / y;
}