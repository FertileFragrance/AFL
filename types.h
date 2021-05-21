/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


/*
   american fuzzy lop - type definitions and minor macros
   ------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>
*/

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

/*
 这些数据类型中都带有_t, _t 表示这些数据类型是通过typedef定义的，而不是新的数据类型。也就是说，
 它们其实是我们已知的类型的别名。
 */

typedef uint8_t u8;  // 就是unsigned char，占1字节
typedef uint16_t u16; // 就是unsigned short int，占2字节
typedef uint32_t u32; // 就是unsigned int，占4字节

/*

   Ugh. There is an unintended compiler / glibc #include glitch caused by
   combining the u64 type an %llu in format strings, necessitating a workaround.

   In essence, the compiler is always looking for 'unsigned long long' for %llu.
   On 32-bit systems, the u64 type (aliased to uint64_t) is expanded to
   'unsigned long long' in <bits/types.h>, so everything checks out.

   But on 64-bit systems, it is #ifdef'ed in the same file as 'unsigned long'.
   Now, it only happens in circumstances where the type happens to have the
   expected bit width, *but* the compiler does not know that... and complains
   about 'unsigned long' being unsafe to pass to %llu.

   啊。有一种意外的编译器glibc包含毛刺，这是由于在格式字符串中组合了u64类型和％llu引起的，因此需要
   一种变通方法。本质上，编译器始终在为％llu寻找“unsigned long long”。在32位系统上，u64类型
   （别名为uint64_t）在<bits/types.h>中扩展为“unsigned long long”，因此所有内容都可以检出。
   但是在64位系统上，ifdef与“unsigned long”存储在同一文件中。现在，它仅在类型恰好具有预期位宽的
   情况下发生，但是编译器不知道...并且抱怨“unsigned long”传递给％llu是不安全的。

 */

#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

typedef int8_t s8;  // 就是signed char
typedef int16_t s16; // 就是signed short int
typedef int32_t s32; // 就是signed int
typedef int64_t s64; // 就是signed long int

#ifndef MIN
#  define MIN(_a, _b) ((_a) > (_b) ? (_b) : (_a))  // 求两者较小
#  define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))  // 求两者较大
#endif /* !MIN */

#define SWAP16(_x) ({ \
    u16 _ret = (_x); \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })  // 将2字节的数按字节翻转

#define SWAP32(_x) ({ \
    u32 _ret = (_x); \
    (u32)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })  // 将4字节的数按字节翻转

#ifdef AFL_LLVM_PASS
#  define AFL_R(x) (random() % (x))
#else
#  define R(x) (random() % (x))
#endif /* ^AFL_LLVM_PASS */

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

#define MEM_BARRIER() \
  __asm__ volatile("" ::: "memory")

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

#endif /* ! _HAVE_TYPES_H */
