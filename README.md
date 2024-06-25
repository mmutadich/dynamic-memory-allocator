## Dynamic Memory Allocator
A general-purpose dynamic storage allocator for C programs.

### mm-implicit.c
This implementation uses an implicit free list, which incorporates block splitting and a delayed coalescing approach. In this approach, payloads are coalesced in the `malloc()` function to reduce computational expense, though this may lead to space inefficiency.

### mm-explicit.c
This version employs an explicit linked list for tracking free block payloads, allowing for faster traversal and manipulation of the free list during allocation and deallocation. It utilizes block splitting and a different coalescing approach, where payloads are coalesced in the `free()` function, to optimize space utilization and improve heap scalability and performance.

_Fall 2023_

