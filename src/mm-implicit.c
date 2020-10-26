/*
 * mm-explicit.c - The best malloc package EVAR!
 * 
 * TODO (bug): Uh..this is an implicit list???
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

typedef uint64_t word_t;
const size_t ALIGNMENT = 2 * sizeof(word_t);

typedef struct {
    size_t header;
    /*
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    word_t payload[];
} block_t;

static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

static size_t round_up(size_t size, size_t n) {
    return n * ((size + (n-1)) / n);
}

static size_t get_size(block_t *block) {
    return block->header & ~0x7;
}

static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
}

static bool is_allocated(block_t *block) {
    return block->header & 0x1;
}

block_t *find_fit(size_t size) {
    for (block_t *curr = mm_heap_first; mm_heap_last && curr <= mm_heap_last; curr = ((void *)curr + get_size(curr))) {
        size_t curr_size = get_size(curr);
        if (!is_allocated(curr) && curr_size >= size) {
            return curr;
        }
    }
    return NULL;
}


bool mm_init(void) {
    mm_heap_first = mem_sbrk(8);
    set_header(mm_heap_first, 8, true);
    mm_heap_last = NULL;
    return true;
}

void *mm_malloc(size_t size) {
    size_t asize = round_up(size + sizeof(word_t), ALIGNMENT);

    block_t *block = find_fit(asize);

    if (!block) {
        void * ptr = mem_sbrk(asize);
        if (ptr == (void *)-1) {
            return NULL;
        }
        mm_heap_last = (block_t *)ptr;
        block = mm_heap_last;
        set_header(block, asize, true);
    }

    set_header(block, get_size(block), true);
    return block->payload;
}

void mm_free(void *ptr) {
    if (!ptr) {
        return;
    }

    block_t *block = (block_t *)(ptr - offsetof(block_t, payload));
    size_t block_size = get_size(block);
    set_header(block, block_size, false);
}

/*
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 **/
void *mm_realloc(void *old_ptr, size_t size) {
    (void)old_ptr;
    (void)size;
    return NULL;
}


/*
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    (void)nmemb;
    (void)size;
    return NULL;
}

/*
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap() {

}
