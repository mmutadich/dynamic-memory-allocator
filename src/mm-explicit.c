/*
 * mm-explicit.c - The best malloc package EVAR!
 *
 * TODO (bug): Uh..this is an implicit list???
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;


typedef struct node{
    size_t header;
    struct node *next;
    struct node *prev;
} free_block_t;


/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;
static free_block_t *free_list_start = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}


free_block_t *list_node_init(block_t *block) {
    free_block_t *node = (free_block_t *)block;
    node->header = block->header;
    node->prev = NULL;
    node->next = NULL;
    return node;
    //sus that I never set the footer....
}

static void add_to_front(free_block_t *block) {
    if (free_list_start == NULL){
        block->prev = NULL;
        block->next = NULL;
    } else {
        block->prev = NULL;
        free_list_start->prev = block;
        block->next = free_list_start;
    }
    free_list_start = block;
}

/*
static void free_block(free_block_t *node){
    free(node->prev);
    free(node->next);
}
*/
static void remove_from_list(free_block_t *block) {
    if (block == NULL){
        return;
    }
    if (block == free_list_start && block->next == NULL){
        //free_block(block);
        free_list_start = NULL;
    } else if ( block == free_list_start){
        free_list_start = block->next;
        free_list_start->prev = NULL;
        //free_block(block);
    } else {
        free_block_t *before = block->prev;
        free_block_t *after = block->next;
        before->next = after;
        after->prev = before;
        //free_block(block);
    }
}

static size_t *get_footer(block_t *block, size_t size) {
    size_t *footer = (size_t *) ((uint8_t *) block + size - sizeof(size_t));
    return footer;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/*
static block_t *get_backward(block_t *block){
    size_t *prev_footer = (size_t *) ((uint8_t *) block - sizeof(size_t));
    size_t size = (*(prev_footer)) & ~1;
    block_t *prev_block = (block_t *) ((uint8_t *) block - size);
    return prev_block
}

static block_t *get_forward(block_t *block){
    block_t *next_block = (block_t *) ((uint8_t *) block + get_size(block));
    return next_block
}
*/

/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
    size_t *footer = get_footer(block, size);
    *(footer) = size | is_allocated;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static free_block_t *find_fit(size_t size) {
    // Traverse the blocks in free list
    free_block_t *curr = free_list_start;
    while ( curr != NULL){
        if (!is_allocated((block_t *)curr) && get_size((block_t *)curr) >= size) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size + sizeof(size_t), ALIGNMENT);

    // If there is a large enough free block, use it
    free_block_t *block = find_fit(size);
    if (block != NULL) {
        /*
        if (get_size(block) > (size + sizeof(block_t) + sizeof(size_t))) {
            block_t *hm_block = block_splitting(block, size);
            return hm_block->payload;
        }
        */
        block_t *allocated = (block_t *)block;
        set_header(allocated, get_size(allocated), true);
        remove_from_list(block);
        return allocated->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block_t *new_block = mem_sbrk(size);
    if (new_block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = new_block;
    }
    mm_heap_last = new_block;

    // Initialize the block with the allocated size
    set_header(new_block, size, true);
    return new_block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    // make a free_block and add it to the linked list
    free_block_t *node = list_node_init(block);
    set_header((block_t *)node, get_size((block_t *)node), false);
    add_to_front(node);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        return mm_malloc(size);
    }
    if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }
    if (old_ptr != NULL) {
        uint8_t *payload = mm_malloc(size);
        size_t amount = get_size(block_from_payload(old_ptr));
        if (size < get_size(block_from_payload(old_ptr))) {
            amount = size;
        }
        memcpy(payload, old_ptr, amount);
        mm_free(old_ptr);
        return payload;
    }
    return NULL;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    uint8_t *payload = mm_malloc(size * nmemb);
    memset(payload, 0, size * nmemb);
    return payload;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    size_t free_blocks = 0; 
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        if (!is_allocated(curr)){
            free_blocks +=  1;
        }
        size_t *footer = get_footer(curr, get_size(curr));
        if (*(footer) != curr->header) {
            printf("\nFOOTER NOT EQUAL TO HEADER");
        }
    }
    printf("\n%ld", free_blocks);
    free_block_t *curr = free_list_start;
    if (free_list_start != NULL){
        size_t counter = 1;
        while ( curr->next != NULL){
            curr = curr->next;
            counter += 1;
        }
        if (free_blocks != counter){
            printf("\nNot all free blocks in list");
        }
        counter -= 1;
        while ( curr->prev != NULL){
            curr = curr->prev;
            counter -= 1;
        }
        if (counter != 0){
            printf("Can't traverse list forwards and backwards");
        }
    }
}