#include <string.h>
#include <unistd.h>

typedef struct MallocMetadata
{
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
} MallocMetadata;

#define MAX_SIZE 100000000
#define FAILURE (void *)(-1)
#define META_SIZE sizeof(MallocMetadata)

class MMDBlockList
{
private:
    MallocMetadata *block_list;

public:
    MMDBlockList() : block_list(NULL){};
    MallocMetadata *get_metadata(void *ptr);
    void freeBlock(void *ptr);
    void *allocateBlock(size_t size);
    size_t numFreeBlocks();
    size_t numFreeBytes();
    size_t numTotalBlocks();
    size_t numTotalBytes();
};

// implement block list //

MallocMetadata *MMDBlockList::get_metadata(void *ptr)
{
    return (MallocMetadata *)((char *)ptr - META_SIZE);
}

void *MMDBlockList::allocateBlock(size_t size)
{
    size_t allocation_size = size + sizeof(META_SIZE);
    MallocMetadata *curr_block = block_list;

    while (curr_block != NULL)
    {
        // check for a fitting block
        if (curr_block->is_free && size <= curr_block->size)
        {
            curr_block->is_free = false;
            // if such block is found return it
            return curr_block;
        }
        curr_block = curr_block->next;
    }

    // else create a new block
    void *pb = sbrk(allocation_size);
    if (pb == FAILURE)
    {
        return NULL;
    }

    MallocMetadata *new_block = (MallocMetadata *)pb;
    new_block->size = size;
    new_block->is_free = false;
    new_block->next = NULL;
    new_block->prev = NULL;

    // insert new block:
    MallocMetadata *curr_block = block_list;
    MallocMetadata *prev_block = NULL;
    while (curr_block)
    {
        curr_block = curr_block->next;
        prev_block = curr_block;
    }
    if (prev_block == NULL)
    {
        block_list = new_block;
    }
    else
    {
        prev_block->next = new_block;
        new_block->prev = prev_block;
    }

    return pb;
}

void MMDBlockList::freeBlock(void *ptr)
{
    MallocMetadata *block = get_metadata(ptr);
    block->is_free = true;
}

size_t MMDBlockList::numFreeBlocks()
{
    MallocMetadata *block = block_list;
    size_t count = 0;
    while (block)
    {
        if (block->is_free)
            count++;
        block = block->next;
    }
    return count;
}

size_t MMDBlockList::numFreeBytes()
{
    MallocMetadata *block = block_list;
    size_t free_bytes = 0;
    while (block)
    {
        if (block->is_free)
            free_bytes += block->size;
        block = block->next;
    }
    return free_bytes;
}

size_t MMDBlockList::numTotalBlocks()
{
    MallocMetadata *block = block_list;
    size_t count = 0;
    while (block)
    {
        count++;
        block = block->next;
    }
    return count;
}

size_t MMDBlockList::numTotalBytes()
{
    MallocMetadata *block = block_list;
    size_t free_bytes = 0;
    while (block)
    {
        free_bytes += block->size;
        block = block->next;
    }
    return free_bytes;
}

MMDBlockList blockList = MMDBlockList();

// implement main functions //

size_t _num_free_blocks()
{
    return blockList.numFreeBlocks();
}

size_t _num_free_bytes()
{
    return blockList.numFreeBytes();
}

size_t _num_allocated_blocks()
{
    return blockList.numTotalBlocks();
}

size_t _num_allocated_bytes()
{
    return blockList.numTotalBytes();
}

size_t _num_meta_data_bytes()
{
    return blockList.numTotalBlocks() * META_SIZE;
}

size_t _size_meta_data()
{
    return META_SIZE;
}

void *smalloc(size_t size)
{
    if (size == 0)
    {
        return NULL;
    }
    if (size > MAX_SIZE)
    {
        return NULL;
    }
    void *allocatedBlock = blockList.allocateBlock(size);
    if (allocatedBlock == NULL)
    {
        return NULL;
    }
    else
    {
        return (char *)allocatedBlock + META_SIZE;
    }
}

void *scalloc(size_t num, size_t size)
{
    if (size == 0)
    {
        return NULL;
    }
    if (size > MAX_SIZE)
    {
        return NULL;
    }
    void *ptr = smalloc(num * size);
    if (ptr == NULL)
    {
        return NULL;
    }
    memset(ptr, 0, num * size);
    return ptr;
}

void sfree(void *p)
{
    MallocMetadata *metadata = blockList.get_metadata(p);
    if (p == NULL)
    {
        return;
    }
    if (metadata->is_free == true)
    {
        return;
    }
    blockList.freeBlock(p);
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0)
    {
        return NULL;
    }
    if (size > MAX_SIZE)
    {
        return NULL;
    }

    if (oldp == NULL)
    {
        return smalloc(size);
    }

    MallocMetadata *metadata = blockList.get_metadata(oldp);
    size_t md_size = metadata->size;
    if (size <= md_size)
    {
        return oldp;
    }

    void *ptr = smalloc(size);
    if (ptr == NULL)
    {
        return NULL;
    }
    
    memcpy(ptr, oldp, size);
    sfree(oldp);
    return ptr;
}