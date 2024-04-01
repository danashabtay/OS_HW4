#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

typedef struct MallocMetadata
{
    size_t size;
    bool is_free;
    bool is_mmaped; // New field to differentiate mmaped blocks
    MallocMetadata *next;
    MallocMetadata *prev;
} MallocMetadata;

#define MAX_SIZE 100000000
#define FAILURE (void *)(-1)
#define META_SIZE sizeof(MallocMetadata)
#define BLOCK_SIZE (128 * 1024) // 128KB
#define INITIAL_BLOCKS 32
#define MAX_ORDER 10 // Maximum order of free block (128KB)

class MMDBlockList
{
public:
    MallocMetadata *block_list;
    MallocMetadata *mmap_list; // List for mmaped blocks
    MMDBlockList();
    MallocMetadata *get_metadata(void *ptr);
    void freeBlock(void *ptr);
    void *allocateBlock(size_t size);
    void mergeBuddyBlocks(MallocMetadata *metadata);
    size_t numFreeBlocks();
    size_t numFreeBytes();
    size_t numTotalBlocks();
    size_t numTotalBytes();
};

MMDBlockList *arr[MAX_ORDER];

// implement block list //

void MMDBlockList::mergeBuddyBlocks(MallocMetadata *metadata)
{
    size_t block_size = metadata->size + META_SIZE;
    int order = 0;
    while ((1 << order) * BLOCK_SIZE < block_size)
    {
        ++order;
    }

    while (order < MAX_ORDER - 1)
    {
        // Calculate the address of the buddy block
        MallocMetadata *buddy = NULL;
        if ((uintptr_t)metadata % (block_size * 2) == 0)
        {
            // Address is aligned, buddy is to the right
            buddy = (MallocMetadata *)((char *)metadata + block_size);
        }
        else
        {
            // Address is not aligned, buddy is to the left
            buddy = (MallocMetadata *)((char *)metadata - block_size);
        }

        // Check if the buddy block is free
        if (buddy->is_free && buddy->size == metadata->size)
        {
            // Merge the buddy blocks into one large free block
            if (buddy->prev != NULL)
            {
                buddy->prev->next = buddy->next;
            }
            else
            {
                arr[order]->block_list = buddy->next;
            }
            if (buddy->next != NULL)
            {
                buddy->next->prev = buddy->prev;
            }
            metadata->size *= 2;
            block_size *= 2;
            metadata->is_free = true;

            // Move to the next order
            ++order;

            // Return the merged block
            return metadata;
        }
        else
        {
            break; // No more buddy blocks to merge
        }
    }

    return NULL; // No merged block found
}

MallocMetadata *MMDBlockList::get_metadata(void *ptr)
{
    return (MallocMetadata *)((char *)ptr - META_SIZE);
}

void *MMDBlockList::allocateBlock(size_t size)
{
    if (size >= BLOCK_SIZE)
    {
        // Allocate memory using mmap()
        void *mem = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED)
        {
            return NULL;
        }

        // Initialize metadata
        MallocMetadata *metadata = (MallocMetadata *)mem;
        metadata->size = size;
        metadata->is_free = false;
        metadata->is_mmaped = true;             // Mark as mmaped block
        metadata->next = mmap_list->block_list; // Add to mmap list
        metadata->prev = NULL;

        return (char *)mem + META_SIZE;
    }
    else
    {
        // Check if it's the first call to malloc
        static bool first_malloc_call = true;
        if (first_malloc_call)
        {
            // Call sbrk() once for alignment
            sbrk(1); // This call should not affect the statistics functions' results

            // Allocate the initial 32 free blocks of size 128kb and align them
            void *initial_blocks = sbrk(INITIAL_BLOCKS * BLOCK_SIZE);
            if (initial_blocks != FAILURE)
            {
                // Ensure alignment by finding the nearest multiple of 32*128kb
                uintptr_t aligned_address = ((uintptr_t)initial_blocks + (32 * 128 * 1024) - 1) & ~((32 * 128 * 1024) - 1);
                uintptr_t offset = aligned_address - (uintptr_t)initial_blocks;

                // Initialize metadata for each block and add to the free lists
                for (int i = 0; i < INITIAL_BLOCKS; ++i)
                {
                    MallocMetadata *metadata = (MallocMetadata *)((char *)initial_blocks + i * BLOCK_SIZE + offset);
                    metadata->size = BLOCK_SIZE - META_SIZE;
                    metadata->is_free = true;
                    metadata->is_mmaped = false;                     // Not mmaped
                    metadata->next = arr[MAX_ORDER - 1]->block_list; // Add to the list of maximum order
                    metadata->prev = NULL;
                    if (arr[MAX_ORDER - 1]->block_list != NULL)
                        arr[MAX_ORDER - 1]->block_list->prev = metadata;
                    arr[MAX_ORDER - 1]->block_list = metadata;
                }
            }
            first_malloc_call = false;
        }

        // Calculate the order of the block based on its size
        int order = 0;
        size_t block_size = BLOCK_SIZE;
        while (block_size < size + META_SIZE)
        {
            block_size <<= 1; // Double the size
            ++order;
        }

        // Search for a free block in the appropriate order
        for (int i = order; i < MAX_ORDER; ++i)
        {
            MallocMetadata *curr_block = arr[i]->block_list;
            while (curr_block)
            {
                if (curr_block->is_free)
                {
                    // Found a free block, use it
                    curr_block->is_free = false;
                    return (char *)curr_block + META_SIZE;
                }
                curr_block = curr_block->next;
            }
        }

        // No suitable free block found, return NULL
        return NULL;
    }
}

void MMDBlockList::freeBlock(void *ptr)
{
    MallocMetadata *metadata = get_metadata(ptr);
    if (metadata == NULL)
    {
        return;
    }

    if (metadata->is_mmaped)
    {
        // Free memory using munmap()
        munmap(metadata, metadata->size + META_SIZE);
        // Remove from mmap list
        if (metadata->prev != NULL)
        {
            metadata->prev->next = metadata->next;
        }
        else
        {
            mmap_list->block_list = metadata->next;
        }
        if (metadata->next != NULL)
        {
            metadata->next->prev = metadata->prev;
        }
    }
    else
    {
        metadata->is_free = true;
    }
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

MMDBlockList::MMDBlockList()
{
    block_list = NULL;
    mmap_list = new MallocMetadata; // Create mmap list
    mmap_list->next = NULL;
    mmap_list->prev = NULL;
    mmap_list->is_free = false;
    mmap_list->is_mmaped = false;
    mmap_list->size = 0;
}

// Implement main functions //

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

void splitBlockIfNeeded(MallocMetadata *metadata, size_t requested_size)
{
    size_t block_size = metadata->size + META_SIZE;
    int order = 0;
    while ((1 << order) * BLOCK_SIZE < block_size)
    {
        ++order;
    }

    while (order > 0 && block_size >= 2 * (requested_size + META_SIZE))
    {
        // Split the block into two buddies
        block_size >>= 1;
        MallocMetadata *buddy = (MallocMetadata *)((char *)metadata + block_size);
        buddy->size = block_size - META_SIZE;
        buddy->is_free = true;
        buddy->is_mmaped = metadata->is_mmaped; // Set buddy's mmap status
        buddy->prev = metadata;
        buddy->next = metadata->next;
        if (metadata->next != NULL)
        {
            metadata->next->prev = buddy;
        }
        metadata->next = buddy;

        // Update the order
        --order;

        // Update the array of linked lists
        MallocMetadata *prev_ptr = NULL;
        MallocMetadata *curr_ptr = arr[order]->block_list;
        while (curr_ptr && curr_ptr != metadata)
        {
            prev_ptr = curr_ptr;
            curr_ptr = curr_ptr->next;
        }
        if (curr_ptr == metadata)
        {
            if (prev_ptr)
            {
                prev_ptr->next = buddy;
            }
            else
            {
                arr[order]->block_list = buddy;
            }
            buddy->prev = prev_ptr;
            buddy->next = curr_ptr->next;
            if (curr_ptr->next != NULL)
            {
                curr_ptr->next->prev = buddy;
            }
            curr_ptr->next = NULL; // Disconnect the current block from the list
        }

        metadata = buddy;
    }
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

    // Allocate a block if no suitable block is available
    void *allocatedBlock = blockList.allocateBlock(size);
    if (allocatedBlock == NULL)
    {
        return NULL;
    }

    // Check if the allocated block can be split
    MallocMetadata *metadata = blockList.get_metadata(allocatedBlock);
    splitBlockIfNeeded(metadata, size);

    // Return the address of the allocated block
    return (char *)allocatedBlock + META_SIZE;
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
    blockList.mergeBuddyBlocks(metadata);
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0)
    {
        sfree(oldp);
        return NULL;
    }
    if (size > MAX_SIZE)
    {
        return NULL;
    }

    MallocMetadata *metadata = blockList.get_metadata(oldp);
    if (metadata == NULL)
    {
        return NULL;
    }

    if (metadata->size >= size)
    {
        // If the requested size is less than or equal to the current size,
        // return the original pointer.
        return oldp;
    }
    else
    {
        // Attempt to expand the current block.
        // First, allocate a new block with the requested size.
        void *newp = smalloc(size);
        if (newp == NULL)
        {
            // If allocation fails, return NULL.
            return NULL;
        }

        // Copy the data from the old block to the new block.
        memcpy(newp, oldp, metadata->size);

        // Free the old block.
        sfree(oldp);

        // Return the new pointer.
        return newp;
    }
}
