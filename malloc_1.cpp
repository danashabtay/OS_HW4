#include <unistd.h>

#define MAX_SIZE 100000000
#define FAILURE (void *)(-1)

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

    intptr_t increment = size;
    void *prev_pb = sbrk(increment);

    if (prev_pb == FAILURE)
    {
        return NULL;
    }

    return prev_pb;
}