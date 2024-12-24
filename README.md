![github repo badge: Language](https://img.shields.io/badge/Language-C-181717?color=red) ![github repo badge: Testing](https://img.shields.io/badge/Testing-Criterion-181717?color=orange)
# SF_Malloc
A Dynamic Memory Allocater in C project created for my System Fundamentals II class. We were provided sf_mem_grow serving as a safe wrapper for sbrk, the struct for sf_block and sf_mem_start/sf_mem_end to tell the start/end address of the heap we were creating!

Additonally we we're given sf_show_block, sf_show_free_list, sf_show_free_lists(), sf_show_heap() to aid in visually seeing the heap being created.<br> 

**sf_malloc, sf_realloc, sf_free, and sf_memalign were implemented by me**  

## Design/Features 

SF_Malloc is a segregated free list allocator (hence SF), using seperate free lists for different sizes of blocks to approximate best-fit policy. First-fit policy is used in the placement of a block within each list and the last block is considered a wilderness block, meaning we only place blocks here if no previous list fits! This takes advantage of the "wilderness preservation" heuristic to prevent unnecessary growing of the heap as this block is what's extended per call to sf_mem_grow().    

Using boundary tags with the inclusion of the footer optimization for allocated blocks allows us to immediately and efficiently coalesce adjacent free blocks that were freed from either allocation, reallocation, or free. SF_Malloc splits blocks during allocation without creating splinters by only splitting if the remainder is large enough, allowing us to lessen the amount of internal fragmentation.   

A prolouge and epilouge for the heap was used to prevent edge cases. 

All pointers returned by SF_Malloc are 32 byte aligned, and implemented to handle the edge case of the heap starting as 16 byte-aligned or 32-byte aligned.  

*Note: SF_Malloc is not suitable for use in an actual program and is only meant for learning purposes.* 

## Usage 

SF_Malloc provides the following functions for use:

```c
void *sf_malloc(size_t size);
void *sf_free(void *ptr);
void *sf_realloc(void *ptr, size_t size);
void *sf_memalign(size_t size, size_t align);
```

All the functions above provide the same interface as their counterparts in stdlib.h except sf_memalign as the specified alignment must be a power of 2 where the default alignment of 16 bytes was not sufficient. 

## Building & Testing

SF_Malloc can be built using the provided make files and running ```make clean && make all```. 

The testing framework used was [criterion](https://github.com/Snaipe/Criterion), so this must be installed before attempting to run the tests using ```bin/sfmm_tests```

## Acknowledgements 

A lot of my understanding of malloc and figuring out such an implementation can be attributed to the excellent explanations that can be found in [*Computer Systems: A Programmer's Perspective*](http://csapp.cs.cmu.edu/3e/home.html) by Randal E. Bryant and David R. O'Hallaron

