#include <criterion/criterion.h>
#include <errno.h>
#include <signal.h>
#include "debug.h"
#include "sfmm.h"
#define TEST_TIMEOUT 15

/*
 * Assert the total number of free blocks of a specified size.
 * If size == 0, then assert the total number of all free blocks.
 */
void assert_free_block_count(size_t size, int count) {
    int cnt = 0;
    for(int i = 0; i < NUM_FREE_LISTS; i++) {
	sf_block *bp = sf_free_list_heads[i].body.links.next;
	while(bp != &sf_free_list_heads[i]) {
	    if(size == 0 || size == (bp->header & ~0x1f))
		cnt++;
	    bp = bp->body.links.next;
	}
    }
    if(size == 0) {
	cr_assert_eq(cnt, count, "Wrong number of free blocks (exp=%d, found=%d)",
		     count, cnt);
    } else {
	cr_assert_eq(cnt, count, "Wrong number of free blocks of size %ld (exp=%d, found=%d)",
		     size, count, cnt);
    }
}

/*
 * Assert that the free list with a specified index has the specified number of
 * blocks in it.
 */
void assert_free_list_size(int index, int size) {
    int cnt = 0;
    sf_block *bp = sf_free_list_heads[index].body.links.next;
    while(bp != &sf_free_list_heads[index]) {
	cnt++;
	bp = bp->body.links.next;
    }
    cr_assert_eq(cnt, size, "Free list %d has wrong number of free blocks (exp=%d, found=%d)",
		 index, size, cnt);
}

Test(sfmm_basecode_suite, malloc_an_int, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz = sizeof(int);
	int *x = sf_malloc(sz);
	cr_assert_not_null(x, "x is NULL!");

	*x = 4;

	cr_assert(*x == 4, "sf_malloc failed to give proper space for an int!"); 	
	//sf_show_heap(); 
	assert_free_block_count(0, 1);
	assert_free_block_count(1952, 1); 

	cr_assert(sf_errno == 0, "sf_errno is not zero!");
	cr_assert(sf_mem_start() + PAGE_SZ == sf_mem_end(), "Allocated more than necessary!");  
	//sf_show_heap();

}

Test(sfmm_basecode_suite, malloc_four_pages, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;

	// We want to allocate up to exactly four pages, so there has to be space
	// for the header and the link pointers.
	void *x = sf_malloc(8092);
	cr_assert_not_null(x, "x is NULL!");
	assert_free_block_count(0, 0);
	cr_assert(sf_errno == 0, "sf_errno is not 0!"); 
	//sf_show_heap(); 

}

Test(sfmm_basecode_suite, malloc_too_large, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	void *x = sf_malloc(100281);

	cr_assert_null(x, "x is not NULL!");
	assert_free_block_count(0, 1);
	assert_free_block_count(100288, 1);
	cr_assert(sf_errno == ENOMEM, "sf_errno is not ENOMEM!");  
	//sf_show_heap(); 

}

Test(sfmm_basecode_suite, free_no_coalesce, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz_x = 8, sz_y = 200, sz_z = 1;
	/* void *x = */ sf_malloc(sz_x);
	void *y = sf_malloc(sz_y);
	/* void *z = */ sf_malloc(sz_z);

	sf_free(y);

	assert_free_block_count(0, 2);
	assert_free_block_count(0, 2);
	assert_free_block_count(224, 1);
	assert_free_block_count(1696, 1); 
	//sf_show_heap(); 

	cr_assert(sf_errno == 0, "sf_errno is not zero!");
}

Test(sfmm_basecode_suite, free_coalesce, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz_w = 8, sz_x = 200, sz_y = 300, sz_z = 4;
	/* void *w = */ sf_malloc(sz_w);
	void *x = sf_malloc(sz_x);
	void *y = sf_malloc(sz_y);
	/* void *z = */ sf_malloc(sz_z);

	sf_free(y);
	sf_free(x);

	assert_free_block_count(0, 2);
	assert_free_block_count(544, 1);
	assert_free_block_count(1376, 1);
	//sf_show_heap(); 

	cr_assert(sf_errno == 0, "sf_errno is not zero!");
}

Test(sfmm_basecode_suite, freelist, .timeout = TEST_TIMEOUT) {
        size_t sz_u = 200, sz_v = 300, sz_w = 200, sz_x = 400, sz_y = 200, sz_z = 500; 
	void *u = sf_malloc(sz_u); 
	/* void *v = */ sf_malloc(sz_v); 
	void *w = sf_malloc(sz_w); 
	/* void *x = */ sf_malloc(sz_x); 
	void *y = sf_malloc(sz_y); 
	/* void *z = */ sf_malloc(sz_z); 


	sf_free(u); 
	sf_free(w); 
	sf_free(y); 
	//sf_show_heap(); 
	assert_free_block_count(0, 4);
	assert_free_block_count(224, 3);
	assert_free_block_count(64, 1);
	// sf_show_blocks(); 
	// sf_show_free_lists(); 
	//sf_show_heap(); 
	// First block in list should be the most recently freed block.
	int i = 4;
	sf_block *bp = sf_free_list_heads[i].body.links.next;
	cr_assert_eq(bp, (char *)y - 8,
		     "Wrong first block in free list %d: (found=%p, exp=%p)",
                     i, bp, (char *)y - 8);
}

Test(sfmm_basecode_suite, realloc_larger_block, .timeout = TEST_TIMEOUT) {
        size_t sz_x = sizeof(int), sz_y = 10, sz_x1 = sizeof(int) * 20;
	void *x = sf_malloc(sz_x); 
	//sf_show_heap(); 
	/* void *y = */ sf_malloc(sz_y); 
	//sf_show_heap(); 
	x = sf_realloc(x, sz_x1);  
	//sf_show_heap(); 
	//sf_show_heap();  
	cr_assert_not_null(x, "x is NULL!");
	sf_block *bp = (sf_block *)((char *)x - 8);
	cr_assert(bp->header & 0x10, "Allocated bit is not set!");
	cr_assert((bp->header & ~0x1f) == 96,
		  "Realloc'ed block size (%ld) not what was expected (%ld)!",
		  bp->header & ~0x1f, 96);

	assert_free_block_count(0, 2);
	assert_free_block_count(32, 1);
	assert_free_block_count(1824, 1); 
	//sf_show_heap();
}

Test(sfmm_basecode_suite, realloc_smaller_block_splinter, .timeout = TEST_TIMEOUT) {
        size_t sz_x = sizeof(int) * 20, sz_y = sizeof(int) * 16;
	void *x = sf_malloc(sz_x);
	void *y = sf_realloc(x, sz_y);

	cr_assert_not_null(y, "y is NULL!");
	cr_assert(x == y, "Payload addresses are different!");

	sf_block *bp = (sf_block *)((char *)y - 8);
	cr_assert(bp->header & 0x10, "Allocated bit is not set!");
	cr_assert((bp->header & ~0x1f) == 96,
		  "Block size (%ld) not what was expected (%ld)!",
		  bp->header & ~0x1f, 96);

	// There should be only one free block.
	assert_free_block_count(0, 1);
	assert_free_block_count(1888, 1); 
	//sf_show_heap(); 
}

Test(sfmm_basecode_suite, realloc_smaller_block_free_block, .timeout = TEST_TIMEOUT) {
        size_t sz_x = sizeof(double) * 8, sz_y = sizeof(int);
	void *x = sf_malloc(sz_x);
	void *y = sf_realloc(x, sz_y);

	cr_assert_not_null(y, "y is NULL!");

	sf_block *bp = (sf_block *)((char *)y - 8);
	cr_assert(bp->header & 0x10, "Allocated bit is not set!");
	cr_assert((bp->header & ~0x1f) == 32,
		  "Realloc'ed block size (%ld) not what was expected (%ld)!",
		  bp->header & ~0x1f, 32);

	// After realloc'ing x, we can return a block of size ADJUSTED_BLOCK_SIZE(sz_x) - ADJUSTED_BLOCK_SIZE(sz_y)
	// to the freelist.  This block will go into the main freelist and be coalesced.
	assert_free_block_count(0, 1);
	assert_free_block_count(1952, 1); 
	//sf_show_heap(); 
}

//############################################
//STUDENT UNIT TESTS SHOULD BE WRITTEN BELOW
//DO NOT DELETE OR MANGLE THESE COMMENTS
//############################################

//Test(sfmm_student_suite, student_test_1, .timeout = TEST_TIMEOUT) {
//} 

Test (sfmm_student_suite, student_test_realloc_size_0, .timeout = TEST_TIMEOUT){ 
	//Will be testing that realloc size of 0 works perfectly fine 
	void* x = sf_malloc(1000); 
	void* y = sf_realloc(x, 0); 

	cr_assert_null(y, "y SHOULD BE NULL");  
	//The freeblock space should be the inital freeblock space which is 1984; 
	assert_free_block_count(1984, 1); 
} 

Test (sfmm_student_suite, student_test_null_free_pointer, .timeout = TEST_TIMEOUT, .signal = SIGABRT){  
	void* invalid_ptr = NULL; 
	sf_free(invalid_ptr); 
}  

Test (sfmm_student_suite, student_test_mem_align_not_power, .timeout = TEST_TIMEOUT){ 
	char* result = sf_memalign(56, 56);  
	cr_assert_null(result, "result SHOULD BE NULL");  
	cr_assert(sf_errno == EINVAL, "SFERRNO SHOULD BE SET TO EINVAL"); 
} 

Test(sfmm_student_suite, student_test_malloc_size_0, .timeout = TEST_TIMEOUT) { 
	void *x = sf_malloc(0);  
	cr_assert_null(x, "X SHOULD BE NULL"); 
	cr_assert(sf_errno != ENOMEM, "SFERRNO SHOULD NOT BE SET TO ENOMEM"); 
} 

Test(sfmm_student_suite, student_test_free_pointer_before_prolouge, .timeout = TEST_TIMEOUT, .signal = SIGABRT){  
	//Intialize the heap with some sf_malloc call
	sf_malloc(48);   
	//Get a pointer before the prolouge
	void* ptr = sf_mem_start() - 64;  
	//Try Freeing This Invalid PTR
	sf_free(ptr); 
} 
Test(sfmm_student_suite, student_test_free_pointer_after_epilouge, .timeout = TEST_TIMEOUT, .signal = SIGABRT){ 
	sf_malloc(3000); 
	void* ptr = sf_mem_end() + 12; 
	sf_free(ptr); 
}  

//Want test cases to test not just these edge cases but also the headers of things, their PAL Bits and etc... 
Test(sfmm_student_suite, student_test_payload_cpy_basic, .timeout = TEST_TIMEOUT){  
	int payload = 4; 
	int * pp = sf_malloc(32);  
	*pp = payload;  
	int * new_pp = sf_realloc(pp, 1000);  
	cr_assert(*new_pp = 4, "PAYLOAD WAS NOT COPIED OVER PROPERLY WHEN REALLOCING LARGER");  
	assert_free_block_count(0, 2);   
}   
Test(sfmm_student_suite, student_test_header_basic, .timeout = TEST_TIMEOUT){
	int * pp = sf_malloc(120);   
	size_t actual_size = 128; 
	size_t actual_alloc_bit = 1; 
	size_t previous_alloc_bit = 1; 
	sf_block* pp_header = (sf_block*)((char*)pp -8); 
	size_t pp_header_size = pp_header->header & ~0X1F;  
	size_t given_alloc_bit = ((pp_header->header & 0x10) >> 4); 
	size_t given_prev_alloc_bit = ((pp_header->header & 0x8) >> 3); 
	cr_assert(pp_header_size == actual_size, "The Header Size was not the expected value of 128");  
	cr_assert(given_alloc_bit == actual_alloc_bit, "The Curr_Alloc bit was not set correctly"); 
	cr_assert(previous_alloc_bit == given_prev_alloc_bit, "The Prev_Alloc bit was not set correctly"); 
} 
Test(sfmm_student_suite, student_test_realloc_hdr_basic, .timeout = TEST_TIMEOUT){ 
	int payload = 4; 
	int * pp = sf_malloc(32);  
	*pp = payload;  
	int * new_pp = sf_realloc(pp, 1000); 
	size_t actual_size = 1024; 
	size_t actual_alloc_bit = 1; 
	size_t previous_alloc_bit = 0;  
	sf_block* pp_header = (sf_block*)((char*)new_pp-8); 
	size_t pp_header_size = pp_header->header & ~0X1F;  
	size_t given_alloc_bit = ((pp_header->header & 0x10) >> 4); 
	size_t given_prev_alloc_bit = ((pp_header->header & 0x8) >> 3); 
	cr_assert(pp_header_size == actual_size, "The Header Size was not the expected value of 1024");  
	cr_assert(given_alloc_bit == actual_alloc_bit, "The Curr_Alloc bit was not set correctly"); 
	cr_assert(previous_alloc_bit == given_prev_alloc_bit, "The Prev_Alloc bit was not set correctly");  
	cr_assert(pp_header->body.payload[0] == payload, "PAYLOAD WAS NOT COPIED CORRECTLY"); 
}  
Test(sfmm_student_suite, student_test_memalign_test1, .timeout = TEST_TIMEOUT){ 
	//Simple test just to see if the pointer returned is properly what it needs to be... 
	void * pp1 = sf_memalign(64, 256);  
	void * pp2 = sf_memalign(64, 128); 
	void * pp3 = sf_memalign(64, 64); 
	void * pp4 = sf_memalign(64, 32);  
	int aligned1 = ((uintptr_t)pp1 % 256);  
	int aligned2 = ((uintptr_t)pp2 % 128); 
	int aligned3 = ((uintptr_t)pp3 % 64);  
	int aligned4 = ((uintptr_t)pp4 % 32); 
	cr_assert(aligned1 == 0, "POINTER RETURNED IS NOT ALIGNED ON 256"); 
	cr_assert(aligned2 == 0, "POINTER RETURNED IS NOT ALIGNED ON 128");  
	cr_assert(aligned3 == 0, "POINTER RETURNED IS NOT ALIGNED ON 64"); 
	cr_assert(aligned4 == 0, "POINTER RETURNED IS NOT ALIGNED ON 32"); 
}
