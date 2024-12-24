
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "sfmm.h" 
#include <errno.h> 

//Defining Macros That Will Be Useful 
#define HDRFTR_SIZE 8    

//Macros have been Adapted From 9.9.12 of CSAPP Third Edition Figure 9.43
#define PACK(size, alloc, prev_alloc) ((size) | (alloc << 4) | (prev_alloc << 3)) 
#define GET(p) (*(unsigned long*)(p)) 
#define PUT(p, val) (*(unsigned long*)(p)) = (val)
#define GET_SIZE(p) (GET(p) & ~0x1F)
#define GET_ALLOC(p) ((GET(p) & 0x10) >> 4)
#define GET_PREV_ALLOC(p) ((GET(p) & 0x8) >> 3) 
#define MAX(x, y) ((x), > (y) ? (x) : (y) )  

//globals
int flag_initalized = 0; 
int byte_alignment = 0;    

//Editing prev_alloc to 0 is just block->header &= ~0x8 
//Editing prev_alloc to 1 is just block->header |= (1 <<3)  
//Editing curr_alloc is 0 just block->header &= ~0x10 
//Editing curr_alloc to 1 is just block->header |= (1 << 4) 

//The below functions up to PREV_BLK_PTR are ADAPTED FROM CSAPP MACROS 9.9.12 as functions
size_t get_size(sf_block* curr_block_ptr){  
    return (*(unsigned long *)(curr_block_ptr) & ~0x1F);
}   
size_t get_prev_alloc_bit(sf_block* curr_block_ptr){
    return ((curr_block_ptr->header & 0x8) >> 3); 
} 
size_t get_curr_alloc_bit(sf_block* curr_block_ptr){
    return ((curr_block_ptr->header & 0x10) >> 4);
}
size_t pack(int size, int alloc, int prev_alloc){ 
    size_t packed = 0; 
    packed = ((size) | (alloc << 4) | (prev_alloc << 3)); 
    return packed; 
} 
void put(sf_block* curr_ptr, size_t packed_value){ 
    curr_ptr->header = packed_value; 
}
sf_block * sf_get_epilouge(){
    if(byte_alignment == 16){
        return (sf_block *) ((char*)sf_mem_end()-24);
    }else if (byte_alignment == 32){
        return (sf_block *) ((char *)sf_mem_end()-8); 
    } 
    return NULL; 
}  
sf_block * sf_get_prolouge(){
    if(byte_alignment == 16){
        return (sf_block *) ((char*)sf_mem_start() + 8); 
    }else if(byte_alignment == 32){
        return (sf_block *) ((char*)sf_mem_start() + 24); 
    } 
    return NULL; 
}
sf_block * NEXT_BLK_PTR(sf_block* curr_block_ptr){ 
    sf_block * next_ptr = NULL; 
    next_ptr = (sf_block*)((char *)curr_block_ptr + get_size(curr_block_ptr)); 
    return next_ptr; 
}   
sf_block * PREV_BLK_PTR(sf_block* curr_block_ptr){
    sf_block * prev_ptr = NULL; 
    if(GET_PREV_ALLOC(curr_block_ptr) == 1){
        return prev_ptr; 
    }else{   
        sf_block * prev_footer = (sf_block*)((char*)curr_block_ptr - 8); 
        size_t subtracting = get_size(prev_footer);  
        prev_ptr = (sf_block*)((char*)curr_block_ptr - subtracting); 
        //prev_ptr = (sf_block*)(char*)curr_block_ptr - get_size(((sf_block*)(char*)curr_block_ptr - 8));
    } 
    return prev_ptr; 
}

sf_block* remove_from_free_list(sf_block* curr_ptr){ 
    sf_block* previous_node =  curr_ptr->body.links.prev; 
    sf_block* next_node = curr_ptr->body.links.next;   
    previous_node->body.links.next = next_node; 
    next_node->body.links.prev = previous_node;  
    return curr_ptr; 
} 
void add_to_free_list(sf_block *ptr, int index){  
    sf_block * sentinel = &sf_free_list_heads[index]; 
    sf_block * original_head = sentinel->body.links.next; 
    //We change our ptr to point next to orignal head and prev to sentinel 
    ptr->body.links.next = original_head; 
    ptr->body.links.prev = sentinel; 
    original_head->body.links.prev = ptr; 
    sentinel->body.links.next = ptr; 
} 
int determine_free_list_index(size_t size){ 
    size_t scaled_down = size/32; 
    int indx = 0; 
	if(scaled_down == 1){ 
		indx = 0; 
	}else if(scaled_down == 2){ 
		indx = 1; 
	}else if(scaled_down == 3){ 
		indx = 2; 
	}else if(scaled_down > 3 && scaled_down <= 5){ 
		indx = 3; 
	}else if(scaled_down > 5 && scaled_down <= 8){ 
		indx = 4; 
	}else if(scaled_down > 8 && scaled_down <= 13){  
		indx = 5; 
	}else if(scaled_down > 13 && scaled_down <= 21){ 
		indx = 6; 
	}else if(scaled_down > 21){ 
		indx = 7; 
	}
    return indx; 
}
void *initialize(){  
    //So first we call memgrow, which can fail so we want to make sure we handle that case and set the errno
    char* ptr = sf_mem_grow(); 
    if(ptr == NULL){
        return NULL; 
    }   
    //Need to check alignment of the heap at the start, whether it be 16 or 32 byte aligned  
    //If 32 byte aligned increment pointer by 24, 16 we do 8 
    if ((uintptr_t) ptr % 32 == 0){ 
        ptr += 24;  
        byte_alignment = 32; 
    }else if((uintptr_t) ptr % 16 == 0){
        ptr += 8;  
        byte_alignment = 16; 
    } 
    //Now I need to place the prologue for the first time  
    PUT(ptr, PACK(32, 1, 0)); 
    ptr += 32; 
    //Now I want to place the header for the free block 
    PUT(ptr, PACK(1984, 0, 1));     
    //Now I want to place the epilogue for the first time  
    void* epi_ptr = NULL;  
    if(byte_alignment == 16){ 
        epi_ptr = sf_mem_end() - 24; 
    }else if(byte_alignment == 32){ 
        epi_ptr = sf_mem_end() - 8; 
    }
    //void* epi_ptr = sf_mem_end() - 24; 
    PUT(epi_ptr, PACK(0, 1, 0)); 
    void* footer_ptr = epi_ptr - 8; 
    PUT(footer_ptr, PACK(1984, 0, 1));
    //Now I want to do the free lists and initializing them so, that'll set up the sentinel nodes    
    for(int i = 0; i < NUM_FREE_LISTS; i++){ 
        sf_free_list_heads[i].body.links.next = &sf_free_list_heads[i]; 
        sf_free_list_heads[i].body.links.prev = &sf_free_list_heads[i]; 
    }    

    //Now we happily insert our wilderness block!     
    sf_block * first_block = (sf_block*) ptr; 
    sf_free_list_heads[NUM_FREE_LISTS-1].body.links.next = first_block; 
    sf_free_list_heads[NUM_FREE_LISTS-1].body.links.prev = first_block;  
    (*first_block).body.links.prev = &sf_free_list_heads[NUM_FREE_LISTS-1]; 
    (*first_block).body.links.next = &sf_free_list_heads[NUM_FREE_LISTS-1];   

    ptr += 8;  
    //sf_show_heap(); 
    return (void *) ptr;  
} 
//ADAPTED FROM CSAPP FIGURE 9.46 
sf_block *coalesce(sf_block * curr_block){ 
    //Need to handle all 4 cases mentioned in the textbook...  
    size_t curr_block_size = curr_block->header & ~0x1F; 
    sf_block* prev = PREV_BLK_PTR(curr_block); 
    sf_block* next = NEXT_BLK_PTR(curr_block); 
    int prev_status = 0; //Status will be 1 if they are aren't free 
    int next_status = 0; //STatus will be 1 if they are aren't free
    prev_status = (curr_block->header & 0x8) >> 3; 
    next_status = (next->header & 0x10) >> 4; 
    size_t new_size = curr_block_size;    
    if(prev_status && next_status){ 
        //Then curr_block remains curr_block and we keep it as is  
        curr_block = curr_block;  
        sf_block * curr_block_footer = (sf_block*)((char *)curr_block + new_size - 8);  
        curr_block_footer->header = curr_block -> header;  
        sf_block * curr_block_nextHDR = (sf_block*)((char*)curr_block + new_size); 
        curr_block_nextHDR->header &= ~0x8;
    }
    else if(prev_status && !next_status){
        //then we need to coalesce with the next block and edit our header as well as footer 
        //Need to remove next from free_list  
        remove_from_free_list(next); 
        size_t next_size = next->header & ~0x1F; 
        new_size = next_size + curr_block_size;   
        size_t packed = pack(new_size, 0, 1); 
        curr_block->header = packed; 
        sf_block * curr_block_footer = (sf_block *)((char *)curr_block + new_size - 8); 
        curr_block_footer->header = curr_block->header;   
        sf_block * curr_block_nextHDR = (sf_block*)((char*)curr_block + new_size); 
        curr_block_nextHDR->header &= ~0x8;  
    }  
    else if(!prev_status && next_status){ 
	//We need to coalesce to the previous block and then edit the header and footer there 
        remove_from_free_list(prev);  
        size_t prev_size = prev->header & ~0x1F;  
        new_size = prev_size + curr_block_size; 
        int prev_allocated_bit = (prev->header & 0x8) >> 3;  
        size_t packed = pack(new_size, 0, prev_allocated_bit);  
        curr_block = prev;  
        prev->header = packed; 
        sf_block * curr_block_footer = (sf_block *)((char *)curr_block + new_size - 8); 
        curr_block_footer->header = prev->header;  
        sf_block * curr_block_nextHDR = (sf_block*)((char*)curr_block + new_size); 
        curr_block_nextHDR->header &= ~0x8;  
    } 
    else if(!prev_status && !next_status){  
        //debug("BOTH COALESCE NEEDED");  
        remove_from_free_list(prev); 
        remove_from_free_list(next); 
        size_t prev_size = prev->header & ~0x1F; 
        size_t next_size = next->header & ~0x1F;  
        new_size = prev_size + next_size + curr_block_size; 
        int prev_allocated_bit = (prev->header & 0x8) >> 3;  
        size_t packed = pack(new_size, 0, prev_allocated_bit); 
        curr_block = prev; 
        prev->header = packed; 
        sf_block* curr_block_footer = (sf_block *)((char *)curr_block + new_size -8); 
        curr_block_footer->header = prev->header;  
        sf_block * curr_block_nextHDR = (sf_block*)((char*)curr_block + new_size); 
        curr_block_nextHDR->header &= ~0x8;  
    } 
    //curr_block will be the block we are adding... we can first see if it's wilderness or find it's regular index 
    sf_block *final_next = (sf_block*) ((char*)curr_block + new_size); 
    if (final_next == sf_get_epilouge()){ 
        //wilderness so we add to free_list at that spot 
        add_to_free_list(curr_block, NUM_FREE_LISTS-1); 
    }else{  
        //debug("ADDING VIA COALESCE"); 
        int index = determine_free_list_index(new_size); 
        add_to_free_list(curr_block, index); 
    }  
    return curr_block; 
}  
//If the wilderness flag is 0, we know it's not a wilderness block so we'll do regular adding to heap 
//If it is a wilderness block we just keep it in the wilderness_block
sf_block* split_block(sf_block *curr_block, size_t curr_size, size_t actual_size, int wilderness_flag){ 
    size_t new_size_right = curr_size - actual_size;  
    int prev_alloc_bit_left = (curr_block->header & 0x8) >> 3;  
    curr_block->header = actual_size;  
    curr_block->header |= (1 << 4);
    curr_block->header |= (prev_alloc_bit_left << 3); 
    sf_block * right_block_header = (sf_block *)((char*) curr_block + actual_size);  
    right_block_header->header = new_size_right; 
    right_block_header->header |= (0 << 4); 
    right_block_header->header |= (1 << 3);  
    sf_block * right_block_footer = (sf_block*)((char*) right_block_header + new_size_right - 8); 
    right_block_footer->header = right_block_header->header;   
    if(wilderness_flag){
        add_to_free_list(right_block_header, NUM_FREE_LISTS-1); 
    }else{
        int index = determine_free_list_index(new_size_right); 
        add_to_free_list(right_block_header, index); 
    }
    return curr_block; 
} 
  
sf_block* allocate_from_free_list(size_t size, int index){  
    //We start searching through this list and then we return the sf_block   
    sf_block* first_fit_block = NULL; 
    int not_found = 1;  
    int curr_list = index; 
    while(curr_list < 8){   
        sf_block* curr_ptr = sf_free_list_heads[curr_list].body.links.next; 
        size_t curr_size = 0;     
        while(curr_ptr != &sf_free_list_heads[curr_list]){ 
            curr_size = GET_SIZE(curr_ptr); 
            if(curr_size >= size){   
                remove_from_free_list(curr_ptr); 
                not_found = 0;  
                first_fit_block = curr_ptr;   
                if((curr_size - size) % 32 == 0 && curr_size - size != 0){
                    first_fit_block = split_block(curr_ptr, curr_size, size, 0);  
                }else{
                //Just Deal with adjacent block case;  
                    //This should be the next_hdr
                    sf_block* next_hdr = (sf_block*)((char*)curr_ptr + curr_size);     
                    //EDIT THE ALLOCATION BIT (edit_prev_alloc(header/ptr, and then 0 or 1))
                    (next_hdr->header) = next_hdr->header & ~0x8; 
                    next_hdr->header |= (next_hdr->header | (1 << 3));  
                    curr_ptr->header |= (1<<4); 
                    first_fit_block = curr_ptr;  
                    not_found = 0; 
                }
                break;  
            }  
            curr_ptr = curr_ptr->body.links.next;  
        } 
        if(not_found == 0){break;} 
        else{curr_list += 1;}
    } 
    if(not_found == 0){
        return first_fit_block; 
    }     

    //While loop and then return NULL if there's not enough   
    sf_block * curr_ptr = sf_free_list_heads[NUM_FREE_LISTS-1].body.links.next;  
    int sf_mem_grow_needed = 0;  
    if(curr_ptr == &sf_free_list_heads[NUM_FREE_LISTS-1]){ 
        //there is no wilderness block we must SF_Memgrow, otheriwse there is one but we have to check if it's enough  
        sf_mem_grow_needed = 1; 
    }
    if(sf_mem_grow_needed == 0){  
        //We can check the size of the current wilderness block and make sure it's fine 
        size_t curr_size = curr_ptr->header & ~0x1F; 
        if(curr_size < size){ 
            sf_mem_grow_needed = 1; 
        }else{   
            remove_from_free_list(curr_ptr); 
            if((curr_size - size)%32 == 0 && (curr_size - size != 0)){
                first_fit_block = split_block(curr_ptr, curr_size, size, 1);
            }else{ 
                sf_block * next_hdr = (sf_block*)((char*)curr_ptr + curr_size);  
                (next_hdr->header) = next_hdr->header & ~0x08; 
                next_hdr->header |= (next_hdr->header | (1 << 3));  
                curr_ptr->header |= (1<<4); 
                first_fit_block = curr_ptr; 
            }
        }
    }  
    while(sf_mem_grow_needed){  
        //The previous epilouge is our new header  
        sf_block *prev_epilouge = sf_get_epilouge(); 
        char* ptr = sf_mem_grow(); 
        if(ptr == NULL){ 
            return NULL; 
        }    
        sf_block *new_epilouge = sf_get_epilouge(); 
        size_t epilouge_packed = pack(0, 1, 0); 
        new_epilouge->header = epilouge_packed;  
        sf_block *new_footer = (sf_block*)((char*)new_epilouge - 8); 
        int prev_allocated_bit = (prev_epilouge->header & 0x8) >> 3;  
        size_t footer_packed = pack(2048, 0, prev_allocated_bit); 
        prev_epilouge->header = footer_packed;  
        new_footer->header = footer_packed;  
        sf_block *new_header = coalesce(prev_epilouge);  
        size_t new_size = new_header->header & ~0x1F; 
        if(new_size >= size){ 
            remove_from_free_list(new_header); 
            sf_mem_grow_needed = 0; 
            if((new_size- size)%32 == 0 && (new_size - size != 0)){
                first_fit_block = split_block(new_header, new_size, size, 1);
            }else{  
                curr_ptr->header |= (1<<4); 
                sf_block * next_hdr = (sf_block*)((char*)curr_ptr + new_size); 
                (next_hdr->header) = next_hdr->header & ~0x08; 
                next_hdr->header |= (next_hdr->header | (1 << 3)); 
                first_fit_block = new_header;
            }
        }
    }
    return first_fit_block; 
}

void *sf_malloc(size_t size) {   
    
    void * ret_ptr = NULL; 
    if (size == 0){
        return NULL; 
    } 
    if (size < 0){
        sf_errno = ENOMEM; 
        return NULL; 
    }  
    //we can now assume the size is just greater than 0  
    if(flag_initalized == 0){
        ret_ptr = initialize(); 
        if(ret_ptr == NULL){
            sf_errno = ENOMEM;  
            return NULL; 
        }else{ 
            flag_initalized = 1; 
        }
    }  
    size_t adjusted_payload_size = size + 8;   

    if((adjusted_payload_size)%32 == 0){ 
        //DO Nothing, otherwise we need to round up to the next 32 bit mulitple
    }else{
        adjusted_payload_size += (32 - (adjusted_payload_size%32)); 
    }  

    //Now need to find a free_block with this size
    int index = determine_free_list_index(adjusted_payload_size);   
    sf_block* payload_HDR = allocate_from_free_list(adjusted_payload_size, index);
    if(payload_HDR == NULL){
        sf_errno = ENOMEM; 
        return NULL; 
    }else{ 
        return (void *) ((char*)payload_HDR + 8); 
    }  
    return NULL; 
}

void sf_free(void *pp) {
    // To be implemented 
    //Let's first check invalid pointers   
    debug("FREE CRASH:");
    //Is it Null?  
    if(pp == NULL){
        debug("Crash of NULL POINTER"); 
        abort();  
    } 
    //is it 32 aligned? 
    else if((uintptr_t)pp %32 != 0){ 
        debug("CRASH OF 32 ALIGNED");
        abort(); 
    } 
    sf_block* pp_header = (sf_block *)((char*)pp - 8);   
    size_t pp_header_size = pp_header->header & ~0X1F; 
    //is the size of the block less than 32 or not a multiple of 32
    if (pp_header_size < 32){ 
        debug("CRASH OF HEADER_SIZE");
        abort(); 
    }else if (pp_header_size % 32 != 0){ 
        debug("CRASH OF HEADER_SIZE");
        abort(); 
    }   
    sf_block* pp_footer = (sf_block *)((char*)pp + pp_header_size - 8);
    sf_block* curr_epilouge = sf_get_epilouge();
    sf_block* curr_prolouge = sf_get_prolouge();  
    //is the address of the header before our first block (prolouge) or is the footer beyond our last block (epilouge) 
    if((char*)pp_header < (char*)curr_prolouge){  
        debug("CRASH OF pp_header");
        abort(); 
    }else if ((char*)pp_footer > (char*)curr_epilouge){ 
        debug("CRASH OF pp_footer");
        abort(); 
    }  
    int curr_allocated_bit = (pp_header->header & 0x10) >> 4; 
    int prev_allocated_bit = (pp_header->header & 0x8) >> 3; 
    //Is our curr_allocated_bit 0?     
    if(curr_allocated_bit == 0){  
        abort();  
    }
    //is the prev_allocated_bit not matching with our prev_allocated bit... 
    else if(prev_allocated_bit == 0){  
        sf_block* prev_pp_header = PREV_BLK_PTR(pp_header); 
        int prev_pp_allocated_bit = (prev_pp_header->header & 0x10) >> 4;  
        if(prev_pp_allocated_bit != 0){
            abort(); 
        }
    } 
    ////debug("GETS PAST INVALID CHECKS");
    //Now we can call coalesce after just changing the curr_allocated bit! 
    pp_header->header &= ~0x10;   
    //sf_block* pp_nextHDR = (sf_block *)((char*)pp_header + pp_header_size); 
    //pp_nextHDR->header &= ~0x8; 
    coalesce(pp_header); 
}
void *sf_split_realloc(sf_block* curr_block, size_t curr_size, size_t actual_size){
    //This is a version of split for sf_realloc as it'll call coalesce immediately on the split and return the allocated block back
    size_t new_size_right = curr_size - actual_size;  
    int prev_alloc_bit_left = (curr_block->header & 0x8) >> 3;  
    curr_block->header = actual_size;  
    curr_block->header |= (1 << 4);
    curr_block->header |= (prev_alloc_bit_left << 3); 
    sf_block * right_block_header = (sf_block *)((char*) curr_block + actual_size);  
    right_block_header->header = new_size_right; 
    right_block_header->header |= (0 << 4); 
    right_block_header->header |= (1 << 3);  
    sf_block * right_block_footer = (sf_block*)((char*) right_block_header + new_size_right - 8); 
    right_block_footer->header = right_block_header->header;   
    coalesce(right_block_header); 
    return curr_block; 
}
void *sf_realloc(void *pp, size_t rsize) {
    // To be implemented  
    //Time to do the same exact validty checks that we did in sf_free 
    //If pointer is NULL 
    if(pp == NULL){
        sf_errno = EINVAL; 
        return NULL; 
    } 
    //If it's not 32 bit aligned 
    else if((uintptr_t)pp %32 != 0){
        sf_errno = EINVAL;  
        return NULL; 
    }  
    sf_block* pp_header = (sf_block*)((char*)pp - 8); 
    size_t pp_header_size = pp_header->header & ~0X1F;  
    //if the size is not a multiple of 32 bits or it's less than 32
    if(pp_header_size < 32){
        sf_errno = EINVAL;  
        return NULL;  
    }else if(pp_header_size % 32 != 0){
        sf_errno = EINVAL; 
        return NULL; 
    }    
    debug("CRASH HERE!");
    //If the footer is after the epilogue or the header is before the prologue
    sf_block* pp_footer = (sf_block *)((char*)pp + pp_header_size - 8);
    sf_block* curr_epilouge = sf_get_epilouge();
    sf_block* curr_prolouge = sf_get_prolouge();   
    if((char*)pp_header < (char*)curr_prolouge){  
        debug("CRASH OF pp_header");
        sf_errno = EINVAL; 
        return NULL; 
    }else if ((char*)pp_footer > (char*)curr_epilouge){ 
        debug("CRASH OF pp_footer");
        sf_errno = EINVAL; 
        return NULL; 
    }   
    int curr_allocated_bit = (pp_header->header & 0x10) >> 4; 
    int prev_allocated_bit = (pp_header->header & 0x8) >> 3; 
    //Is our curr_allocated_bit 0?     
    if(curr_allocated_bit == 0){  
        sf_errno = EINVAL; 
        return NULL;  
    } 
    //is the prev_allocated_bit not matching with our prev_allocated bit...  
    else if(prev_allocated_bit == 0){ 
        sf_block* prev_pp_header = PREV_BLK_PTR(pp_header); 
        int prev_pp_allocated_bit = (prev_pp_header->header & 0x10) >> 4;   
        if(prev_pp_allocated_bit != 0){
            sf_errno = EINVAL; 
            return NULL; 
        }
    }  
    //Case 1 of user reallocs to 0
    if(rsize == 0){  
        sf_free(pp);
        return NULL; 
    }  
    size_t required_size = rsize + 8;   
    if((required_size)%32 == 0){ 
        //DO Nothing, otherwise we need to round up to the next 32 bit multiple
    }else{
        required_size += (32 - (required_size%32)); 
    } 
    //Case 2 where user reallocs to a larger size
    if(required_size > pp_header_size){   
        debug("ENTERED rsize Greater Case"); 
        //Step 1: Call SF_Malloc to obtain a larger block , if it returns NULL then uhh we return NULL; 
        void * larger_block = sf_malloc(rsize);   
        if(larger_block == NULL){
            return NULL; 
        }    
        //Step 2: Calling Memcpy to copy the data in the block given by the client to the block returned by sf_malloc 
        memcpy(larger_block, pp, pp_header_size-8);   
        //sf_show_block(larger_block); 
        //Step 3: sf_free on the pp block!   
        //sf_show_heap(); 
        sf_free(pp); 
        //Step 4: Return block to client! 
        return larger_block; 
    } 
    if(required_size <= pp_header_size){ 
        size_t difference = pp_header_size - required_size; 
        //Case 3 NO Splitting because it would cause a splinter  
        if(difference < 32){
            return pp; 
        }
        //Case 4 Splitting Required
        else if(difference >= 32){
            //general split function so that I can split into left and right, with left being allocated, right being coalesced... 
            sf_block* new_pp_header = sf_split_realloc(pp_header, pp_header_size, required_size); 
            return (void*) ((char*)new_pp_header + 8); 
        }
    }
    return NULL;
    //abort();
}

void *sf_memalign(size_t size, size_t align) { 
    // To be implemented 
    //Quick Validation Checks   
    //Alignment must at least be 32 bytes
    if(align < 32){ 
        sf_errno = EINVAL; 
        return NULL; 
    }
    //our size must be at least a power of 2
    else if((align & (align - 1)) != 0){ 
        sf_errno = EINVAL; 
        return NULL; 
    } 
    //4 Sizes will be tracked for the 2 cases here, the 2 cases being 
    //1) The ptr is aligned so I just have to worry about splitting the remainder 
    //2) The ptr is not aligned so I have to worry about the 1st blocl 
        /* The size fields associated with each case and their purpose will be the following 
        Allocating Size for our inital call to sf_malloc (both cases) 
        Rounded_up Requested Size for the splitting remainder behavior (split realloc 2nd field size) (must check difference before calling) 
        the 1st_split_block size for the 2nd case, will be used to edit the header and we'll just call free as we edit the curr_allocated bit 
        Aligned Header Size as this is the actual size of the block we got back from sf_Malloc 
        */  
    //First let's get the adjusted size for the malloc 
    size_t allocating_size = size + align + 32 + 8; //No HDR size included since malloc handles that/adds on to that
    void * pp = sf_malloc(allocating_size);  
    if(pp == NULL){
        return NULL; 
    }
    sf_block * pp_header = (sf_block *)((char*)pp - 8);  
    size_t pp_header_size =  pp_header->header & ~0x1F; 
    size_t rounded_size = size + 8; 
    if((rounded_size % 32) == 0){
        //Do Nothing 
    }else{
        rounded_size += (32 - (rounded_size%32));
    }   
    size_t split_size = 0; 
    //Case 1: The Thing is already aligned! 
    if((uintptr_t)pp % align == 0){ 
        // if((curr_size - size) % 32 == 0 && curr_size - size != 0){
        if((pp_header_size - rounded_size)%32 == 0 && (pp_header_size-rounded_size!= 0)){ 
            pp_header = sf_split_realloc(pp_header, pp_header_size, rounded_size);  
        }  
    }else{ 
        //pp_header is our orignal_pp block ptr so we don't have to save pp for freeing we can increment it! 
        while(((uintptr_t)pp % align) != 0){
            pp = (void *)((char *)pp + 32); 
            split_size += 32; 
        } 
        //Now that it is aligned we gotta write our new header with the new size and it should be allocated and prev allocated is 0. 
        size_t new_pp_size = pp_header_size - split_size; 
        size_t new_pp_packed = pack(new_pp_size, 1, 0);  
        //rmbr pp is 8 ahead of it's header spot so we back up eight to get the new header 
        sf_block * new_pp_header = (sf_block*)((char*)pp - 8); 
        new_pp_header->header = new_pp_packed; 
       int prev_alloc_bit_pp_header = get_prev_alloc_bit(pp_header); 
       size_t pp_packed = pack(split_size, 1, prev_alloc_bit_pp_header);  
       pp_header->header = pp_packed; 
       void * pp_header_pointer = (void*)((char*)pp_header + 8); 
       sf_free(pp_header_pointer);  

       //Now we just have to deal with the remaining with sf_split_realloc 
       if((new_pp_size-rounded_size)%32 == 0 && (new_pp_size - rounded_size != 0)){
        new_pp_header = sf_split_realloc(new_pp_header, new_pp_size, rounded_size); 
       }
    } 
    //Case 2: THe thing is not already aligned
    return pp; 
}
