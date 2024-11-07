/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * scm.c
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "scm.h"

#define MAGIC_NUMBER 0xCAFEBABE
#define METADATA_SIZE 24
#define VM_ADDR 0x600000000000


struct scm {
    int fd;
    void *memory;
    size_t size;
    size_t length;
};

struct scm_metadata {
    size_t magic;
    size_t utilized_size;
};
int invalid_file_size(struct scm *scm);

struct scm *scm_open(const char *pathname, int truncate){
    size_t curr ,page, vm_addr;
    struct scm *scm;
    struct scm_metadata *metadata = malloc(sizeof(struct scm_metadata));
    if (!metadata) {
        TRACE("Error: Could not allocate memory for metadata");
        return NULL;  
    }
    scm = malloc(sizeof(struct scm));
    scm->fd = open(pathname, O_RDWR);
    /*error checking*/
    if (invalid_file_size(scm)){
        TRACE("Error");
        return NULL;
    }
    curr = (size_t) sbrk(0);
    page = page_size();
    vm_addr = ((VM_ADDR/page)*page);
    if(vm_addr<curr){
        TRACE("Error");
        return NULL;
    }
    scm->memory = mmap((void *)vm_addr, scm->length, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, scm->fd, 0);
    if(MAP_FAILED == scm->memory){
        TRACE("Error");
        return NULL;
    }
    
    memcpy(metadata, scm->memory, sizeof(struct scm_metadata));
    printf("scm->size : %lu\n",scm->size );
    printf("metadata->utilized_size : %lu\n",metadata->utilized_size );
    if (metadata->magic != MAGIC_NUMBER || truncate) {
        metadata->magic = MAGIC_NUMBER;
        metadata->utilized_size = 0;  
        memcpy(scm->memory, metadata, sizeof(struct scm_metadata));
    }
    scm->size =  metadata->utilized_size;
    return scm;
}

int invalid_file_size(struct scm *scm){
    struct stat statistics;
    size_t page;
    fstat(scm->fd, &statistics);
    if (S_ISREG(statistics.st_mode)){
        scm->length = statistics.st_size;
        page = page_size();
        scm->length = (scm->length/page)*page;
    }
    else{
        TRACE("Error");
        return 1;
    }
    return (0>=scm->length ? 1 : 0);
}

void *scm_malloc(struct scm *scm, size_t n){
    void *p;
    if (scm->size < sizeof(struct scm_metadata)) {
        scm->size = sizeof(struct scm_metadata);
    }
    if ((scm->size + n)<=scm->length){
        p = (char *)scm->memory + scm->size;
        scm->size+=n;
        return p;
    }
    return NULL;
}

void scm_close(struct scm *scm){
    if(scm->memory && scm->memory != MAP_FAILED){
        
        struct scm_metadata *metadata = (struct scm_metadata *) scm->memory;
        printf("scm->size : %lu\n",scm->size );
        printf("metadata->utilized_size : %lu\n",metadata->utilized_size );
        metadata->utilized_size = scm->size; 
        printf("scm->size : %lu\n",scm->size );
        printf("metadata->utilized_size : %lu\n",metadata->utilized_size );
        memcpy(scm->memory, metadata, sizeof(struct scm_metadata));
        
        if(msync(scm->memory, scm->length, MS_SYNC) == -1 ){
            printf("could not sync");
            TRACE("Error");
            return;

        }
        if (munmap(scm->memory, scm->length) == -1) {
            TRACE("Error: munmap could not unmap memory");
        }
    }
    if(scm->fd){
        close(scm->fd);
    }
    FREE(scm);
}

size_t scm_utilized(const struct scm *scm) {
    return scm->size; 
}

size_t scm_capacity(const struct scm *scm) {
    return scm->length;
}

void *scm_mbase(struct scm *scm) {
    return (void *)((char *)scm->memory + sizeof(struct scm_metadata));
}

char *scm_strdup(struct scm *scm, const char *s){
    size_t len;
    char *new_str;
    if (s == NULL) {
        TRACE("Error: NULL string passed to scm_strdup");
        return NULL;
    }
    len = strlen(s) + 1;  
    if (scm->size + len > scm->length) {
        TRACE("Error: Not enough space in SCM region for scm_strdup");
        return NULL;
    }
    new_str = (char *)((char *)scm->memory + scm->size);
    memcpy(new_str, s, len);
    scm->size += len;
    return new_str;

}

/**
 * Needs:
 *   fstat()
 *   S_ISREG()
 *   open()
 *   close()
 *   sbrk()
 *   mmap()
 *   munmap()
 *   msync()
 */

/* research the above Needed API and design accordingly */
