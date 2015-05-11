/*
 *   bloomindex - Index based on Bloom Filters
 *
 *   Copyright (C) 2015  Gerard Wagener
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>
#include <getopt.h>
#include "hashes.h"

#ifdef DEBUG
    #define DBG(args...) printf(args)
#else
    #define DBG(args...)
#endif

#define BIT_SET(bs, addr) bs[addr>>3] |= 1 << (addr-((addr>>3)<<3))
#define MAGIC "BLIND"
#define MAGIC_LEN 5
#define FILEVERSION 1

#define BLOCK_SIZE 512
#define DOCID_SIZE 40
#define MAXBLOOMFILTERS 1000

#define ERROR_NOSPACE 1
#define ERROR_NOSPACE_L 2
#define ERROR_CANNOT_READ 3

/* Set a bit per hash function in the description of a bloom filter */ 
#define HASH_MODULO 1
#define HASH_MURMUR 2
#define HASH_FNV    4

/* Bloom filter flags */
#define BL_FLAG_LZO 1
#define BL_FP 0.1 // False positive rate of the bloom filter


typedef struct toc_s {
    char docid[DOCID_SIZE];
    char filename[FILENAME_MAX];
    uint64_t offset;
} toc_t;

/* The Index consists of a sequence of bloomfilter */
typedef struct bloomfilter_s {
    uint8_t hashbitset; /* One bit is set per used hash function */
    uint8_t flags; /* Define the encoding of the bloom filter */
    uint32_t size; /* Size of the bloom filter */
    uint8_t docid[40]; /* Document identifier for instance sha1sum */
    uint32_t m; // Number of bytes in the bloomfilter
    uint32_t n; // Number of elements in the bloomfilter
    uint8_t k; // Number of hash functions
} bloomfilter_t;


/* Structure containing the attributes of an index
 * Structure serving as file header an object in memory
 * [UD] execution mode only. The data should be discarded when being
 * loaded from the disk
 */

typedef struct blind_s {
    char magic[5];
    uint8_t version;
    char* filename[FILENAME_MAX]; /* Filename of the index */
    uint8_t* rawmem; // [UD]
    uint8_t* data; /* Pointer below header for quicker access [UD] */
    size_t size; // Size without header
    uint8_t error; /* Error code of blind [UD] */
    uint64_t next_block; // Offset to the next free block
    toc_t toc[MAXBLOOMFILTERS];
    uint32_t tocpos; // Position in the table of content
    int fd; // File descriptor of the index [UD]
} blind_t;

int process_files(blind_t* blind, FILE* stream);
int load_file(blind_t* blind, char* filename);
void process_ngrams(blind_t* blind, uint8_t* buff, size_t sz);


// Returns the offset to the data block
// Returns 0 if no space is avilable
uint64_t get_next_block(blind_t* blind, size_t size)
{
    DBG("Request for a new block of size=%08x. Old pointer is at %08x.\n", (uint32_t)size, (uint32_t)blind->next_block);
    if (blind->next_block+size < blind->size) {
        DBG("New block is at %08x\n", (uint32_t)blind->next_block);
        return blind->next_block+size;
    }
    return 0;
}

/* Iterate through the file list and index them
 * Returns 1 on success
 * Returns 0 on error
 */
int process_files(blind_t* blind, FILE* stream)
{
    char *filename=NULL;
    size_t sz = 0;
    int read;
    int cnt = 0;
    while ((read=getline(&filename, &sz, stream)) != -1){
        if (read > 1) {
            cnt++;
            if (cnt >= MAXBLOOMFILTERS) {
                fprintf(stderr,"[ERROR] Cannot store bloomfilter max amount is reached\n");
                blind->error = ERROR_NOSPACE;
                return 0;
            }
            filename[read-1] = 0;
            // Store filename in table of content
            strncpy((char*)&blind->toc[blind->tocpos].filename, filename,  FILENAME_MAX);
            blind->tocpos++;
            if (!load_file(blind, filename)) {
                free(filename);
                return 0;
            }
            free(filename);
            filename = NULL;    
        }
    }
    return 1;
}

/* Load filename and index the content.
 * Returns 0 on error and 1 on success and set blind->error code
 */
int load_file(blind_t* blind, char* filename)
{
    int fd;
    uint8_t* content;
    struct stat st;
    uint32_t m; // Number of bits in the bloom filter
    uint32_t mb; // Number of bytes
    int32_t k; // Number of hash functions
    int32_t n; // Number of elements in the bloom filter
    uint64_t ofs;
    uint8_t* ptr;
    bloomfilter_t *bloom;
    if (stat(filename,&st) != -1) {
        if (S_ISREG(st.st_mode)){
            //FIXME Do  not process empty files
            printf("Processing %s\n", filename);
            fd = open(filename, O_RDONLY);
            if (fd != -1) {
                content = mmap(NULL,st.st_size, PROT_READ, MAP_PRIVATE,fd,0);
                if (content == MAP_FAILED) {
                    fprintf(stderr, "[ERROR] Cannot read filename %s. Cause=%s\n",
                            filename, strerror(errno));
                    close(fd);
                    blind->error = ERROR_CANNOT_READ;
                    return 0;
                }
                /*  Compute parameters of the bloomfilter  */
                n = st.st_size / sizeof(uint32_t)+1;
                m = ceil((n * log((float)BL_FP)) / log((float)1.0 / (pow((float)2.0, log((float)2.0)))));
                mb = m / 8 + 2; // 1 For alignment and 1 for next byte
                k = round(log((float)2.0) * (float)m / (float)n);

                DBG("File size: %ld\n",st.st_size);
                DBG("Configured false positive rate: %f\n",BL_FP);
                DBG("Number of elements for the bloomfilter: %d\n",n);
                DBG("Number of bits for the bloomfilter: %d\n",m);
                DBG("Number of bytes for the bloomfilter: 0x%08x\n",mb);
                DBG("Number of hash functions: %d\n",k);
                ofs = get_next_block(blind, mb+sizeof(bloomfilter_t));
                if (ofs > 0) {
                    DBG("Bloomfilter for filename %s is at offset %08x\n",
                        filename, (uint32_t)blind->next_block);
                    blind->toc[blind->tocpos].offset = ofs;
                    //Store bloom filter settings in the bloomfilter header
                    ptr = blind->data+blind->next_block;
                    bloom = (bloomfilter_t*)ptr;
                    DBG("Store bloom filter settings at addresses %p (offset=%08x)\n", ptr, (uint32_t)(ptr-(uint8_t*)blind->data));
                    bloom->m = m;
                    bloom->n = n;
                    bloom->k = k;
                    process_ngrams(blind, content, st.st_size);
                    blind->next_block = ofs;
                    DBG("Next free block is at %08x\n", (uint32_t)blind->next_block);
                }else{
                    fprintf(stderr, 
                    "[ERROR] Cannot store bloom filter for filename %s\n",
                            filename);
                    blind->error = ERROR_NOSPACE_L;
                    return 0;
                }
                munmap(content, st.st_size);
                close(fd);
            }
        }
    }
    return 1;
}

//Returns 1 if the ngram was found
//Returns 0 otherwise
int validate_fp(char* filename, uint32_t ngram)
{
    int fd;
    uint8_t* content;
    struct stat st;
    uint64_t i;
    uint32_t* x;
    int ret = 0;

    if (stat(filename,&st) != -1) {
        if (S_ISREG(st.st_mode)){
            fd = open(filename, O_RDONLY);
            if (fd != -1) {
                content = mmap(NULL,st.st_size, PROT_READ, MAP_PRIVATE,fd,0);
                if (content == MAP_FAILED) {
                    fprintf(stderr, "[ERROR] Cannot read filename %s. Cause=%s\n",
                            filename, strerror(errno));
                    close(fd);
                    ret = 1;
                }
                //FIXME Handle trailing bytes that do not fit in an ngram
                for (i=0; i<st.st_size; i+=sizeof(uint32_t)) {
                    x = (uint32_t*)(content+i);
                    if (*x == ngram) {
                        ret = 1;
                        break;
                    }
                }
                munmap(content, st.st_size);
                close(fd);
            }
        }
    }
    return ret;
}


void process_ngrams(blind_t* blind, uint8_t* buff, size_t sz)
{
    uint32_t *ngram;
    uint64_t i;
    bloomfilter_t* bloom;
    uint32_t mh;
    uint32_t crc;
    uint32_t nmh;
    uint32_t ncrc;
    uint8_t* memory;
    uint32_t rw; // Normalize the raw value
    bloom = (bloomfilter_t*)blind->data;
    memory = blind->data + blind->next_block+sizeof(bloomfilter_t);
    DBG("Size of bloomfilter_t %08x\n", (uint32_t)sizeof(bloomfilter_t));
    DBG("Bloom filter memory is at address %p (offset = %08x)\n",
        memory, (uint32_t)(memory-blind->data));
    #ifdef DATA_DEBUG
    DBG("Ngram|Murmur Hash|Norm MH|CRC|Norm CRC|Norm ngram|Size\n");
    #endif
    for (i=0; i<sz; i+=sizeof(uint32_t)) {
        //FIXME Handle the last 3,2,1 grams
        if (i < sz - sizeof(uint32_t)){
            ngram = (uint32_t*)(buff+i);
            //FIXME create an array of hash functions
            //TODO sha sum hashes
            //TODO Record which hashes are used
            mh = murmur3_32_uint32(*ngram);
            nmh = normalize32(mh, bloom->m);
            crc = crc32_uint32(*ngram);
            ncrc = normalize32(crc, bloom->m);
            rw = normalize32(*ngram, bloom->m);
            #ifdef DATA_DEBUG
            DBG("%08x|%08x|%08x|%08x|%08x|%08x|%08x\n",*ngram, mh,nmh,crc,
                ncrc, rw, bloom->m/8);
            #endif
            BIT_SET(memory, nmh);
            BIT_SET(memory, ncrc);
            BIT_SET(memory, rw);
        }
    }
}

blind_t *create_new_blind(char* filename, size_t size) {
    blind_t* out;
    char ch;
    out = calloc(1,sizeof(blind_t));
    if (out == NULL) {
        fprintf(stderr, "[ERROR] Memory cannot be allocated. Num bytes:%ld\n",
                sizeof(blind_t));
    }
    // Fill the fields also needed for the file system version
    strncpy((char*)&out->magic, MAGIC,MAGIC_LEN);
    out->version = FILEVERSION;
    strncpy((char*)&out->filename, filename, FILENAME_MAX);
    out->fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (out->fd == -1 ) {
        fprintf(stderr,"[ERROR] Failed to open file %s. Cause=%s\n", filename,
                        strerror(errno));
        free(out);
        return NULL;
    }
    // FIXME What happens if an existing index is overwritten is the old data
    // taken into account?
    DBG("Initializing new index ...\n");
    if (lseek(out->fd, size-1, SEEK_SET) != -1) {
        // Write a NULL byte at the end to get the file streched
        ch = 0;
        // FIXME rewrite error handling
        write(out->fd,&ch,1);
    } else {
        fprintf(stderr,"[ERROR] Seek failed. Cause=%s\n",strerror(errno));
        close(out->fd);
        free(out);
       return NULL;
   }

    out->rawmem =  mmap(NULL,size, PROT_READ | PROT_WRITE, MAP_SHARED,out->fd,0);
    if (out->rawmem == MAP_FAILED) {
        fprintf(stderr,"[ERROR] Failed to mmap index. Cause=%s.\n",strerror(errno));
        close(out->fd);
        free(out);
        return NULL;
    }
    DBG("Init. Address of memory block:%p\n", out->rawmem);
    DBG("Init. End of memory block:%p\n", out->rawmem + size);
    DBG("Init. Size of blind_t header: %08x\n",(unsigned int)sizeof(blind_t));
    if (out->rawmem == NULL) {
        fprintf(stderr, "[ERROR] Could not allocate memory chunk. Num bytes:%ld\n",
                        sizeof(blind_t));
        free(out);
        return NULL;
    }
    // All went fine
    out->size=size-sizeof(blind_t);
    DBG("Init. Size available for data:%ld\n", out->size);
    out->next_block = 0;
    out->data = out->rawmem + sizeof(blind_t);
    DBG("Init. Address of the data segment: %p (offset=%08x)\n",out->data,
        (uint32_t)(out->data-out->rawmem));
    DBG("Init. Size of memory block:%ld\n", size);
    //Memory chunks are filled from the bottom to the top
    DBG("Init. Offset to next block:%ld\n", out->next_block);
    /* Memory chunks directory is listed at the end of the file */
    return out;
}

int usage(int exit_code) {
    printf("Usage: blind [-h] [[-c] [-s size]] [[-f file list] [-i index file]] [-q ngram] [-b list of ngrams]\n");
    printf("Iterate through a file list and index 4-grams in an  index file\n");
    printf("\nArguments\n");
    printf("    -h, --help      Shows this screen\n");
    printf("    -s, --size      Specify the size of the index file that is created\n");
    printf("    -c, --create    Create the index file\n");
    printf("    -f, --filelist  File list that is iterated through and indexed.\n");
    printf("    -i, --indexfile Filename of the index\n");
    printf("    -q, --query     ngram\n");
    printf("    -b, --bulk      Bulk query of list of ngrams\n");
    printf("    -a, --ascii     Dump index in ascii to be human readable\n");
    exit(exit_code);
}

int create_new_index(char* indexfile, uint64_t size, FILE* fp)
{
    blind_t *blind;

    blind = create_new_blind(indexfile, size);
    if (blind) {
        printf("[INFO] Create new indexfile: %s\n", indexfile);
        printf("[INFO] Size of the indexfile: %ld\n", size);
        printf("[INFO] Maximum bloom filters %d\n", MAXBLOOMFILTERS);
        printf("[INFO] Maximal file size :%d\n", FILENAME_MAX);
        printf("[INFO] Waiting for filenames on stdin\n");
        //TODO handle error codes
        process_files(blind, fp);
        memcpy((char*)blind->rawmem, blind, sizeof(blind_t));
        //Sync the file
        munmap(blind->rawmem, blind->size);
        close(blind->fd);
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

uint8_t test_bit(uint8_t* bs, uint32_t addr)
{
    #ifdef DATA_DEBUG
    DBG("addr: %08x\n",addr);
    DBG("addr>>3: %08x\n",addr>>3);
    DBG("(1 << (addr-((addr>>3)<<3))): %08x\n",(1 << (addr-((addr>>3)<<3))));
    #endif
    return bs[addr>>3] & (1 << (addr-((addr>>3)<<3)));
}

/* Check the header of an index file
 * Returns 1 on success
 * Returns 0 on error
 */
int check_header(blind_t* t)
{
    //TODO Implement me
    return 1;
}
blind_t* load_index(char* indexfile)
{
    blind_t* blind;
    blind_t* shadow;
    uint8_t* ptr;
    int fd;
    struct stat st;
    blind = calloc(sizeof(blind_t),1);
    if (!blind)
        return NULL;

    fd = open(indexfile, O_RDONLY);
    if (fd != -1) {
        blind->rawmem = mmap(NULL,st.st_size, PROT_READ, MAP_PRIVATE,fd,0);
        shadow = (blind_t*)blind->rawmem;
        if (stat(indexfile,&st) != -1) {
                blind->rawmem = mmap(NULL,st.st_size, PROT_READ, MAP_PRIVATE,
                                     fd,0);
                if (blind->rawmem != MAP_FAILED){
                    if (check_header(blind)) {
                        ptr = blind->rawmem;
                        memcpy(blind, shadow, sizeof(blind_t));
                        blind->rawmem = ptr;
                        //TODO Scrub old dynamic fields
                        DBG("Identified %d samples\n", shadow->tocpos);
                        blind->data = blind->rawmem + sizeof(blind_t);
                        blind->fd = fd;
                        return blind;
                    }
                }else {
                    fprintf(stderr, "[ERROR] Mmap failed. Cause=%s\n",
                                                             strerror(errno));
                }
        }else{
            fprintf(stderr,"[ERROR] Cannot stat indexfile %s. Cause %s\n",
                            indexfile, strerror(errno));
        }
    } else {
        fprintf(stderr, "[ERROR] Cannot load index file %s. Cause=%s\n",
                indexfile, strerror(errno));
    }
    // Something went wrong, Cleanup the mess
    if (blind)
        if (blind->fd)
            close(blind->fd);
        free(blind);
    return NULL;
}


void dump_toc(blind_t* blind)
{
    int i;
    printf("#Filename|Offset\n");
    for (i=0; i<blind->tocpos; i++) {
        printf("%s|%08x\n", blind->toc[i].filename,
                    (uint32_t)blind->toc[i].offset);
    }
}

/* Returns a number >0  if the ngram is probaby in bloomfilter
 * Returns 0 otherwise
 */
uint8_t query_index(blind_t *blind, uint32_t ngram)
{
    int i;
    uint8_t* memory;
    bloomfilter_t* bloom;
    uint32_t mh;
    uint32_t nmh;
    uint32_t crc;
    uint32_t ncrc;
    uint32_t rw;
    uint8_t hmh;
    uint8_t hcrc;
    uint8_t hrw;
    int8_t un;
    DBG("Data is at offset %p\n",blind->data);
    DBG("Querying index for ngram %04x\n", ngram);
    DBG("Number of files encoded in the index %d\n", blind->tocpos);
    for (i=0; i<blind->tocpos; i++) {
        DBG("Encountered filename %s @ offset %08x\n", blind->toc[i].filename,
            (int)blind->toc[i].offset);
        //FIXME check if strings are valid
        bloom = (bloomfilter_t*)(blind->data+blind->toc[i].offset);
        DBG("Corresponding bloom filter is at address %p (Offset=%08x).\n",
            bloom, (uint32_t)((uint8_t*)bloom-blind->data));
        memory = blind->data + blind->toc[i].offset +sizeof(bloomfilter_t);
        DBG("Corresponding bloom filter memory address %p. (Offset=%08x).\n",
            memory, (uint32_t)(memory-(uint8_t*)blind->data));
        DBG("Bloom filter number of bits: %d\n", bloom->m);
        // Compute hashes and test bits
        mh = murmur3_32_uint32(ngram);
        nmh = normalize32(mh, bloom->m);
        crc = crc32_uint32(ngram);
        ncrc = normalize32(crc, bloom->m);
        rw = normalize32(ngram, bloom->m);

        DBG("Query Table\n");
        DBG("Ngram|Murmur Hash|Norm MH|CRC|Norm CRC|Norm ngram|Size\n");
        DBG("%08x|%08x|%08x|%08x|%08x|%08x|%08x\n",ngram, mh,nmh,crc,
                                               ncrc, rw, bloom->m/8);
        hmh = test_bit(memory,nmh);
        hcrc = test_bit(memory, ncrc);
        hrw = test_bit(memory, rw);
        DBG("Match Table\n");
        DBG("Ngram|Murmur Hash|CRC\n");
        DBG("%08x|%08x|%08x|%08x\n", ngram, hmh, hcrc, hrw);
        un = hmh && hcrc && hrw;
        if (un > 0) {
            if (validate_fp(blind->toc[i].filename, ngram)) {
                printf("ngram %04x found in filename %s\n", ngram,
                                                       blind->toc[i].filename);
            }else{
                printf("False positive for ngram %04x for filename %s\n", ngram,
                       blind->toc[i].filename);
            }
        }
    }
    return 0;
}


int main(int argc, char* argv[])
{
    int should_create = 0;
    int should_ascii = 0;
    char* query = NULL;
    char* filelist = NULL;
    char* indexfile = NULL;
    char* bulk_queryfile = NULL;
    uint64_t index_size = 0;
    FILE* fp = stdin;
    int l = 0;
    uint32_t value = 0;
    blind_t *blind = NULL;
    const char* const short_options = "hs:cf:i:q:l:a";
    const struct option long_options [] = {
                                            { "help", 0, NULL, 'h' },
                                            { "size", 1, NULL, 's' },
                                            { "create", 0, NULL, 'c'},
                                            { "filelist", 1, NULL, 'f'},
                                            { "indexfile", 1, NULL, 'i'},
                                            { "query",1,NULL, 'q'},
                                            {"bulk",1,NULL, 'b'},
                                            { "ascii", 0, NULL, 'a'},
                                            { NULL, 0, NULL, 0}
                                          };
    int next_option;
    do {
        next_option = getopt_long(argc, argv, short_options, long_options, NULL);
        switch(next_option) {
            case 'h':
                usage(EXIT_SUCCESS);
            case 's':
                index_size = atol(optarg);
                break;
            case 'f':
                l = strlen(optarg);
                filelist = calloc(l,1);
                if (filelist)
                    strncpy(filelist, optarg, l);
                break;
            case 'i':
                l = strlen(optarg);
                indexfile = calloc(l,1);
                if (indexfile)
                    strncpy(indexfile,optarg,l);
                break;
            case 'q':
                l = strlen(optarg);
                query = calloc(l,1);
                if (query)
                    strncpy(query, optarg,l);
                break;
            case 'b':
                l = strlen(optarg);
                bulk_queryfile = calloc(l,1);
                if (bulk_queryfile)
                    strncpy(bulk_queryfile, optarg,l);
                break;
            case 'c':
                should_create = 1;
                break;
            case 'a':
                should_ascii = 1;
        }
    } while ( next_option != -1);

    if (should_create) {
        if (!indexfile) {
            fprintf(stderr,"[ERROR] An indexfile must be specified\n");
            usage(EXIT_FAILURE);
        }
        if (index_size < (sizeof(blind_t) + MAXBLOOMFILTERS * sizeof(bloomfilter_t) + sizeof(toc_t)*MAXBLOOMFILTERS)) {
                fprintf(stderr,"[ERROR] The size %ld of the indexfile is too small.\n", index_size);
                return EXIT_FAILURE;
            }
        return create_new_index(indexfile, index_size, fp);
    }

    if (query) {
        if (indexfile){
            blind = load_index(indexfile);
            if (blind) {
                l = strlen(query);
                if ((l>0) && (l<=8)) {
                    value = 0;
                    sscanf(query,"%08x",&value);
                    printf("Query ngram %04x\n", value);
                    query_index(blind, value);
                    //TODO error handling
                    return EXIT_SUCCESS;
                } else{
                    fprintf(stderr,"[ERROR] Invalid ngram specified\n");
                }
            } else {
                fprintf(stderr,"[ERROR] Could not acquire the index\n");
            }
        } else {
            fprintf(stderr,"[ERROR] An index file is missing for doing the query\n");
            usage(EXIT_FAILURE);
        }
    }
    if (should_ascii) {
        if (indexfile) {
            blind = load_index(indexfile);
            if (blind) {
                printf("Ascii export of the table of contents\n");
                dump_toc(blind);
            }
        } else {
            fprintf(stderr,"[ERROR] An index file must be specified.\n");
        }
        return EXIT_FAILURE;
    }

    printf("*** Nothing to do. Read the help. ****\n");
    return EXIT_SUCCESS;
}
