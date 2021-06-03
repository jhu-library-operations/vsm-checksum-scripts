/*
 * To compile:
 * gcc -o getbaginfo getbaginfo.c argparsing.c -lm -lpthread -I ./boringssl/include -L ./boringssl/build/crypto -L ./boringssl/build/ssl -lssl -lcrypto -lvsm
 *
 * Usage:  ./getbaginfo -m bag <archive>
 */

/* These are all highly standard and portable headers. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <math.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "vsm/stat.h"
#include <vsm/diskvols.h>
#include "/opt/vsm/include/lib.h"
#include "./argparsing.h"
#include "./boringssl/include/openssl/evp.h"
#include "./boringssl/include/openssl/digest.h"
#include "./boringssl/include/openssl/nid.h"

/*
 * size_t BUF_SZ = 1048576;
 * size_t BUF_SZ = 2097152;
 * size_t BUF_SZ = 4194304;
 */

               /* 0       1      2       3        4         5 */
enum tar_header{EXTENDED, EMPTY, NORMAL, NONFILE, BADMAGIC, BADCHECKSUM};
               /* 0       1          2       3          4         5 */
enum tar_flags{NORMALFILE,HARDLINK,SYMLINK,CHAR_DEVICE,BLK_DEVICE,DIRECTORY,FIFO};

enum name_types{NAME_REG, NAME_LINK, NAME_EXT};

//4194304
//1048576
//    BUF_SZ = 1536,
//    BUF_SZ = 33554432
//  PREFETCH = 67108864
typedef enum {
    TAR_BLK_SZ = 512,
    BUF_SZ = 3072,
    PAGE_SZ = 4096,
    WRK_SZ = 8192,
    NAME_POOL = 1048576, /* Each string pool is 1MB */
    RECORDS_CHUNK = 10000,
    MD_BUF_SZ = 4194304,
    PREFETCH = 8388608 
} MyEnum;
// 8388608
// 134217728
// PREFETCH = 33554432 

/*
 *
 */
typedef struct
{
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    unsigned char size[12];
    char mtime[12];
    const char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
} GnuTarHeader;

/*
 *
 */
typedef struct
{
    size_t filesize;
    size_t offset;
    char *filename;
    unsigned char fname_hash[EVP_MAX_MD_SIZE];
    short int type;
    char manifest_csum[129];
    char calc_csum[129];
    unsigned int mdLen;
} Record;

/*
 *
 */
typedef struct
{
    char *current_pool;
    char **pools;
    short int n_pools;
    int current_pool_bytes;
    int total_bytes;
} NamePool;

/*
 *
 */
typedef struct
{
    char *name;
    char *sam_name;
    size_t size;
    size_t sam_size;
    int n_recs;
    int recs_allocation;
    Record *recs;
    NamePool *np;
    bool tar_in_tar;
    bool is_sam;
    // This is typically '0' but maybe not for a sam file or a tar-in-tar. Value in bytes.
    size_t sam_offset_bytes;
} TarFile;

typedef struct
{
    unsigned char buffer[BUF_SZ];
    size_t bufsize;
    size_t buf_bytes_read;
    size_t total_bytes_read;
    size_t prefetch;
    bool do_prefetch;
} TarFileBuffer;

/*
 *
 */
typedef struct
{
    TarFile *tarFile;
    char *bagname;
    Record *bagit;
    Record *baginfo;
    Record *manifest;
    Record *tagmanifest;
    char *algo;
    unsigned long octetcount;
    unsigned int streamcount;
    char *payloadOxum;
    char *calc_payloadOxum;
} BagFile;

typedef struct tpool_work {
         void (*routine)();
         void *arg;
         struct tpool_work *next;
} tpool_work_t;

typedef struct tpool {
         /* pool characteristics */
         int num_threads;

         /* pool state */
         pthread_t *threads;
         int cur_queue_size;
         tpool_work_t *queue_head;
         tpool_work_t *queue_tail;
         pthread_mutex_t queue_lock;
         pthread_cond_t queue_not_empty;
         pthread_cond_t queue_empty;
         int queue_closed;
         int shutdown;
} *tpool_t;

// 5MB
//const int MAX_MANIFEST = 5242880;
const int MAX_MANIFEST = 104857600;
const char TAR_MAGIC[] = "ustar ";
int fd;
unsigned char *f_mmap;
char *algo = NULL;

extern int errno;


void tpool_init(tpool_t *tpoolp, int num_worker_threads);
int tpool_add_work(tpool_t tpool, void *routine, void *arg);
int tpool_destroy(tpool_t tpoolp, int finish);
void *tpool_thread(void *tpoolvar);
static void md_calc(Record *rec);
static void calc_fname_hash(Record *recs, int num_recs);
static void calc_fname_hash_from_manifest_bits(char *bagname, char *filename, unsigned char *hash, unsigned int *mdLen);
static bool get_next_tar_header(GnuTarHeader *tarHeader, TarFile *tarFile, TarFileBuffer *tarBuf, int *flag);
static void read_next_tar_blk(TarFile *tarFile, TarFileBuffer *tarBuf, GnuTarHeader *out_buffer);

void parseFileSize(size_t *filesize, const unsigned char *p, size_t n)
{
        int i = 0;
	char *c;

	*filesize = 0;

	if (*p == 'x') {
	    //printf("size is in hex!!!!\n");
	    //15.9999TB > file size > 8G
	    c = (char *)malloc(sizeof(char)*n);
	    strncpy(c,p+1,(n-1));
	    c[11] = '\0';
	    *filesize = strtol(c,NULL,16);
	} else if (*p & (0X01 << 7)) {
	    //file size > 8G
	    ++p;
	    for (i=1; i<n; i++) {
	        *filesize *= 256;
		*filesize += *p;
		++p;
	    }
	} else {
	    //file size <= 8G
	    for (i=0; i<12; i++) {
	        if ((0 == *p) || (' ' == *p)) {
		    ++p;
		    continue;
		}
		*filesize *= 8;
		*filesize += *p - '0';
		++p;
	    }
	}
}

/* Parse an octal number, ignoring leading and trailing nonsense. */
static int
parseoct(const char *p, size_t n)
{
	int i = 0;

	while ((*p < '0' || *p > '7') && n > 0) {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return (i);
}

/* Returns true if this is 512 zero bytes. */
static int
is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
		if (p[n] != '\0')
			return (0);
	return (1);
}

/* Verify the tar checksum. */
static int
verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == parseoct(p + 148, 8));
}

// Given a file size in bytes, return the block-adjusted bytes.
size_t
get_block_adjusted_bytes(size_t fsize)
{
    size_t bytes_read_from_beg = 0;
    size_t bytes_skipped = 0;
    double blocks_to_advance;

    blocks_to_advance = ceil((double)fsize/TAR_BLK_SZ);
    bytes_skipped = blocks_to_advance*TAR_BLK_SZ;

    return bytes_skipped;
}

size_t
advanceFilePointer(size_t fsize)
{
    size_t bytes_read_from_beg = 0;
    size_t bytes_skipped = 0;
    double blocks_to_advance;

    blocks_to_advance = ceil((double)fsize/TAR_BLK_SZ);
    bytes_skipped = blocks_to_advance*TAR_BLK_SZ;
    bytes_read_from_beg = lseek(fd,(blocks_to_advance*TAR_BLK_SZ),SEEK_CUR);
    if (bytes_read_from_beg == -1) {
        printf("Something went wrong advancing file....");
        bytes_skipped = 0;
    }
    return bytes_skipped;
}

static void
advance_tar_buffer(TarFileBuffer *tarBuf, size_t size)
{
    size_t adj_bytes = 0;

    adj_bytes = get_block_adjusted_bytes(size);
    tarBuf->total_bytes_read += adj_bytes;
    tarBuf->buf_bytes_read += adj_bytes;
    tarBuf->prefetch += adj_bytes;
}

static void
check_np_space(NamePool *np, short int len, int *offset)
{
    int remaining = 0;
    int i;

    if (len > TAR_BLK_SZ) {
        fprintf(stderr, "check_np_space :: filename length is greater than %d. Something is wrong.\n", TAR_BLK_SZ);
	exit(1);
    }

    if (np->current_pool_bytes > NAME_POOL) {
	fprintf(stderr,"Houston, we have a problem: %d v %d\n",np->current_pool_bytes, NAME_POOL);
        exit(1);
    }

    remaining = NAME_POOL - np->current_pool_bytes;

    // check if there is room to store the next string + null terminator + next byte
    // 'next byte' accounts for the fact that we increment current_pool_bytes one more byte
    // for writing the next string. That must be accounted for here so that "remaining" is not negative.
    if ( remaining < (len+2)) {
	//printf("check_np_space :: MORE!  bytes: %d ; t_bytes: %d ; pools: %d.\n", np->current_pool_bytes, np->total_bytes, np->n_pools);

	// allocate new pool

	np->n_pools++;
	np->pools = (char **)realloc(np->pools, sizeof(char *)*(np->n_pools+1));
	if (np->pools == NULL) {
	    fprintf(stderr,"new_pools is NULL!!!!!!\n");
	    exit(1);
	}

	np->pools[np->n_pools] = (char *)malloc(sizeof(char)*NAME_POOL);
	np->current_pool = np->pools[np->n_pools];
	np->current_pool_bytes = 0;
	*offset = 0;

	memset(np->current_pool, '\0', sizeof(char)*NAME_POOL);
    }
}

static void
set_filename(char *name, Record *rec, NamePool *np, bool isextended)
{
    int offset=0;
    int len=0;

    len = strlen(name);

    offset = np->current_pool_bytes;

    if ( (len > 100) && (!isextended) ) {
        len = 100;
    }

    check_np_space(np,len,&offset);
    memcpy(np->current_pool+offset, name, len);
    *(np->current_pool+offset+len) = '\0';

    // +2 because we want it to point to the next available chunk
    np->current_pool_bytes += (len+2);
    np->total_bytes += (len+1);
    rec->filename = np->current_pool+offset;
}

static void
set_link_filename(char *name, char *linkname, Record *rec, NamePool *np)
{
    int len=0;
    int actual_len=0;
    int offset;

    len = strlen(name);
    len += strlen(linkname);
    len += strlen(" -> ");

    check_np_space(np,len,&offset);

    offset = np->current_pool_bytes;

    snprintf(np->current_pool+offset, len+1, "%s -> %s", linkname, name);
    rec->filename = np->current_pool+offset;
    np->current_pool_bytes += (len+2);
    np->total_bytes += (len+1);
}

static void
init_np(NamePool *np)
{
	np->n_pools = 0;
	np->total_bytes = 0;
	np->current_pool_bytes = 0;

	np->pools = (char **)malloc(sizeof(char *)*(np->n_pools+1));
	np->pools[np->n_pools] = (char *)malloc(sizeof(char)*NAME_POOL);
	np->current_pool = np->pools[np->n_pools];
	memset(np->current_pool, '\0', sizeof(char)*NAME_POOL);
}

static void
set_name_in_rec(GnuTarHeader *tarHeader, Record *rec, NamePool *np, char typeflag) {
    short int len = 0;

    switch(typeflag) {
        case '1': // Hardlink
        case '2': // Symlink
	    // linkename -> name
	    set_link_filename(tarHeader->name, tarHeader->linkname, rec, np);
	    break;
        case '0': // Normal File
        case '3': // Character device
        case '4': // Block device
        case '5': // Directory
        case '6': // FIFO
	    set_filename(tarHeader->name, rec, np, false);
	    break;
        case 'L': // Extended
	    set_filename((char *)tarHeader, rec, np, true);
	    break;
    }
}

// Extend allocation if needed
static bool 
check_recs(TarFile *tarFile, Record **recs)
{
    bool retval = false;

    if ((tarFile->n_recs) >= tarFile->recs_allocation) {
        //printf("So far, written %d Records. ; Allocation: %d\n", (tarFile->n_recs-1), tarFile->recs_allocation);

	// add realloc error check
        *recs = (Record *)realloc(*recs, sizeof(Record)*(RECORDS_CHUNK+tarFile->recs_allocation));

	tarFile->recs_allocation += RECORDS_CHUNK;
	//printf("Added another chunk of %d records to the 'recs' array. Total allocation: %d\n", RECORDS_CHUNK,tarFile->recs_allocation);
	//printf(" ++ %s ++\n", (*recs)[tarFile->n_recs-1].filename);
	retval = true;
    }
    return retval;
}

static void
get_headers_from_tar(TarFile *tarFile, Record **recs)
{
	TarFileBuffer tarBuf;
	GnuTarHeader tarHeader;
	NamePool *np;
	int flag;
	size_t filesize;

	tarFile->np = malloc(sizeof(NamePool));
	np = tarFile->np;
	// initialize NamePool
	init_np(np);

	// set up memory map for file (this is the entire TAR file)
	f_mmap = mmap(NULL, tarFile->size, PROT_READ, MAP_PRIVATE, fd, 0);

	// spin up thread pool of one thread to build Records
        // Now spin up a thread pool and work queue and start adding jobs to the queue
        // one job is the file descriptor, the file offset, size

	tarBuf.do_prefetch = true;
	tarBuf.prefetch = 0;
	tarBuf.bufsize = 0;
	tarBuf.buf_bytes_read = 0;
	tarBuf.total_bytes_read = 0;
	tarFile->n_recs = 0;

	// each time through this loop, a new tar record will be processed
	// there are not multiple iterations for, e.g. an extended ('L') header
	while (get_next_tar_header(&tarHeader, tarFile, &tarBuf, &flag)) {
	    //printf("%d\n", tarFile->n_recs);
	    switch(flag) {
		case EMPTY:
		    // do nothing
		    break;
		case EXTENDED:
		    // get the extended name
		    get_next_tar_header(&tarHeader, tarFile, &tarBuf, &flag);
		    set_name_in_rec(&tarHeader, &(*recs)[tarFile->n_recs], np, 'L');
		    //printf("recs[%d].filename = %s\n", tarFile->n_recs, (*recs)[tarFile->n_recs].filename);

		    // read next 512-bytes into tarHeader
		    get_next_tar_header(&tarHeader, tarFile, &tarBuf, &flag);
		    (*recs)[tarFile->n_recs].type = strtol(&tarHeader.typeflag,NULL,10);

		    parseFileSize(&filesize, tarHeader.size, 12);
		    (*recs)[tarFile->n_recs].filesize = filesize;
		    (*recs)[tarFile->n_recs].offset = (tarBuf.total_bytes_read + tarFile->sam_offset_bytes)/TAR_BLK_SZ;

	            advance_tar_buffer(&tarBuf, filesize);
		    tarFile->n_recs++;
		    if (check_recs(tarFile, recs)) {
		        //printf("%d - %s\n", tarFile->n_recs-1, (*recs)[tarFile->n_recs-1].filename);
		    }
		    break;
		case NORMAL:
		    set_name_in_rec(&tarHeader, &(*recs)[tarFile->n_recs], np, tarHeader.typeflag);
		    //printf("recs[%d].filename = %s\n", tarFile->n_recs, (*recs)[tarFile->n_recs].filename);
		    (*recs)[tarFile->n_recs].type = strtol(&tarHeader.typeflag,NULL,10);

		    parseFileSize(&filesize, tarHeader.size, 12);
		    (*recs)[tarFile->n_recs].filesize = filesize;
		    (*recs)[tarFile->n_recs].offset = (tarBuf.total_bytes_read + tarFile->sam_offset_bytes)/TAR_BLK_SZ;

	            advance_tar_buffer(&tarBuf, filesize);
		    tarFile->n_recs++;
		    if (check_recs(tarFile, recs)) {
		        //printf("%d - %s\n", tarFile->n_recs-1, (*recs)[tarFile->n_recs-1].filename);
		    }
		    break;
		case NONFILE:
		    set_name_in_rec(&tarHeader, &(*recs)[tarFile->n_recs], np, tarHeader.typeflag);
		    //printf("recs[%d].filename = %s\n", tarFile->n_recs, (*recs)[tarFile->n_recs].filename);
		    (*recs)[tarFile->n_recs].type = strtol(&tarHeader.typeflag,NULL,10);

		    (*recs)[tarFile->n_recs].filesize = 0;
		    (*recs)[tarFile->n_recs].offset = (tarBuf.total_bytes_read + tarFile->sam_offset_bytes)/TAR_BLK_SZ;

		    tarFile->n_recs++;
		    if (check_recs(tarFile, recs)) {
		        //printf("%d - %s\n", tarFile->n_recs-1, (*recs)[tarFile->n_recs-1].filename);
		    }
		    break;
		case BADMAGIC:
		    fprintf(stderr, "Encountered bad magic in tar header.\n");
		    break;
		case BADCHECKSUM:
		    fprintf(stderr, "Encountered bad tar header checksum.\n");
		    break;
	    }
	}
        munmap(f_mmap,tarFile->size);
}

static void
check_prefetch(TarFileBuffer *tarBuf, size_t offset, size_t tar_size)
{
    bool time_to_fetch = false;

    if (tarBuf->prefetch >= PREFETCH) {
	if ( (tarBuf->total_bytes_read - tar_size) > PREFETCH)
            time_to_fetch = true;
    }

    if ( (tarBuf->do_prefetch) && (time_to_fetch) ) {
	posix_fadvise64(fd,offset,PREFETCH,POSIX_FADV_WILLNEED);
        tarBuf->prefetch = 0;
    }
}

static void
read_next_tar_blk(TarFile *tarFile, TarFileBuffer *tarBuf, GnuTarHeader *out_buffer)
{
    size_t offset = 0;
    size_t tar_size = 0;

    offset = tarBuf->total_bytes_read + tarFile->sam_offset_bytes;

    if (tarFile->is_sam)
        tar_size = tarFile->sam_size;
    else
        tar_size = tarFile->size;

    // check prefetch status 
    check_prefetch(tarBuf, offset, tar_size);

    memset(out_buffer, '\0', sizeof(GnuTarHeader));

    // read next block

    //int madvise(void *addr, size_t length, int advice);
    //madvise(f_mmap+offset, PAGE_SZ, MADV_WILLNEED);
    memcpy(out_buffer, f_mmap+offset, TAR_BLK_SZ);
    
    // increment counters
    tarBuf->total_bytes_read += TAR_BLK_SZ;
    tarBuf->buf_bytes_read += TAR_BLK_SZ;
    tarBuf->prefetch += TAR_BLK_SZ;
}

// This function will read TAR_BLK_SZ from buffer and no more.
static bool
get_next_tar_header(GnuTarHeader *tarHeader, TarFile *tarFile, TarFileBuffer *tarBuf, int *flag)
{
    GnuTarHeader emptyHeader;
    bool returnval = true;

    // read next 512-byte block into buffer
    read_next_tar_blk(tarFile, tarBuf, tarHeader);

    memset (&emptyHeader, 0, TAR_BLK_SZ);

    if (0 == memcmp(tarHeader, &emptyHeader, TAR_BLK_SZ)) {
	if (*flag == EMPTY) {
	    // Two empty headers in a row
	    returnval = false;
	}
        *flag = EMPTY;
    }
    else if (memcmp(tarHeader->magic,TAR_MAGIC,5) != 0)
        *flag = BADMAGIC;
    else if (!verify_checksum((char *)tarHeader))
        *flag = BADCHECKSUM;
    else if (tarHeader->typeflag == 'L')
        *flag = EXTENDED;
    else if (tarHeader->typeflag != '0')
        *flag = NONFILE;
    else
	*flag = NORMAL;

    //printf("get_next_tar_header :: flag = %d\n", *flag);
    // enum tar_header{EXTENDED, EMPTY, NORMAL, NONFILE, BADMAGIC, BADCHECKSUM};
    // return true, there are more headers, or false, there are NOT more headers
    return returnval;
}

// https://stackoverflow.com/questions/3068397/finding-the-length-of-an-integer-in-c
static int
get_int_len (int value)
{
    int l=1;
    while(value>9){ l++; value/=10; }
    return l;
}

static void
print_bag_file(const char *bagit_file, BagFile *bagFile)
{
    char *buffer, *line;
    Record *rec;

    if (strcmp(bagit_file,TAGMANIFEST) == 0)
        rec = bagFile->tagmanifest;
    else if (strcmp(bagit_file,MANIFEST) == 0)
        rec = bagFile->manifest;
    else if (strcmp(bagit_file,BAGINFO) == 0)
        rec = bagFile->baginfo;
    else if (strcmp(bagit_file,BAGIT) == 0)
        rec = bagFile->bagit;
    else {
        printf("Something went wrong. Unexpected 'get' request? (%s)\nReturning bagit file instead...\n\n",bagit_file);
	rec = bagFile->bagit;
    }

    printf("\nFilename: %s; size = %lu\n\n", rec->filename,rec->filesize);
    buffer = malloc((sizeof(char)*(rec->filesize)+1));
    pread(fd, buffer, rec->filesize, rec->offset*TAR_BLK_SZ);
    buffer[rec->filesize] = 0;
    line = strtok(buffer, "\n");
    while(line) {
	// remove windows control character, if it exists
	char *p = strchr(line, '\r');
	if (p != NULL)
	    *p = '\0';
        printf("%s\n", line);
	line = strtok(NULL, "\n");
    }
    printf("\n");
    free(buffer);
}

static bool 
verify_bag_payload_oxum(BagFile *bagFile)
{
    char *buffer;
    char *line;
    char *name;
    int len;

    // Calculate length of string for payload-oxum value 
    len += get_int_len(bagFile->octetcount);
    len += get_int_len(bagFile->streamcount);
    // add some extra
    len += 16;

    bagFile->payloadOxum = malloc(sizeof(char)*len);
    bagFile->calc_payloadOxum = malloc(sizeof(char)*len);

    buffer = malloc( (sizeof(char)*(bagFile->baginfo->filesize)+1) );
    pread(fd, buffer, bagFile->baginfo->filesize, bagFile->baginfo->offset*TAR_BLK_SZ);
    line = strtok(buffer, "\n");
    while(line) {
	// remove windows control character, if it exists
	char *p = strchr(line, '\r');
	if (p != NULL)
	    *p = '\0';
	if (strstr(line, "Payload-Oxum:") != NULL) {
            name = malloc(sizeof(char)*(strlen("Payload-Oxum:")+1));
            sscanf(line,"%s %s\n",name,bagFile->payloadOxum);
	    sprintf(bagFile->calc_payloadOxum,"%lu.%d", bagFile->octetcount,bagFile->streamcount);
	    if (strcmp(bagFile->payloadOxum,bagFile->calc_payloadOxum) == 0)
	        return true;
	}
        line = strtok(NULL, "\n");
    }
    free(buffer);
    free(name);
    return false;
}

static void
init_bag(BagFile *bagFile)
{
    Record *recs;
    char *bagname;
    char *baginfo_search, *bagit_search, *manifest_search, *tagmanifest_search, *data_search;
    char *tmp;
    int len;
    int i;

    // initialize some things in bagFile
    bagFile->octetcount = 0;
    bagFile->streamcount = 0;


    recs = bagFile->tarFile->recs;

    // First, get the 'bagname'
    for (i=0; i<bagFile->tarFile->n_recs; i++) {
        if (recs[i].type == 5) {
            if ((tmp = strstr(recs[i].filename, "/data/")) != NULL) {
                // Calculate length of the bagname, not including the trailing '/'.
                len = strlen(recs[i].filename) - strlen(tmp);
                bagname = malloc(sizeof(char)*(len+1));
                strncpy(bagname,recs[i].filename,(len));
                bagname[len] = '\0';
                break;
            }
        }
    }
    bagFile->bagname = bagname;
    //printf("Got Bagname: |%s|\n", bagname);

    // Go through the file list, looking for "bag" related files
    // EXAMPLE:
    // name-of-bag/bag-info.txt
    // name-of-bag/bagit.txt
    // name-of-bag/manifest-md5.txt (OR manifest-sha1.txt ; manifest-sha256.txt ; manifest-sha512.txt)
    // name-of-bag/tagmanifest-md5.txt
    // algos: md5, sha1, sha256, sha512

    // Review all the records looking for bag metadata files
    // First record should be the top-level bag directory: "bagname/" -- this is NOT the case for files created on Windows by DMS using the PackageTool!!!
    // But, unfortunately, it might be something like: "dir/blah/blubber/bagname/" (or maybe with trailing slash)

    baginfo_search = malloc( sizeof(char)*(strlen(bagname) + strlen("/bag-info.txt") + 1) );
	sprintf(baginfo_search,"%s/bag-info.txt",bagname);
    bagit_search = malloc( sizeof(char)*(strlen(bagname) + strlen("/bagit.txt") + 1) );
	sprintf(bagit_search,"%s/bagit.txt",bagname);
    manifest_search = malloc( sizeof(char)*(strlen(bagname) + strlen("/manifest-") + 1) );
	sprintf(manifest_search,"%s/manifest-",bagname);
    tagmanifest_search = malloc(sizeof(char)*(strlen(bagname) + strlen("/tagmanifest-") + 1));
	sprintf(tagmanifest_search,"%s/tagmanifest-",bagname);
    data_search = malloc(sizeof(char)*( strlen(bagname) + strlen("/data/") + 1) );
	sprintf(data_search,"%s/data/",bagname);

    // Clear default algo setting
    if (strcmp(algo, SN_md5) == 0) {
        free(algo);
	algo = NULL;
    }
    for (i=0; i<bagFile->tarFile->n_recs; i++) {
	//printf("%d %lu %s\n",i, recs[i].filesize, recs[i].filename);

        if (strstr(recs[i].filename, baginfo_search) != NULL)
            bagFile->baginfo = &recs[i];
        else if (strstr(recs[i].filename, bagit_search) != NULL)
            bagFile->bagit = &recs[i];
        else if (strstr(recs[i].filename, manifest_search) != NULL) {
            char *test = strrchr(recs[i].filename, '-');
            test++;
	    const char *tmpalgo;
            if (strcmp(test,"md5.txt") == 0)
                tmpalgo = SN_md5;
            else if (strcmp(test,"sha1.txt") == 0)
                tmpalgo = SN_sha1;
            else if (strcmp(test,"sha256.txt") == 0)
                tmpalgo = SN_sha256;
            else if (strcmp(test,"sha512.txt") == 0)
                tmpalgo = SN_sha512;

	    if (algo == NULL) {
	        algo = strdup(tmpalgo);
                bagFile->manifest = &recs[i];
	    }
	    // Choose the strongest algorithm 
	    else if ( (strcmp(algo, SN_sha512) != 0) && (tmpalgo != SN_md5) ) {
	        if (strcmp(algo, SN_md5) == 0) {
		    algo = strdup(tmpalgo);
		    bagFile->manifest = &recs[i];
		}
		else if (tmpalgo == SN_sha512) {
		    algo = strdup(tmpalgo);
		    bagFile->manifest = &recs[i];
		}
		else if ( (strcmp(algo, SN_sha1) == 0) && (tmpalgo == SN_sha256) ) {
		    algo = strdup(tmpalgo);
		    bagFile->manifest = &recs[i];
		}
	    }
        }
        else if (strstr(recs[i].filename, tagmanifest_search) != NULL) {
            bagFile->tagmanifest = &recs[i];
            bagFile->tagmanifest->type = 8;
        }
        else {
            // regular data file
            if (recs[i].type == 0) {
                if (strstr(recs[i].filename, data_search) != NULL) {
                    bagFile->octetcount += recs[i].filesize;
                    bagFile->streamcount++;
                }
            }
        }
    }
    free(baginfo_search);
    free(bagit_search);
    free(manifest_search);
    free(tagmanifest_search);
    free(data_search);

    bagFile->algo = algo;

    /*
    printf("Algo: %s\n", bagFile->algo);
    printf("bag-info file: %s\n", bagFile->baginfo->filename);
    printf("bagit file: %s\n", bagFile->bagit->filename);
    printf("manifest file: %s\n", bagFile->manifest->filename);
    printf("tag manifest file: %s\n\n", bagFile->tagmanifest->filename);
    */
}

// return list of the Recs, sorted by fname_hash
static Record **
get_sorted_recs(BagFile *bagFile)
{
    Record *recs;
    Record **sorted_recs;
    int i,j;

    sorted_recs = (Record **)malloc(sizeof(Record *));
    return sorted_recs;
}

static void
parse_manifest(BagFile *bagFile)
{
    Record *recs;
    unsigned char *buffer;
    char *line;
    char *tmp;
    char fname[512];
    char csum[130];
    int i,len;
    unsigned int mdLen;
    unsigned char h[EVP_MAX_MD_SIZE];
    char *hash_array;

    /* Now we have algorithm for calculation and also pointers into reclist to the bag metadata files.
     * 
     * Parse the manifest file.
     * Assume format: <checksum string><2 spaces><filename>
     */
    if (bagFile->manifest->filesize > MAX_MANIFEST) {
        fprintf(stderr, "The manifest file is larger than we expected... (%lu)\n", bagFile->manifest->filesize);
	exit(1);
    }

    recs = bagFile->tarFile->recs;

    buffer = malloc(sizeof(unsigned char)*(bagFile->manifest->filesize + 1));
    pread(fd, buffer, bagFile->manifest->filesize, bagFile->manifest->offset*TAR_BLK_SZ);
    line = strtok(buffer, "\n");
    while(line) {
	// remove windows control character, if it exists
	char *p = strchr(line, '\r');
	if (p != NULL)
	    *p = '\0';

	memset(fname,'\0',sizeof(fname));
	memset(csum,'\0',sizeof(csum));
	memset(h, '\0', EVP_MAX_MD_SIZE);

	sscanf(line,"%s  %511c",csum,fname);
        calc_fname_hash_from_manifest_bits(bagFile->bagname,fname,h,&mdLen);

	// search for this file in reclist
	for (i=0; i<bagFile->tarFile->n_recs; i++) {
	    if (recs[i].type == 0) {
		if (memcmp(h,recs[i].fname_hash,mdLen) == 0) {
		    strcpy(recs[i].manifest_csum,csum);
		    break;
		}
	    }
        }
	line = strtok(NULL, "\n");
    }
    free(buffer);

    /* tagmanifest.txt
     *
     * defc71b28593bb73c7c94a8332f85da8  bagit.txt
     * 78da50151a6620876638394d3908b58c  manifest-md5.txt
     * a1ede069edbffc15d574b9f453403a08  bag-info.txt
     */
    //
    buffer = malloc( sizeof(unsigned char)*(bagFile->tagmanifest->filesize+1) );
    pread(fd, buffer, bagFile->tagmanifest->filesize, bagFile->tagmanifest->offset*TAR_BLK_SZ);
    line = strtok(buffer, "\n");
    while(line) {
	// remove windows control character, if it exists
	char *p = strchr(line, '\r');
	if (p != NULL)
	    *p = '\0';

	memset(fname,'\0',sizeof(fname));
	memset(csum,'\0',sizeof(csum));

        sscanf(line,"%s  %511c",csum,fname);
	if (strlen(fname) == 0)
	    break;
	char *tmp = strdup(fname);
	strcpy(fname,bagFile->bagname);
	strcat(fname,"/");
	strcat(fname,tmp);
	free(tmp);

	// search for this file in reclist
	for (i=0; i<bagFile->tarFile->n_recs; i++) {
	    if (strstr(recs[i].filename,fname) != NULL) {
	        strcpy(recs[i].manifest_csum,csum);
		break;
	    }
        }
	line = strtok(NULL, "\n");
    }
    free(buffer);
}

static void
get_dk_info(TarFile *tarFile)
{
    struct sam_stat sb;
    char dk_name[256];
    const char *DKROOT = "/dkarcs/";
    int64_t dknum;
    int len = 0;

    //printf("tarFile->sam_name = %s\n", tarFile->sam_name);

    if (sam_lstat(tarFile->sam_name, &sb, sizeof(sb)) < 0 ) {
            perror("sam stat");
            exit(1);
    }

    if (S_ISREG(sb.st_mode)) {
        if (sb.copy[0].flags & CF_ARCHIVED) {
	    //printf("media: %s\nvsn: %s\noffset: %lu\nposition: %lu\n", sb.copy[0].media, sb.copy[0].vsn, sb.copy[0].offset, sb.copy[0].position);
	    DiskVolsGenFileName(sb.copy[0].position, &dk_name[0], sizeof(dk_name));

	    len += strlen(DKROOT);
	    len += strlen(sb.copy[0].vsn);
	    len += strlen(dk_name);
	    len += 2; // '/' + '\0'

	    tarFile->name = malloc(sizeof(char)*len);
	    strcpy(tarFile->name,DKROOT);
	    strcat(tarFile->name,sb.copy[0].vsn);
	    strcat(tarFile->name,"/");
	    strcat(tarFile->name,dk_name);

	    // the VSM stat.h header file now defines offset as a 64-bit (uint64_t) in bytes (not 512-byte blocks).
	    tarFile->sam_offset_bytes = sb.copy[0].offset;
	    tarFile->sam_size = sb.st_size;
	    //printf("file: %s  ; offset = %lu\n", tarFile->name, tarFile->sam_offset_bytes);
	}
	else {
	    fprintf(stderr,"Copy-1 does not exist for %s\n",tarFile->sam_name);
            tarFile->name = NULL;
	}
    }
    else {
        fprintf(stderr,"Was expecting a file but got something else? %s\n",tarFile->sam_name);
        tarFile->name = NULL;
    }
}

int
main(int argc, char **argv)
{
	struct arguments arguments;
    	struct sam_stat sb;
	Record *recs;
	BagFile bagFile;
	TarFile tarFile;
	tpool_t csum_thread_pool;
	int i, good=0, bad=0, empty=0;
	int errnum;
	GnuTarHeader *headers;

	//printf("size of NamePool: %d\n", sizeof(NamePool));
	//printf("size of Record: %d\n", sizeof(Record));
	parse_arguments(argc, argv, &arguments);
	algo = strdup(arguments.algo);

	tarFile.sam_offset_bytes = 0;
	tarFile.is_sam = false;
	tarFile.tar_in_tar = false;

	CRYPTO_library_init();

	// in this case, we need to get the back-end dk tar file
	if (arguments.sam_copy == 1) {
	    tarFile.is_sam = true;
	    tarFile.sam_name = arguments.file;
	    // We set this to false because 'get_dk_info' will provide the proper offset
	    tarFile.tar_in_tar = false;
	    get_dk_info(&tarFile);
	    if (tarFile.name == NULL) {
	        fprintf(stderr,"Could not resolve %s to a disk-archive path name.\n", tarFile.sam_name);
		exit(1);
	    }
	}
	// this does not work yet
	else if (arguments.wrapped) {
	    printf("wrapped = true!\n");
	    printf("wrap offset = %lu\n", arguments.offset);
	    tarFile.tar_in_tar = true;
	    tarFile.sam_offset_bytes = arguments.offset;
	    tarFile.name = arguments.file;
	}
	else {
	    tarFile.tar_in_tar = false;
	    tarFile.name = arguments.file;
	    tarFile.sam_offset_bytes = 0;
	}

    	// grab stat struct
    	if (sam_lstat(tarFile.name, &sb, sizeof(sb)) < 0) {
        	perror("sam_lstat");
       		exit(1);
    	}
	tarFile.size = sb.st_size;

	// "fd" is a global variable
	fd = open(tarFile.name, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
	        fprintf(stderr, "Unable to open %s\n", tarFile.name);
		return (1);
	}

	// report tar file we're reading and its size
        //printf("file: %s ; size = %lu\n", tarFile.name,tarFile.size);

	// Build list of tar-file contents
	recs = malloc(sizeof(Record)*RECORDS_CHUNK);
	tarFile.recs_allocation = RECORDS_CHUNK;
	get_headers_from_tar(&tarFile,&recs);

	//printf("Finished getting records.\n");
	//printf("recs: %d; last fname: %s\n", tarFile.n_recs,recs[0].filename);
	// reduce rec array to free space?
	//recs = realloc(recs, sizeof(Record)*tarFile.n_recs);

	tarFile.recs = recs;

	calc_fname_hash(recs, tarFile.n_recs);
	//printf("Finished calculating fname hashes.\n");

	// If expecting a BagIT "bag", do some more processing.
	if (strcmp(arguments.mode,BAG) == 0) {
	    bagFile.tarFile = &tarFile;
	    init_bag(&bagFile);

	    if (arguments.fast) {
	        if (verify_bag_payload_oxum(&bagFile)) {
	            printf("INFO - GOOD - %s  %s\n", bagFile.bagname,bagFile.payloadOxum);
		    //printf("     %s (expected)\n",bagFile.payloadOxum);
		    //printf("     %s (calculated)\n",bagFile.calc_payloadOxum);
	        }
	        else {
	            printf("ERROR - BAD - %s  Expected|Calculated   %s|%s\n", bagFile.bagname,bagFile.payloadOxum,bagFile.calc_payloadOxum);
		    //printf("     %s (expected)\n",bagFile.payloadOxum);
		    //printf("     %s (calculated)\n",bagFile.calc_payloadOxum);
	        }
	        close(fd);
	        exit(0);
	    }
	    else if (arguments.empties) {
                for (i=0; i<tarFile.n_recs; i++) {
                    if (recs[i].type == 0) {
                        if (recs[i].filesize == 0) {
                            printf("EMPTY-FILE:  %s\n",recs[i].filename);
                            empty++;
                        }
                    }
                }
		printf("\nEmpty files: %d\n\n", empty);
	        close(fd);
	        exit(0);
	    }
	    else if (arguments.get != NULL) {
	        print_bag_file(arguments.get,&bagFile);
	        close(fd);
	        exit(0);
	    }

	    parse_manifest(&bagFile);
	}

        // Now spin up a thread pool and work queue and start adding jobs to the queue
        // one job is the file descriptor, the file offset, size

        tpool_init(&csum_thread_pool, arguments.n_threads);

        // Add work
	for (i=0; i<tarFile.n_recs; i++) {
            if (recs[i].type == 0) {
		//printf("adding work for %s\n", recs[i].filename);
                tpool_add_work(csum_thread_pool, md_calc, (void *)&recs[i]);
            }
        }
        tpool_destroy(csum_thread_pool, 1);
        //printf("Destroyed thread pool\n");

        // Now print out all the records & verify checksums
	for (i=0; i<tarFile.n_recs; i++) {
	    if (recs[i].type == 0) {
		if (strcmp(arguments.mode,BAG) == 0) {
		    if (recs[i].filesize == 0) {
		        empty++;
			if (arguments.verbose)
			    printf("EMPTY-FILE:  %s\n",recs[i].filename);
		    }
		    else { // don't verify checksums for empty files
		        if (strcmp(recs[i].calc_csum, recs[i].manifest_csum) == 0) {
		            good++;
			    if (arguments.verbose)
			        printf("INFO  %s: calculated(%s) manifest(%s) - GOOD!\n",recs[i].filename,recs[i].calc_csum, recs[i].manifest_csum);
		        }
		        else {
		            bad++;
			    printf("ERROR  %s: calculated(%s) manifest(%s) - BAD!\n",recs[i].filename,recs[i].calc_csum, recs[i].manifest_csum);
		        }
		    }
		}
		else {
	            printf("%d|%lu|%lu|%s|%s\n",recs[i].type,recs[i].offset,recs[i].filesize,recs[i].calc_csum,recs[i].filename);
	        }
	    }
        }
	if (strcmp(arguments.mode,BAG) == 0) {
	    printf("\nFixity is good for %d out of %d files.\n", good, (good+bad+empty));
	    if (empty > 0)
	        printf("\nEmpty files: %d\n", empty);
	    printf("\n");
	}

	free(recs);
	// free NamePool resources?
	close(fd);
	return (0);
}

static void
md_calc(Record *rec)
{
        int errnum;
        unsigned long int total_bytes_read = 0;
        unsigned long int size;
        unsigned long int offset;
        unsigned char *buffer;
        size_t bytes_read;
        size_t current_byte = 0;
        size_t remaining_bytes = 0;
        size_t inputLen;
        const EVP_MD *md;
        EVP_MD_CTX *ctx;
        unsigned char calc_csum[EVP_MAX_MD_SIZE];
        char tmp[8];
        int mdLen;
        int i = 0;

        //printf("md_calc :: Trying to initialize openssl EVP stuff...\n");
        // initialize openssl message digest stuff
        //OpenSSL_add_all_algorithms();
        //ERR_load_crypto_strings();
        //printf("md_calc :: initialized !! openssl EVP stuff...\n");

        //CRYPTO_library_init();

        md = EVP_get_digestbyname(algo);
        if (md == NULL) {
            printf("Something went wrong because md is NULL!\n");
            exit (1);
        }


        size = rec->filesize;
        offset = rec->offset*TAR_BLK_SZ;

        ctx = EVP_MD_CTX_create();
        EVP_DigestInit(ctx,md);

        buffer = (unsigned char *) malloc(sizeof(unsigned char)*MD_BUF_SZ);
        total_bytes_read = 0;


        while (size > 0)
        {
                if (size >= MD_BUF_SZ) {
                    if (size > (MD_BUF_SZ*2))
                        posix_fadvise64(fd,offset,MD_BUF_SZ*2,POSIX_FADV_WILLNEED);
                    if ((bytes_read = pread(fd,buffer,MD_BUF_SZ,offset)) == -1)
                        perror("pread"), exit(-1);
                    offset += bytes_read;
                }
                else {
                    if ((bytes_read = pread(fd,buffer,size,offset)) == -1)
                        perror("pread"), exit(-1);
                    offset += bytes_read;
                }

                total_bytes_read += bytes_read;
                current_byte = 0;
                remaining_bytes = bytes_read;
                // LOOP 2
                while (current_byte < bytes_read) {
                  if (size <= WRK_SZ) {
                        if (size <= remaining_bytes) {
                                EVP_DigestUpdate(ctx, buffer+current_byte, size);
                                EVP_DigestFinal(ctx, calc_csum, &mdLen);
                                size = 0;
                                break; /* is this the way to break out of this while loop? */
                        }
                        else {
                                EVP_DigestUpdate(ctx, buffer+current_byte, remaining_bytes);
                                size -= remaining_bytes;
                                current_byte = bytes_read;
                        }
                  }
                  else {
                        if (remaining_bytes >= WRK_SZ) {
                                EVP_DigestUpdate(ctx, buffer+current_byte, WRK_SZ);
                                size -= WRK_SZ;
                                current_byte += WRK_SZ;
                                remaining_bytes -= WRK_SZ;
                        }
                        else {
                                EVP_DigestUpdate(ctx, buffer+current_byte, remaining_bytes);
                                size -= remaining_bytes;
                                current_byte = bytes_read;
                        }
                  }
                }
                memset(buffer, '\0', MD_BUF_SZ);
                //posix_fadvise64(fd,(total_bytes_read+MD_BUF_SZ),MD_BUF_SZ*2,POSIX_FADV_WILLNEED);
                //posix_fadvise64(fd,(offset-MD_BUF_SZ),MD_BUF_SZ,POSIX_FADV_DONTNEED);
        }
        free(buffer);

        for (i=0; i<mdLen; i++) {
            sprintf(tmp,"%02x", calc_csum[i]);
            strcat(rec->calc_csum,tmp);
        }
        memset(calc_csum, '\0', 128);

        EVP_MD_CTX_destroy(ctx);
}

void tpool_init(tpool_t   *tpoolp,
                int       num_worker_threads)
{
   int i, rtn;
   tpool_t tpool;

   /* allocate a pool data structure */
   if ((tpool = (tpool_t )malloc(sizeof(struct tpool))) == NULL)
     perror("malloc"), exit(-1);

   /* initialize the fields */
   //printf("Initializing thread pool with %d worker threads.\n", num_worker_threads);
   tpool->num_threads = num_worker_threads;

   if ((tpool->threads = (pthread_t *)malloc(sizeof(pthread_t)*num_worker_threads)) == NULL)
     perror("malloc"), exit(-1);

   tpool->cur_queue_size = 0;
   tpool->queue_head = NULL;
   tpool->queue_tail = NULL;
   tpool->queue_closed = 0;
   tpool->shutdown = 0;

   if ((rtn = pthread_mutex_init(&(tpool->queue_lock), NULL)) != 0)
        fprintf(stderr,"pthread_mutex_init %s",strerror(rtn)), exit(-1);
   if ((rtn = pthread_cond_init(&(tpool->queue_not_empty), NULL)) != 0)
        fprintf(stderr,"pthread_cond_init %s",strerror(rtn)), exit(-1);
   if ((rtn = pthread_cond_init(&(tpool->queue_empty), NULL)) != 0)
        fprintf(stderr,"pthread_cond_init %s",strerror(rtn)), exit(-1);

   /* create threads */
   for (i = 0; i != num_worker_threads; i++) {
	//printf("Creating thread %d\n", i);
        if ((rtn = pthread_create( &(tpool->threads[i]),
                        NULL,
                        tpool_thread,
                        (void *)tpool)) != 0)
           fprintf(stderr,"pthread_create %d",rtn), exit(-1);
   }

   *tpoolp = tpool;
}

void *tpool_thread(void *tpoolvar)
{
   tpool_work_t *my_workp;
   tpool_t tpool = tpoolvar;

   //printf("tpool_thread :: top; queue size = %d\n", tpool->cur_queue_size);
   for (;;) {

            pthread_mutex_lock(&(tpool->queue_lock));
            while ( (tpool->cur_queue_size == 0) && (!tpool->shutdown)) {
		      //printf("tpool_thread :: Queue not empty (%d)!!\n",tpool->cur_queue_size);
                      pthread_cond_wait(&(tpool->queue_not_empty),
                      &(tpool->queue_lock));
            }

            if (tpool->shutdown) {
		      //printf("tpool_thread :: SHUTDOWN!!\n");
                      pthread_mutex_unlock(&(tpool->queue_lock));
                      pthread_exit(NULL);
            }

            my_workp = tpool->queue_head;
            tpool->cur_queue_size--;
            if (tpool->cur_queue_size == 0)
                      tpool->queue_head = tpool->queue_tail = NULL;
            else
                      tpool->queue_head = my_workp->next;

            if (tpool->cur_queue_size == 0)
                      pthread_cond_signal(&(tpool->queue_empty));
            pthread_mutex_unlock(&(tpool->queue_lock));
            (*(my_workp->routine))(my_workp->arg);
            free(my_workp);
   }
}

//
// Example 3-25. Adding Work to a Thread Pool (tpool.c)
//
// typedef struct tpool_work {
//         void (*routine)();
//         void *arg;
//         struct tpool_work *next;
// } tpool_work_t;
//
int tpool_add_work(tpool_t tpool, void *routine, void *arg)
{
        tpool_work_t *workp;
        pthread_mutex_lock(&tpool->queue_lock);

        if (tpool->shutdown || tpool->queue_closed) {
                  pthread_mutex_unlock(&tpool->queue_lock);
                  return -1;
        }

        /* allocate work structure */
        workp = (tpool_work_t *)malloc(sizeof(tpool_work_t));
        workp->routine = routine;
        workp->arg = arg;
        workp->next = NULL;
        if (tpool->cur_queue_size == 0) {
                  tpool->queue_tail = tpool->queue_head = workp;
                  pthread_cond_broadcast(&tpool->queue_not_empty);
        } else {
                  (tpool->queue_tail)->next = workp;
                  tpool->queue_tail = workp;
        }
        tpool->cur_queue_size++;
        pthread_mutex_unlock(&tpool->queue_lock);
        return 1;
}

//
// Example 3-26. Deleting a Thread Pool (tpool.c)
//
int tpool_destroy(tpool_t     tpool,
                  int         finish)
{
   int          i,rtn;
   tpool_work_t *cur_nodep;

   if ((rtn = pthread_mutex_lock(&(tpool->queue_lock))) != 0)
         fprintf(stderr,"pthread_mutex_lock %d",rtn), exit(-1);

   /* Is a shutdown already in progress? */
   if (tpool->queue_closed || tpool->shutdown) {
      if ((rtn = pthread_mutex_unlock(&(tpool->queue_lock))) != 0)
         fprintf(stderr,"pthread_mutex_unlock %d",rtn), exit(-1);
      return 0;
   }

   tpool->queue_closed = 1;

   /* If the finish flag is set, wait for workers to drain queue */
   if (finish == 1) {
     while (tpool->cur_queue_size != 0) {
        if ((rtn = pthread_cond_wait(&(tpool->queue_empty),
                          &(tpool->queue_lock))) != 0)
         fprintf(stderr,"pthread_cond_wait %d",rtn), exit(-1);
     }
   }

   tpool->shutdown = 1;

   if ((rtn = pthread_mutex_unlock(&(tpool->queue_lock))) != 0)
         fprintf(stderr,"pthread_mutex_unlock %d",rtn), exit(-1);

   /* Wake up any workers so they recheck shutdown flag */
   if ((rtn = pthread_cond_broadcast(&(tpool->queue_not_empty))) != 0)
         fprintf(stderr,"pthread_cond_broadcast %d",rtn), exit(-1);

   /* Wait for workers to exit */
   for(i=0; i < tpool->num_threads; i++) {
        if ((rtn = pthread_join(tpool->threads[i],NULL)) != 0)
            fprintf(stderr,"pthread_join  %d",rtn), exit(-1);
   }

   /* Now free pool structures */
   free(tpool->threads);
   while(tpool->queue_head != NULL) {
     cur_nodep = tpool->queue_head->next;
     tpool->queue_head = tpool->queue_head->next;
     free(cur_nodep);
   }
   free(tpool);
   return 0;
}

static void
calc_fname_hash(Record *recs, int num_recs)
{
        int errnum;
        size_t inputLen;
        const EVP_MD *md;
        EVP_MD_CTX *ctx;
        int i,j;

        //CRYPTO_library_init();

        //memset(hash, '\0', EVP_MAX_MD_SIZE);

        md = EVP_get_digestbyname(SN_md5);
        if (md == NULL) {
            printf("Something went wrong because md is NULL!\n");
            exit (1);
        }

        ctx = EVP_MD_CTX_create();

	for (i=0; i<num_recs; i++) {
	    if (recs[i].type == 0) {
	        EVP_DigestInit(ctx,md);
		EVP_DigestUpdate(ctx, recs[i].filename, strlen(recs[i].filename));
		EVP_DigestFinal(ctx, recs[i].fname_hash, &(recs[i].mdLen));
		/*
		printf("calc_fname_hash :: %d :: ",recs[i].mdLen);
		for (j=0; j<(recs[i].mdLen); j++) {
		    printf("%02x", recs[i].fname_hash[j]);
		}
		printf(" - %s\n", recs[i].filename);
		*/
	    }
	}

        EVP_MD_CTX_destroy(ctx);
}

static void
calc_fname_hash_from_manifest_bits(char *bagname, char *filename, unsigned char *hash, unsigned int *mdLen)
{
        int errnum;
        size_t inputLen;
        const EVP_MD *md;
        EVP_MD_CTX *ctx;
	int i;
	char tmp[513];

        md = EVP_get_digestbyname(SN_md5);
        if (md == NULL) {
            printf("Something went wrong because md is NULL!\n");
            exit (1);
        }

        ctx = EVP_MD_CTX_create();
        EVP_DigestInit(ctx,md);

	//tmp = malloc(sizeof(char)*TAR_BLK_SZ);
	strcpy(tmp,bagname);
	strcat(tmp,"/");
	strcat(tmp,filename);

        EVP_DigestUpdate(ctx, tmp, strlen(tmp));
        EVP_DigestFinal(ctx, hash, mdLen);

	/*
	printf("calc_fname_hash_from_manifest_bits :: %d :: ",*mdLen);
        for (i=0; i<*mdLen; i++) {
	    printf("%02x", hash[i]);
	}
	printf(" - %s\n",filename);
	*/

	//free(tmp);
        EVP_MD_CTX_destroy(ctx);
}
