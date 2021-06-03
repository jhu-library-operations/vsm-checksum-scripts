/*
 * This file is in the public domain.  Use it as you see fit.
 * https://github.com/libarchive/libarchive/blob/master/contrib/untar.c
 */

/*
 * "untar" is an extremely simple tar extractor:
 *  * A single C source file, so it should be easy to compile
 *    and run on any system with a C compiler.
 *  * Extremely portable standard C.  The only non-ANSI function
 *    used is mkdir().
 *  * Reads basic ustar tar archives.
 *  * Does not require libarchive or any other special library.
 *
 * To compile: gcc -o untar untar.c -lm -lssl -lcrypto
 * To compile: gcc -o print_offset_cksum_from_tar print_offset_cksum_from_tar.c -I ~gara/c_programs/NEW.getbaginfo/boringssl/include -L ~gara/c_programs/NEW.getbaginfo/boringssl/build/crypto -L ~gara/c_programs/NEW.getbaginfo/boringssl/build/ssl -lm -lpthread -lssl -lcrypto
 *
 * Usage:  untar <archive>
 *
 * In particular, this program should be sufficient to extract the
 * distribution for libarchive, allowing people to bootstrap
 * libarchive on systems that do not already have a tar program.
 *
 * To unpack libarchive-x.y.z.tar.gz:
 *    * gunzip libarchive-x.y.z.tar.gz
 *    * untar libarchive-x.y.z.tar
 *
 * Written by Tim Kientzle, March 2009.
 *
 * Released into the public domain.
 */

/* These are all highly standard and portable headers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

typedef struct
{
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    unsigned char size[12];
    char mtime[12];
    char chksum[8];
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

typedef struct
{
    unsigned long int filesize;
    unsigned long int offset;
    char filename[512];
    short int type;
    unsigned char checksum[EVP_MAX_MD_SIZE];
    int mdLen;
} Record;

char MD5_EMPTY[] = "d41d8cd98f00b204e9800998ecf8427e";
char SHA1_EMPTY[] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
char SHA256_EMPTY[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
char SHA512_EMPTY[] = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
char *empty;

char TAR_MAGIC[] = "ustar ";
// Tape block size (/etc/opt/vsm/defaults:li_blksize = 2048). Aka "blocking factor".
//size_t TAR_REC_SZ = 2097152;
size_t TAR_REC_SZ = 4194304;
size_t TAR_BLK_SZ = 512;
size_t WRK_SZ = 8192;
//size_t WRK_SZ = 17384;
//size_t WRK_SZ = 32768;
// Assume tape unless stated otherwise.
short int isTape = 1;
unsigned long int filesize = 0;
const EVP_MD *md;
EVP_MD_CTX *ctx;

void parseFileSize(const unsigned char *p, size_t n)
{
        int i = 0;
	char *c;

	filesize = 0;
	//printf("parsing as 02x\n");
        //for (i=0; i<n; i++) printf("%02x", p[i]);
	//printf("\n");

	if (*p == 'x') {
	    //printf("size is in hex!!!!\n");
	    //15.9999TB > file size > 8G
	    c = (char *)malloc(n);
	    strncpy(c,p+1,(n-1));
	    c[11] = '\0';
	    filesize = strtol(c,NULL,16);
	} else if (*p & (0X01 << 7)) {
	    //file size > 8G
	    ++p;
	    for (i=1; i<n; i++) {
	        filesize *= 256;
		filesize += *p;
		++p;
	    }
	} else {
	    //file size <= 8G
	    for (i=0; i<12; i++) {
	        if ((0 == *p) || (' ' == *p)) {
		    ++p;
		    continue;
		}
		filesize *= 8;
		filesize += *p - '0';
		++p;
	    }
	}
	//printf("filesize = %llu\n",filesize);
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

/* Extract a tar archive. */
static void
untar(int fd, const char *path)
{
	unsigned long int total_bytes_read = 0;
	unsigned char *buffer;
	unsigned int current_byte = 0;
	unsigned int remaining_bytes = 0;
	char *fname;
	size_t bytes_read;
	size_t blocks_read;
	double blocks_to_advance = 0;
	short int state = 0;
	short int tar_end = 0;
	Record rec;
	int i = 0;

	// initialize Record struct var
        memset(rec.checksum, '\0', EVP_MAX_MD_SIZE);
	memset(rec.filename, '\0', 512);
	rec.mdLen = 0;
	rec.offset = 1;
	rec.type = 0;


	// LOOP 1
	// Read in 4096 512-byte blocks
	buffer = (unsigned char *) malloc(TAR_REC_SZ);

	if (!isTape)
	    posix_fadvise64(fd,0,TAR_REC_SZ*2,POSIX_FADV_WILLNEED);

	while ((bytes_read = read(fd,buffer,TAR_REC_SZ)) > 0)
	{

	    total_bytes_read += bytes_read;

	    if (bytes_read < TAR_BLK_SZ) {
		fprintf(stderr,
		    "Short read on %s: expected at least %d, got %d\n", path, (int)TAR_BLK_SZ, (int)bytes_read);
		return;
   	    }

	    current_byte = 0;
	    remaining_bytes = bytes_read;

	    // LOOP 2
	    while (current_byte < bytes_read)
	    {
//printf("state = %d  rec-type = %d  current_byte = %d  remaining_bytes = %d  filesize = %llu\n",state, rec.type,current_byte, remaining_bytes,filesize);
		switch (state) {
		    // expect new file header
		    case 0:
			    if ((rec.mdLen > 0) || (rec.type > 0)) {
			            // We have a record to print
				    printf("%d|%llu|%llu|",rec.type,rec.offset,rec.filesize);
				    if (rec.type == 0) {
					if (rec.filesize > 0)
				            for (i=0; i<rec.mdLen; i++) printf("%02x", rec.checksum[i]);
				        else 
					    printf("%s",empty); //for (i=0; i<rec.mdLen; i++) printf("00");
				    }
				    printf("|%s\n",rec.filename);
                                    memset(rec.checksum, '\0', EVP_MAX_MD_SIZE);
                                    memset(rec.filename, '\0', 512);
				    rec.filesize = 0;
				    rec.mdLen = 0;
				    rec.type = 0;
			    }
			    if (is_end_of_archive(buffer+current_byte)) {
				current_byte += 512;
				remaining_bytes -= 512;
				//printf("end of archive??\n");
				// if remaining bytes = 0, assume end of archive?
				if (remaining_bytes == 0) {
			            //printf("Total bytes read: %llu\n", total_bytes_read);
				    return;
				}
				continue;
			    }
			    // test for TAR_MAGIC; if no magic, skip -- assume filler
			    if (memcmp(buffer+(current_byte+257),TAR_MAGIC,5) != 0) {
				/*
			        printf("No magic found at byte %lu ; rec.type = %d ; rec.filename = %s\n", current_byte,rec.type,rec.filename);
				for (i=0;i<6;i++)
				    printf("%c",buffer+current_byte+257+i);
				printf("\n");
				*/
				current_byte += TAR_BLK_SZ;
				remaining_bytes -= TAR_BLK_SZ;
				continue;
			    }
		            if (!verify_checksum(buffer + current_byte)) {
			            fprintf(stderr, "Checksum failure\n");
			            return;
		            }
			    parseFileSize(buffer + current_byte + 124, 12);
//printf(">>>>> state = %d  rec-type = %d  current_byte = %d  remaining_bytes = %d  filesize = %llu\n",state, rec.type,current_byte, remaining_bytes,filesize);
			    rec.filesize = filesize;
			    rec.offset = ((total_bytes_read - bytes_read + current_byte)/TAR_BLK_SZ) + 1;
			    switch (buffer[current_byte+156]) {
		                    case '1':
			                    //printf(" Ignoring hardlink %s\n", buffer);
			        	    sprintf(rec.filename,"%s -> %s", buffer+current_byte, buffer+current_byte+157);
					    rec.type = 1;
			                    break;
			 	    case '2':
					    //printf(" Ignoring symlink %s\n", buffer);
			        	    sprintf(rec.filename,"%s -> %s", buffer+current_byte, buffer+current_byte+157);
					    rec.type = 2;
					    break;
				    case '3':
					    //printf(" Ignoring character device %s\n", buffer);
			        	    sprintf(rec.filename,"%s",buffer + current_byte);
					    rec.type = 3;
					    break;
				    case '4':
					    //printf(" Ignoring block device %s\n", buffer);
			        	    sprintf(rec.filename,"%s",buffer + current_byte);
					    rec.type = 4;
					    break;
				    case '5':
					    // Ignoring Directory
			        	    sprintf(rec.filename,"%s",buffer + current_byte);
					    rec.type = 5;
					    //printf(" Ignoring directory %s\n", buffer);
					    break;
				    case '6':
					    //printf(" Ignoring FIFO %s\n", buffer);
			        	    sprintf(rec.filename,"%s",buffer + current_byte);
					    rec.type = 6;
					    break;
				    case 'L':
					    //printf("Case L\n");
					    state = 1;
					    current_byte += TAR_BLK_SZ;
					    remaining_bytes -= TAR_BLK_SZ;
					    break;
				    default:
					    rec.type = 0;
			        	    sprintf(rec.filename,"%s",buffer + current_byte);

					    if (rec.filesize == 0) {
			    			EVP_DigestInit(ctx,md);
					        EVP_DigestUpdate(ctx, buffer+current_byte, rec.filesize);
				  	        EVP_DigestFinal(ctx, rec.checksum, &rec.mdLen);
						state = 0;
					    }
					    else {
					        state = 3;
						EVP_DigestInit(ctx,md);
					        current_byte += TAR_BLK_SZ;
					        remaining_bytes -= TAR_BLK_SZ;
					    }
//printf(">>>>> >>>>> state = %d  rec-type = %d  current_byte = %d  remaining_bytes = %d  mdlen = %d  filesize = %llu\n",state, rec.type,current_byte, remaining_bytes,rec.mdLen,filesize);
			 	   	    break;
			    }
			    // state STILL = 0
			    if (state == 0) {
			        // not reg file or extended header or zero-length regular file
				//printf("So, state = 0 and filesize = %llu\n", filesize);
				// assumes that this file (hardlink) won't span to next record
				if (filesize == 0)
				        filesize += TAR_BLK_SZ;
				blocks_to_advance = ceil((double)filesize/TAR_BLK_SZ);
				current_byte += (blocks_to_advance * TAR_BLK_SZ);
				remaining_bytes -= (blocks_to_advance * TAR_BLK_SZ);
				// state remains 0 -- we assume getting a regular header next?
			    }
		            break;
		    // expect extended header
		    case 1:
			    fname = rec.filename;
		            fname += sprintf(fname,"%s", buffer+current_byte);
			    current_byte += TAR_BLK_SZ;
			    remaining_bytes -= TAR_BLK_SZ;
			    // now look for header after extended header
			    state = 2;
		            break;
		    // header after extended header
		    case 2:
			    parseFileSize(buffer + current_byte + 124, 12);
			    rec.filesize = filesize;
			    rec.offset = ((total_bytes_read - bytes_read + current_byte)/TAR_BLK_SZ) + 1;
//printf(">>>>> STATE 2: state = %d  rec-type = %d  current_byte = %d  bytes_read = %d  remaining_bytes = %d  mdlen = %d  filesize = %llu\n",state, rec.type,current_byte,bytes_read, remaining_bytes,rec.mdLen,filesize);
			    switch(buffer[current_byte+156]) {
			        case '1':
				    rec.type = 1;
			            sprintf(fname, " -> %s", buffer+current_byte+157);
			            state = 0;
				    break;
			        case '2':
				    rec.type = 2;
			            sprintf(fname, " -> %s", buffer+current_byte+157);
			            state = 0;
				    break;
			        case '3':
				    rec.type = 3;
			            state = 0;
				    break;
			        case '4':
				    rec.type = 4;
			            state = 0;
				    break;
			        case '5':
				    rec.type = 5;
			            state = 0;
				    break;
			        case '6':
				    rec.type = 6;
			            state = 0;
				    break;
			        default:
				    rec.type = 0;
				    if (rec.filesize == 0) {
				        EVP_DigestInit(ctx,md);
					EVP_DigestUpdate(ctx, buffer+current_byte, rec.filesize);
					EVP_DigestFinal(ctx, rec.checksum, &rec.mdLen);
					state = 0;
				    }
				    else {
			                state = 3;
			                EVP_DigestInit(ctx,md);
				    }
				    break;
			    }
			    current_byte += TAR_BLK_SZ;
			    remaining_bytes -= TAR_BLK_SZ;
			    //state = 3;
			    //EVP_DigestInit(ctx,md);
		            break;
		    // Processing file payload 
		    case 3:
			    if (filesize <= WRK_SZ) {
			        if (filesize <= remaining_bytes) {
				    EVP_DigestUpdate(ctx, buffer+current_byte, filesize);
				    EVP_DigestFinal(ctx, rec.checksum, &rec.mdLen);
				    blocks_to_advance = ceil((double)filesize/TAR_BLK_SZ);
			            current_byte += (blocks_to_advance*512);
			            remaining_bytes -= (blocks_to_advance*512);
			            state = 0;
				}
				else {
				    EVP_DigestUpdate(ctx, buffer+current_byte, remaining_bytes);
				    filesize -= remaining_bytes;
				    current_byte = bytes_read;
				    state = 3;
				}
			    }
			    else {
			        if (remaining_bytes >= WRK_SZ) {
				    EVP_DigestUpdate(ctx, buffer+current_byte, WRK_SZ);
				    filesize -= WRK_SZ;
				    current_byte += WRK_SZ;
				    remaining_bytes -= WRK_SZ;
				    state = 3;
				}
				else {
				    EVP_DigestUpdate(ctx, buffer+current_byte, remaining_bytes);
				    filesize -= remaining_bytes;
				    current_byte = bytes_read;
				    state = 3;
				}
			    }
		            break;
		    // TAR END
		    case 5:
		            break;
		}
	    }
	    //free(buffer);
	    //buffer = (unsigned char *) malloc(TAR_REC_SZ);
	    memset(buffer, '\0', TAR_REC_SZ);
	    current_byte = 0;
	    if (!isTape) {
	        posix_fadvise64(fd,(total_bytes_read+TAR_REC_SZ),TAR_REC_SZ*2,POSIX_FADV_WILLNEED);
	        posix_fadvise64(fd,(total_bytes_read-TAR_REC_SZ),TAR_REC_SZ,POSIX_FADV_DONTNEED);
	    }
	}
	// print final record
        if (strlen(rec.filename) > 0) {
	    printf("%d|%llu|%llu|",rec.type,rec.offset,rec.filesize);
	    if (rec.type == 0) {
		if (rec.filesize > 0)
                    for (i=0; i<rec.mdLen; i++) printf("%02x", rec.checksum[i]);
		else
		    printf("%s",empty); //for (i=0; i<rec.mdLen; i++) printf("00");
	    }
	    printf("|%s\n",rec.filename);
	}

	free(buffer);

	//printf("\nTotal Bytes Read: %llu\n",total_bytes_read);
}

int
main(int argc, char **argv)
{
	int a;
	char *path;
	int errnum;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	++argv; /* Skip program name */
	if (*argv != NULL) { /* expecting tar file path */
	        path = (char *) malloc(strlen(*argv)+1);
		strncpy(path,*argv,(strlen(*argv)+1));
	}
	else {
	    return (1);
	}

	++argv; /* Skip to the checksum algorithm */
	if (*argv != NULL) {
	        if (strcmp(*argv,"MD5") == 0) {
		    md = EVP_get_digestbyname("MD5");
		    empty = MD5_EMPTY;
		}
		else if (strcmp(*argv,"SHA1") == 0) {
		    md = EVP_get_digestbyname("SHA1");
		    empty = SHA1_EMPTY;
		}
		else if (strcmp(*argv,"SHA256") == 0) {
		    md = EVP_get_digestbyname("SHA256");
		    empty = SHA256_EMPTY;
		}
		else if (strcmp(*argv,"SHA512") == 0) {
		    md = EVP_get_digestbyname("SHA512");
		    empty = SHA512_EMPTY;
		}
		else {
		    fprintf(stderr, "Invalid checksum algorithm %s\n", *argv);
		    return (1);
		}
	}
	else if (md == NULL) {
	    printf("Something went wrong because md is NULL!\n");
	    return (1);
	}
	else {
	    return (1);
	}

	++argv;
	if (*argv != NULL) {
	    if (strcmp(*argv,"DISK") == 0)
	        isTape = 0;
	}

	a = open(path, O_RDONLY);
	if (a < 0) {
	        fprintf(stderr, "Unable to open %s\n", path);
		return (1);
	}

	if (isTape) {
	    //size_t TAR_REC_SZ = 4194304;
	    //size_t WRK_SZ = 8192;
	    WRK_SZ = TAR_REC_SZ;
	}
	ctx = EVP_MD_CTX_create();
        untar(a, path);
	close(a);
	EVP_MD_CTX_destroy(ctx);

	return (0);
}
