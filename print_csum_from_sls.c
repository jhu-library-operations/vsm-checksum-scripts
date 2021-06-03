/* Taken from
 * https://www.lemoda.net/c/recursive-directory/
 *
 * gcc -o print_csum_from_sls print_csum_from_sls.c -L /opt/vsm/lib -lsam -lssl -lvsm
 */

/*
 * Output:
 * typeflag | checksum                       | dk path     |pos|offset |size| filename
 * 0|4eb82199c1d1a18262703db5a40d58d8bca24dd0|DKARC19/d2/f4|516|1101788|4303|/sam2/hamletcollection/Hamlet/filemap.csv
 *
 *                                            copy 2    hexpos|o  copy 3   hexpos|off  size  filename
 * 0|1b21f40c95e506abb717f50d5ee64e8986c11fea|li.A00041|228879|d|li.B00049|35452|2327c|404|/sam2/dlmm/config.properties
 *
 * typflag:
 * 0 - regular file
 * 1 - directory
 * 2 - link
 */

#include <stdlib.h>
/* #include <sqlite3.h> */
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
/* "readdir" etc. are defined here. */
#include <dirent.h>
/* limits.h defines "PATH_MAX". */
#include <limits.h>
#include "vsm/stat.h"
#include <vsm/diskvols.h>
#include "/opt/vsm/include/lib.h"

enum vsmcopy{dk,liA,liB,s3};
enum inotype{file,dir,links,other};

/* Global variables */

off_t t_size=0; /* bytes */
int n_inos[4] = {0,0,0,0};
int copy;
/* Global variables */

static void list_dir (const char * dir_name) {
    DIR * d;
    char * subdir;

    /* Open the directory specified by "dir_name". */

    d = opendir (dir_name);

    /* Check it was opened. */
    if (! d) {
        fprintf (stderr, "Cannot open directory '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
    while (1) {
        struct dirent * entry;
        const char * d_name;
	int path_length;
	char path[PATH_MAX];
	int i;
	struct sam_stat sb;
	struct sam_checksum csum;
	char dkname[256];
	short int type;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir (d);
        if (! entry) {
            /* There are no more entries in this directory, so break
               out of the while loop. */
            break;
        }
        d_name = entry->d_name;

	//printf("%s/%s\n",dir_name,d_name);

	/* Do we really need to check path length? */
	path_length = snprintf (path, PATH_MAX, "%s/%s", dir_name, d_name);
	if (path_length >= PATH_MAX) {
	    fprintf (stderr, "Path length exceeds PATH_MAX!\n");
	    exit (EXIT_FAILURE);
	}

	if (sam_lstat(path, &sb, sizeof(sb)) < 0 ) {
	    perror("sam stat");
	    exit(1);
	}


	// If this is a file or link, print out ino metadata
	if (S_ISLNK(sb.st_mode)) {
	    n_inos[links]++;
	    type=2;
	}
	else if (S_ISREG(sb.st_mode)) {
	    n_inos[file]++;
	    type=0;
        }
        else if (S_ISDIR(sb.st_mode)) {
	    type=1;
            /* Check that the directory is not "d" or d's parent. */
            if (strcmp (d_name, "..") != 0 && strcmp (d_name, ".") != 0) {
                int path_length;
                char path[PATH_MAX];
 
	        n_inos[dir]++;
                path_length = snprintf (path, PATH_MAX, "%s/%s", dir_name, d_name);
                if (path_length >= PATH_MAX) {
                    fprintf (stderr, "Path length exceeds PATH_MAX!\n");
                    exit (EXIT_FAILURE);
                }
                /* Recursively call "list_dir" with the new path. */
                list_dir (path);
            }
	}
	else {
	    n_inos[other]++;
	    type=3;
	}
	if (type == 0) {
            // grab checksum struct
            if (sam_checksum(path, &csum, sizeof(csum)) < 0) {
                //perror("sam checksum");
                //exit(1);
	        printf("%d|",type);
	        printf("NO_CKSUM_IN_INODE");
            }
	    else {
	        printf("%d|",type);
	        if (csum.cs_nchars == 0)
	            printf("NO_CKSUM_IN_INODE");
	        else
	            for (i=0; i<csum.cs_nchars; i++) printf("%02x",csum.cs_csum[i]);
	        csum.cs_nchars = 0;
            }
	    if (copy == dk) {
	        DiskVolsGenFileName(sb.copy[dk].position, &dkname[0], 256);
	        printf("|%s/%s|%" PRIu64 "|%" PRIu64 "|%ld|%s\n",sb.copy[dk].vsn,dkname,sb.copy[dk].position,sb.copy[dk].offset/512,sb.st_size,path);
	    }
	    else {
	        printf("|%s.%s|%" PRIx64 "|%" PRIx64, sb.copy[liA].media, sb.copy[liA].vsn,sb.copy[liA].position,sb.copy[liA].offset/512);
	        printf("|%s.%s|%" PRIx64 "|%" PRIx64 "|%ld|%s\n",sb.copy[liB].media, sb.copy[liB].vsn,sb.copy[liB].position,sb.copy[liB].offset/512,sb.st_size,path);
	    }
	}
	else if (type == 2) {
	    printf("%d|",type);
	    if (copy == dk) {
	        DiskVolsGenFileName(sb.copy[dk].position, &dkname[0], 256);
	        printf("|%s/%s|%" PRIu64 "|%" PRIu64 "|%ld|%s\n",sb.copy[dk].vsn,dkname,sb.copy[dk].position,sb.copy[dk].offset/512,sb.st_size,path);
	    }
	    else {
	        printf("|%s.%s|%" PRIx64 "|%" PRIx64, sb.copy[liA].media, sb.copy[liA].vsn,sb.copy[liA].position,sb.copy[liA].offset/512);
	        printf("|%s.%s|%" PRIx64 "|%" PRIx64 "|%ld|%s\n",sb.copy[liB].media, sb.copy[liB].vsn,sb.copy[liB].position,sb.copy[liB].offset/512,sb.st_size,path);
	    }
	}
    }
    /* After going through all the entries, close the directory. */
    if (closedir (d)) {
        fprintf (stderr, "Could not close '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
}

int main (int argc, char** argv)
{
    struct stat myFile;
    int path_length;
    char path[PATH_MAX];
    time_t time=0;
    int i;
    char *endptr;
    char *progname;

    path_length = snprintf (path, PATH_MAX, "%s", argv[1]);

    copy=dk;
    // Determine how we're called
    progname = strrchr(argv[0], '/');

    if( progname == NULL ) {
        progname = argv[0];
    }
    else
        progname++;
printf("progname = %s\n",progname);
    if (strcmp(progname, "print_csum_li_from_sls") == 0)
        copy=liA;
    else if (strcmp(progname, "print_csum_dk_from_sls") == 0)
        copy=dk;

    if (path_length >= PATH_MAX) {
        fprintf (stderr, "Path length exceeds PATH_MAX!\n");
	exit (EXIT_FAILURE);
    }

    /* remove trailing slash if exists */
    if (path[strlen(path) - 1] == '/') {
        path[strlen(path) - 1] = 0;
    }

    /* check if exists and is directory */
    if (stat(path, &myFile) < 0) {
        // Doesn't exist
        fprintf (stderr, "%s Does not exist: %s\n", path, strerror (errno));
        exit (EXIT_FAILURE);
    }
    else if (!S_ISDIR(myFile.st_mode)) {
        // Exists but is not a directory
        fprintf (stderr, "%s is not a directory: %s\n", path, strerror (errno));
        exit (EXIT_FAILURE);
    }

    n_inos[dir]++;

    /* walk directory and gather info */
    list_dir (path);

    /* print out report */

    return 0;
}
