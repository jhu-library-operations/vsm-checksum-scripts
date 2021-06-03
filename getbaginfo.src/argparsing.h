#include <error.h>
#include <argp.h>
#include <stdbool.h>

#define TAR "tar"
#define BAG "bag"
#define MANIFEST "manifest"
#define TAGMANIFEST "tagmanifest"
#define ALGORITHM "algorithm"
#define BAGINFO "baginfo"
#define BAGIT "bagit"

/* Program documentation. */
static char doc[] =
"mtbagcheck -- Calculate checksums on files within a 'tar' file.\n\
           -- Verify checksums in a 'bagit' file.";

/* A description of the arguments we accept. */
static char args_doc[] = "FILE";

/* The options we understand. */
static struct argp_option options[] = {
  {"mode",   'm', "MODE", 0, "tar | bag" },
  {"sam",   's', "SAM", 0, "SAM copy number to work with. Currently, only copy 1 is supported." },
  {"threads",   't', "NUM_THREADS", 0, "Number of threads to use in checksum processing." },
  {"wrapped",  'w', "OFFSET", 0, "Tar file we're after is wrapped in another tar at specified offset." },
  {"fast",  'f', 0, 0,  "If this is a bag, do a fast verify based only on payload-oxum." },
  {"verbose",  'v', 0, 0,  "If this is a bag, print out file details while comparing checksums." },
  {"empties",  'e', 0, 0,  "If this is a bag, print out list of empty files if there are any." },
  {"algo",   'a', "ALGORITHM", 0, "md5 | sha1 | sha256 | sha512" },
  {"get",   'g', "BAG-FILE", 0, "manifest | tagmanifest | algorithm | baginfo" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *mode;
  char *get;
  char *file;
  char *algo;
  bool wrapped;
  bool fast;
  bool verbose;
  bool empties;
  int n_threads;
  int sam_copy;
  size_t offset;
};

error_t parse_opt (int key, char *arg, struct argp_state *state);
void parse_arguments(int argc, char **argv, struct arguments *arguments);

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };
