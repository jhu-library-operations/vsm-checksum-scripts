#include <stdlib.h>
#include "./argparsing.h"
#include "./boringssl/include/openssl/nid.h"

const char *argp_program_version = "mtbagcheck 0.1a";
const char *argp_program_bug_address = "<gara@jhu.edu>";

/* Parse a single option. */
error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'm':
      if (strcmp(arg,"tar") == 0)
          arguments->mode = TAR;
      else if (strcmp(arg,"bag") == 0)
          arguments->mode = BAG;
      else /* default */
          argp_usage (state);
      break;
    case 'g':
      if (strcmp(arg,"manifest") == 0)
          arguments->get = MANIFEST;
      else if (strcmp(arg,"tagmanifest") == 0)
          arguments->get = TAGMANIFEST;
      else if (strcmp(arg,"algorithm") == 0)
          arguments->get = ALGORITHM;
      else if (strcmp(arg,"baginfo") == 0)
          arguments->get = BAGINFO;
      else if (strcmp(arg,"bagit") == 0)
          arguments->get = BAGIT;
      break;
    case 'f':
        arguments->fast = true;
	break;
    case 'v':
        arguments->verbose = true;
	break;
    case 'e':
        arguments->empties = true;
	break;
    case 'w':
        arguments->offset = (size_t)strtol(arg,NULL,10);;
        arguments->wrapped = true;
	if (arguments->offset <= 0) {
	    printf("For the wrapped case (tar in tar), offset must be 1 or greater.\n");
	    argp_usage(state);
	}
	break;
    case 's':
	arguments->sam_copy = (int)strtol(arg,NULL,10);
	if (arguments->sam_copy != 1) {
	    printf("%d not supported. Only SAM copy 1 is supported at this time.\n", arguments->sam_copy);
	    exit(1);
	}
        break;
    case 't':
	arguments->n_threads = (int)strtol(arg,NULL,10);
	if ( (arguments->n_threads < 1) || (arguments->n_threads > 20) ) {
	    printf("Number of threads (%d) is out of range (1-20).\n", arguments->n_threads);
	    exit(1);
	}
        break;
    case 'a':
      if (strcasecmp(arg,SN_md5) == 0)
          arguments->algo = SN_md5;
      else if (strcasecmp(arg,SN_sha1) == 0)
          arguments->algo = SN_sha1;
      else if (strcasecmp(arg,SN_sha256) == 0)
          arguments->algo = SN_sha256;
      else if (strcasecmp(arg,SN_sha512) == 0)
          arguments->algo = SN_sha512;
      else
          argp_usage (state);
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= 1) /* Too many arguments. */
        argp_usage (state);
      //arguments->args[state->arg_num] = arg;
      arguments->file = arg;
      break;

    case ARGP_KEY_END:
      if (strcmp(arguments->file, "-") == 0)
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

void parse_arguments(int argc, char **argv, struct arguments *arguments)
{
        /* Default CLI argument values. */
        arguments->file = "-";
        arguments->mode = TAR;
        arguments->get = 0;
        arguments->algo = SN_md5;
	arguments->n_threads = 1;
	arguments->fast = false;
	arguments->verbose = false;
	arguments->empties = false;
	arguments->sam_copy = 0;
	arguments->offset = 0;
	arguments->wrapped = false;

	/* Parse our CLI arguments; every option seen by parse_opt will
         * be reflected in arguments.
         */

	argp_parse (&argp, argc, argv, 0, 0, arguments);
	if ( (arguments->get != NULL) && (arguments->mode == TAR) ) {
	    printf("-g (--get=) option only makes sense with 'bag' mode.\n\n");
	    exit(1);
	}

	if ( (arguments->fast) && (arguments->mode == TAR) ) {
	    printf("-f (--fast) option only makes sense with 'bag' mode.\n\n");
	    exit(1);
	}

        //printf ("File: %s\nMODE: %s\nAlgo: %s\nGet: %s\nN_Threads: %d\n", arguments->file, arguments->mode, arguments->algo, arguments->get,arguments->n_threads);
}
