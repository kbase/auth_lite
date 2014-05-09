#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include "bstrlib.h"
#include "json.h"
#include "iniparser.h"

#include "kb-common.h"

void usage()
{
    fprintf(stderr, "Usage: kb-logout\n");
    exit(1);
}    

int main(int argc, char **argv)
{
    static struct option long_options[] = {
	{ "help", 1, 0, 'h' },
	{ 0, 0, 0, 0 }
    };

    while (1)
    {
	int option_index = 0;

	int c = getopt_long (argc, argv, "h",
			     long_options, &option_index);
	if (c == -1)
	    break;

	switch (c)
	{
	case 'h':
	    usage();
	    break;
	}
    }

    int nargs = argc - optind;
    if (nargs != 0)
    {
	usage();
    }

    bstring token = get_token_from_config_file();
    validate_token(token);
    bdestroy(token);

    return 0;
}

