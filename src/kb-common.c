#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "dictionary.h"
#include "iniparser.h"
#include "bstrlib.h"

bstring locate_config_file()
{
    /*
     * Find the config file in $HOME/.kbase_config
     */
    char *h = getenv("HOME");
    if (!h)
    {
	fprintf(stderr, "home not found in env\n");
	return 0;
    }
    bstring home = bfromcstr(h);
    bcatcstr(home, "/.kbase_config");

    return home;
}

void update_config(char *token, char *username)
{
    bstring file = locate_config_file();

    bstring tmp = bstrcpy(file);
    bcatcstr(tmp, ".tmp_XXXXXX");

    int fd = mkstemp((char *) tmp->data);
    if (fd < 0)
    {
	perror("mkstemp");
	exit(1);
    }
    FILE *fp = fdopen(fd, "w");
    if (fp == 0)
    {
	perror("fdopen");
	exit(1);
    }

    dictionary *config;

    struct stat statbuf;
    int rc = stat((char *) file->data, &statbuf);
    if (rc < 0 || statbuf.st_size == 0)
    {
	/* create a new empty dictionary */
	config = dictionary_new(0);
	dictionary_set(config, "authentication", 0);
    }
    else
    {
	config = iniparser_load(bdata(file));
    }

    iniparser_set(config, "authentication:token", token);
    if (username)
	iniparser_set(config, "authentication:user_id", username);
    iniparser_dump_ini(config, fp);

    iniparser_freedict(config);

    fclose(fp);

    if (rename(bdata(tmp), bdata(file)) < 0)
    {
	fprintf(stderr, "Error rename %s to %s: %s\n",
		bdata(tmp), bdata(file), strerror(errno));
	exit(1);
    }

    bdestroy(tmp);
    bdestroy(file);
}

