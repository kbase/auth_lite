#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "bstrlib.h"
#include "json.h"
#include "iniparser.h"

#include "kb-common.h"

static void handle_setup(CURL *curl)
{
//    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1); 
}

static size_t save_incoming_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    bcatblk(userdata, ptr, size * nmemb);
    return size * nmemb;
}

void invalid()
{
    fprintf(stderr, "Invalid\n");
    exit(1);
}


void authenticate(bstring user, bstring pass)
{
    CURL *curl = curl_easy_init();

    handle_setup(curl);

    bstring auth = bstrcpy(user);
    bcatcstr(auth, ":");
    bconcat(auth, pass);
    
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERPWD, auth->data);

    bstring url = bfromcstr(GLOBUS_URL);
    bcatcstr(url, AUTHORIZE_PATH);
    bcatcstr(url, "?grant_type=client_credentials&client_id=");
    bconcat(url, user);

    curl_easy_setopt(curl, CURLOPT_URL, url->data);

    bstring result = bfromcstr("");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, save_incoming_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, result);

    bstring error = bfromcstralloc(CURL_ERROR_SIZE, "");
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, bdata(error));
    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK)
    {
	fprintf(stderr, "Error obtaining token: %s\n", bdata(error));
	exit(1);
    }

    long response_code;
    rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (rc != CURLE_OK)
    {
	fprintf(stderr, "Error obtaining response code\n");
	exit(1);
    }
    if (response_code == 403)
    {
	fprintf(stderr, "Permission denied.\n");
	exit(1);
    }
    if (response_code >= 300)
    {
	fprintf(stderr, "Invalid response code %ld from server\n", response_code);
	exit(1);
    }
    
    // printf("rc=%d '%s'\n", rc, result->data);
	 
    curl_easy_cleanup(curl);
    curl = 0;
    bdestroy(error);
    bdestroy(auth);
    bdestroy(url);

    json_settings settings = { 0 } ;
    char json_error[json_error_max + 1];
    json_value *ret = json_parse_ex(&settings, bdata(result), blength(result), json_error);

    if (ret->type != json_object)
	invalid();
    int i;
    char *token = 0;
    char *username = 0;
    for (i = 0; i < ret->u.object.length; i++)
    {
	if (strcmp(ret->u.object.values[i].name, "access_token") == 0)
	{
	    json_value *t = ret->u.object.values[i].value;
	    token = t->u.string.ptr;
	}
	else if (strcmp(ret->u.object.values[i].name, "user_name") == 0)
	{
	    json_value *t = ret->u.object.values[i].value;
	    username = t->u.string.ptr;
	}
    }

    update_config(token, username);

    json_value_free(ret);
    bdestroy(result);
}


void usage()
{
    fprintf(stderr, "Usage: kb-login [--password password] username\n");
    exit(1);
}    


int main(int argc, char **argv)
{
    bstring user = 0;
    bstring pass = 0;

    static struct option long_options[] = {
	{ "password", 1, 0, 'p' },
	{ "help", 1, 0, 'h' },
	{ 0, 0, 0, 0 }
    };

    while (1)
    {
	int option_index = 0;

	int c = getopt_long (argc, argv, "p:h",
			     long_options, &option_index);
	if (c == -1)
	    break;

	switch (c)
	{
	case 'p':
	    pass = bfromcstr(optarg);
	    break;

	case 'h':
	    usage();
	    break;
	}
    }

    int nargs = argc - optind;
    if (nargs != 1)
    {
	usage();
    }

    user = bfromcstr(argv[optind]);

    if (pass == 0)
    {
	char *p = getpass("Password: ");
	pass = bfromcstr(p);
    }

    authenticate(user, pass);

    bdestroy(user);
    bdestroy(pass);

    return 0;
}

