#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <curl/curl.h>
#include "json.h"
#include "dictionary.h"
#include "iniparser.h"
#include "bstrlib.h"

#include "kb-common.h"

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

bstring get_token_from_config_file()
{
    bstring config_file = locate_config_file();
    
    dictionary *config;

    struct stat statbuf;
    int rc = stat((char *) config_file->data, &statbuf);
    if (rc < 0 || statbuf.st_size == 0)
    {
	bdestroy(config_file);
	return 0;
    }
    else
    {
	config = iniparser_load(bdata(config_file));
    }

    char *token = iniparser_getstring(config, "authentication:token", 0);

    bdestroy(config_file);

    bstring ret = 0;
    if (token)
    {
	ret = bfromcstr(token);
    }

    iniparser_freedict(config);

    return ret;
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

int validate_token(bstring token)
{
    int i;

    OpenSSL_add_all_algorithms();

    struct bstrList *parts = bsplit(token, '|');

    dictionary *dict = dictionary_new(10);

    bstring sig = bfromcstr("sig");
    bstring to_sign = bfromcstr("");
    
    for (i = 0; i < parts->qty; i++)
    {
	printf("%d: %s\n", i, parts->entry[i]->data);

	struct bstrList *x = bsplit(parts->entry[i], '=');
	if (x->qty == 2)
	{
	    if (bstrcmp(x->entry[0], sig) != 0)
	    {
		if (blength(to_sign) > 0)
		    bconchar(to_sign, '|');
		bconcat(to_sign, parts->entry[i]);
	    }
	    dictionary_set(dict, bdata(x->entry[0]), bdata(x->entry[1]));
	}
    }
    dictionary_dump(dict, stdout);
    printf("to sign: '%s'\n", bdata(to_sign));

    // Check signing subject (need to know the valid values)

    char *subj = dictionary_get(dict, "SigningSubject", 0);
    if (!subj)
    {
	fprintf(stderr, "could not get signing subject\n");
	return 0;
    }

    char *sigstr = dictionary_get(dict, "sig", 0);
    printf("sig to verify is %s\n", sigstr);

    bstring binsig = bfromcstralloc(strlen(sigstr) / 2, "");
    char *s, *e;
    for (s = sigstr, e = sigstr + strlen(sigstr); s < e; s += 2)
    {
	char n[3];
	n[0] = s[0];
	n[1] = s[1];
	n[2] = 0;
	long int v = strtol(n, 0, 16);
//	printf("n=%s v=%ld %lx\n", n, v, v);
	bconchar(binsig, (char) v);
    }

    unsigned char *sha = SHA1((const unsigned char *) to_sign->data, to_sign->slen, 0);

    bstring bsubj = bfromcstr(subj);
    bstring pubkey = get_signer_pubkey(bsubj);

    BIO *bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, bdata(pubkey));

    RSA *rsa = PEM_read_bio_RSAPublicKey(bio, 0, 0, 0);

    int rc = RSA_verify(NID_sha1, sha, SHA_DIGEST_LENGTH, binsig->data, binsig->slen, rsa);
    printf("rc=%d\n", rc);

    return rc;
}

static size_t save_incoming_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    bcatblk(userdata, ptr, size * nmemb);
    return size * nmemb;
}

bstring get_signer_pubkey(bstring url)
{
    CURL *curl = curl_easy_init();

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
	return 0;
    }
    if (response_code == 403)
    {
	fprintf(stderr, "Permission denied.\n");
	return 0;
    }
    if (response_code >= 300)
    {
	fprintf(stderr, "Invalid response code %ld from server\n", response_code);
	return 0;
    }
    
    // printf("rc=%d '%s'\n", rc, result->data);
	 
    curl_easy_cleanup(curl);
    curl = 0;
    bdestroy(error);

    json_settings settings = { 0 } ;
    char json_error[json_error_max + 1];
    json_value *ret = json_parse_ex(&settings, bdata(result), blength(result), json_error);

    if (ret->type != json_object)
	return 0;
    
    int i;
    bstring pubkey = 0;
    for (i = 0; i < ret->u.object.length; i++)
    {
	if (strcmp(ret->u.object.values[i].name, "pubkey") == 0)
	{
	    json_value *t = ret->u.object.values[i].value;
	    pubkey = bfromcstr(t->u.string.ptr);
	}
    }

    json_value_free(ret);

    bdestroy(result);
    return pubkey;
}
