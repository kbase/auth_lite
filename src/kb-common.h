#ifndef _KB_COMMON_H
#define _KB_COMMON_H

extern bstring locate_config_file();
extern void update_config(char *token, char *username);
extern bstring get_token_from_config_file();
extern int validate_token(bstring token);
extern bstring get_signer_pubkey(bstring url);

#define GLOBUS_URL "https://nexus.api.globusonline.org"
#define AUTHORIZE_PATH "/goauth/token"


#endif
