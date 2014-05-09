#ifndef _KB_COMMON_H
#define _KB_COMMON_H

extern bstring locate_config_file();
extern void update_config(char *token, char *username);

#define GLOBUS_URL "https://nexus.api.globusonline.org"
#define AUTHORIZE_PATH "/goauth/token"


#endif
