#ifndef MD5__H
#define MD5__H

#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <string.h>

typedef unsigned char uchar; // Les octets sont non-signés.

extern uchar clef[16];

void StringToMd5(char* mdp);


#endif
