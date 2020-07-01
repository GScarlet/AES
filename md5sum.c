// -*- coding: utf-8 -*-


#include "md5sum.h"

/* variable globale pour les autres méthodes */
uchar clef[16];

void StringToMd5(char* mdp)
{
  int i;
  uchar resume_md5[MD5_DIGEST_LENGTH];
  
  MD5_CTX contexte;
  MD5_Init(&contexte); // Initialisation de la fonction de hachage
  MD5_Update(&contexte, mdp, 16);                    // Digestion du morceau
  MD5_Final(resume_md5, &contexte);
  printf("La clef utilisé est: 0x");
  for(i = 0; i < MD5_DIGEST_LENGTH; i++){
  	 printf("%02x", resume_md5[i]);
  	 clef[i] = resume_md5[i] ;
  }
  printf("\n");
  
}

