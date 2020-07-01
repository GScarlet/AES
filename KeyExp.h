// -*- coding: utf-8 -*-
#ifndef KEYEXP__H
#define KEYEXP__H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char uchar;

/*----------------- VARIABLES GLOBALES -------------*/

extern uchar clefNulle[16];

extern uchar* clefEtendue;
  
extern uchar SBoxKE[256];

extern uchar RconKE[10];


/*------------------- UTILS ----------------------*/

void affiche_la_clef(uchar *clef, int longueur);

int howManyWords(int keyL);

int howManyRound(int keyL);


/*----------------METHODES D'EXPENSION DE CLEF------*/

void RotWord(uchar *W,int indice);

void SubWord(uchar *W,int indice);

void calcule_la_clef_etendue(uchar *K, int long_K, uchar *W, int long_W, int Nr, int Nk);

uchar* KeyExpansion (uchar *Key, int keyLength);


#endif
