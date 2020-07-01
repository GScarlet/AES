#ifndef AES__H
#define AES__H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> 

typedef unsigned char uchar;

/* -------------- VARIABLES GLOBALES -------*/
  
extern uchar InvSBox[256];

extern uchar blocNul[16];

extern uchar Inv[16];


/* ----------------- UTILS -----------------*/

uchar gmul(uchar a, uchar b);

void affiche_bloc_matriciel(uchar *M);


/* -------------METHODES CHIFFRAGES --------*/
  
void Chiffrage (uchar* bloc, uchar* clef, int keyLength);

void chiffrer(uchar* bloc, uchar* Key, int Nr);

void SubBytes(uchar* bloc);

void AddRoundKey(uchar* bloc, uchar* Key, int r);

void ShiftRows(uchar* bloc);

void MixColumns(uchar* bloc);


/* ------------METHODES DECHIFFRAGES -------*/

void Dechiffrage (uchar* bloc, uchar* clef, int keyLength);

void dechiffrer(uchar* bloc, uchar* Key, int Nr);

void Inv_SubBytes(uchar* bloc);

void Inv_ShiftRows(uchar* bloc);

void Inv_MixColumns(uchar* bloc);


#endif
