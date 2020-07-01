// -*- coding: utf-8 -*-
#include "aesC.h"
#include "KeyExp.h"

/* -------------- VARIABLES GLOBALES -----------------------*/

uchar blocNul[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00 };

uchar Inv[16] = { 
	0x0E,0x0B,0x0D,0x09,
	0x09,0x0E,0x0B,0x0D,
	0x0D,0x09,0x0E,0x0B,
	0x0B,0x0D,0x09,0x0E };

uchar InvSBox[256];


/* ----------------- UTILS ----------------------------------*/

/* Fonction mystérieuse qui calcule le produit de deux octets */
uchar gmul(uchar a, uchar b) {
  uchar p = 0;
  uchar hi_bit_set;
  int i;
  for(i = 0; i < 8; i++) {
    if((b & 1) == 1) 
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if(hi_bit_set == 0x80) 
      a ^= 0x1b;		
    b >>= 1;
  }
  return p;
}

void affiche_bloc_matriciel(uchar *M) {
  
  printf("0x");
  for(int i = 0; i<16; i++)
      printf ("%02X", M[i] & 255);
  
  printf("\n");
}


/* -------------METHODES CHIFFRAGES ----------------------------------*/

void SubBytes(uchar* bloc){

	for(int i=0;i<16;i++)
		bloc[i] = SBoxKE[bloc[i]];
}

/* Codage "brutal", mais très efficace pour debugguer */
void ShiftRows(uchar* bloc){
	
	uchar tmp = bloc[1];
	
	bloc[1] = bloc[5];
	bloc[5] = bloc[9];
	bloc[9] = bloc[13];
	bloc[13] = tmp;
	
	tmp = bloc[2];
	uchar tmp2 = bloc[6];
	
	bloc[2] = bloc[10];
	bloc[6] = bloc[14];
	bloc[10] = tmp;
	bloc[14] = tmp2;
	
	tmp = bloc[15];

	bloc[15] = bloc[11];
	bloc[11] = bloc[7];
	bloc[7] = bloc[3];
	bloc[3] = tmp;
	
}


/* Codage "brutal", mais très efficace pour debugguer */
void MixColumns(uchar* bloc){
	
	uchar Tampbloc[16];
	for(int i=0;i<16;i++)
		Tampbloc[i] = bloc[i];
	
	bloc[0] = gmul(0x02,Tampbloc[0])^gmul(0x03,Tampbloc[1])^gmul(0x01,Tampbloc[2])^gmul(0x01,Tampbloc[3]);
	bloc[1] = gmul(0x01,Tampbloc[0])^gmul(0x02,Tampbloc[1])^gmul(0x03,Tampbloc[2])^gmul(0x01,Tampbloc[3]);
	bloc[2] = gmul(0x01,Tampbloc[0])^gmul(0x01,Tampbloc[1])^gmul(0x02,Tampbloc[2])^gmul(0x03,Tampbloc[3]);
	bloc[3] = gmul(0x03,Tampbloc[0])^gmul(0x01,Tampbloc[1])^gmul(0x01,Tampbloc[2])^gmul(0x02,Tampbloc[3]);
	
	bloc[4] = gmul(0x02,Tampbloc[4])^gmul(0x03,Tampbloc[5])^gmul(0x01,Tampbloc[6])^gmul(0x01,Tampbloc[7]);
	bloc[5] = gmul(0x01,Tampbloc[4])^gmul(0x02,Tampbloc[5])^gmul(0x03,Tampbloc[6])^gmul(0x01,Tampbloc[7]);
	bloc[6] = gmul(0x01,Tampbloc[4])^gmul(0x01,Tampbloc[5])^gmul(0x02,Tampbloc[6])^gmul(0x03,Tampbloc[7]);
	bloc[7] = gmul(0x03,Tampbloc[4])^gmul(0x01,Tampbloc[5])^gmul(0x01,Tampbloc[6])^gmul(0x02,Tampbloc[7]);
	
	bloc[8] = gmul(0x02,Tampbloc[8])^gmul(0x03,Tampbloc[9])^gmul(0x01,Tampbloc[10])^gmul(0x01,Tampbloc[11]);
	bloc[9] = gmul(0x01,Tampbloc[8])^gmul(0x02,Tampbloc[9])^gmul(0x03,Tampbloc[10])^gmul(0x01,Tampbloc[11]);
	bloc[10] = gmul(0x01,Tampbloc[8])^gmul(0x01,Tampbloc[9])^gmul(0x02,Tampbloc[10])^gmul(0x03,Tampbloc[11]);
	bloc[11] = gmul(0x03,Tampbloc[8])^gmul(0x01,Tampbloc[9])^gmul(0x01,Tampbloc[10])^gmul(0x02,Tampbloc[11]);
	
	bloc[12] = gmul(0x02,Tampbloc[12])^gmul(0x03,Tampbloc[13])^gmul(0x01,Tampbloc[14])^gmul(0x01,Tampbloc[15]);
	bloc[13] = gmul(0x01,Tampbloc[12])^gmul(0x02,Tampbloc[13])^gmul(0x03,Tampbloc[14])^gmul(0x01,Tampbloc[15]);
	bloc[14] = gmul(0x01,Tampbloc[12])^gmul(0x01,Tampbloc[13])^gmul(0x02,Tampbloc[14])^gmul(0x03,Tampbloc[15]);
	bloc[15] = gmul(0x03,Tampbloc[12])^gmul(0x01,Tampbloc[13])^gmul(0x01,Tampbloc[14])^gmul(0x02,Tampbloc[15]);
		
}

void AddRoundKey(uchar* bloc, uchar* Key, int r){
	
	int index = r*4*4;
	
	for(int i=0; i<16 ; i++)
		bloc[i] = bloc[i] ^ Key[index+i];
	
}

void chiffrer(uchar* bloc, uchar* Key, int Nr){
  int i;
  AddRoundKey(bloc,Key,0);
  
  for (i = 1; i < Nr; i++) {
    SubBytes(bloc);
    ShiftRows(bloc);
    MixColumns(bloc);
    AddRoundKey(bloc,Key,i);
  }
  SubBytes(bloc);
  ShiftRows(bloc);
  AddRoundKey(bloc,Key,Nr);

}

void Chiffrage (uchar* bloc, uchar* clef, int keyLength) {

  int Nr = howManyRound(keyLength);
  
  uchar* W = KeyExpansion(clef,keyLength);
  
  chiffrer(bloc,W,Nr);
  
}


/* ------------METHODES DECHIFFRAGES -----------------------------*/


/* Codage "brutal", mais très efficace pour debugguer */
void Inv_ShiftRows(uchar* bloc){
	uchar tmp = bloc[13];
	
	bloc[13] = bloc[9];
	bloc[9] = bloc[5];
	bloc[5] = bloc[1];
	bloc[1] = tmp;
	
	tmp = bloc[14];
	uchar tmp2 = bloc[10];
	
	bloc[10] = bloc[2];
	bloc[14] = bloc[6];
	bloc[6] = tmp;
	bloc[2] = tmp2;
	
	tmp = bloc[3];

	bloc[3] = bloc[7];
	bloc[7] = bloc[11];
	bloc[11] = bloc[15];
	bloc[15] = tmp;
}


/* Codage "brutal", mais très efficace pour debugguer */
void Inv_MixColumns(uchar* bloc){
	
	uchar Tampbloc[16];
	for(int i=0;i<16;i++)
		Tampbloc[i] = bloc[i];
		
	bloc[0] = gmul(Inv[0],Tampbloc[0])^gmul(Inv[1],Tampbloc[1])^gmul(Inv[2],Tampbloc[2])^gmul(Inv[3],Tampbloc[3]);
	bloc[1] = gmul(Inv[4],Tampbloc[0])^gmul(Inv[5],Tampbloc[1])^gmul(Inv[6],Tampbloc[2])^gmul(Inv[7],Tampbloc[3]);
	bloc[2] = gmul(Inv[8],Tampbloc[0])^gmul(Inv[9],Tampbloc[1])^gmul(Inv[10],Tampbloc[2])^gmul(Inv[11],Tampbloc[3]);
	bloc[3] = gmul(Inv[12],Tampbloc[0])^gmul(Inv[13],Tampbloc[1])^gmul(Inv[14],Tampbloc[2])^gmul(Inv[15],Tampbloc[3]);
	
	bloc[4] = gmul(Inv[0],Tampbloc[4])^gmul(Inv[1],Tampbloc[5])^gmul(Inv[2],Tampbloc[6])^gmul(Inv[3],Tampbloc[7]);
	bloc[5] = gmul(Inv[4],Tampbloc[4])^gmul(Inv[5],Tampbloc[5])^gmul(Inv[6],Tampbloc[6])^gmul(Inv[7],Tampbloc[7]);
	bloc[6] = gmul(Inv[8],Tampbloc[4])^gmul(Inv[9],Tampbloc[5])^gmul(Inv[10],Tampbloc[6])^gmul(Inv[11],Tampbloc[7]);
	bloc[7] = gmul(Inv[12],Tampbloc[4])^gmul(Inv[13],Tampbloc[5])^gmul(Inv[14],Tampbloc[6])^gmul(Inv[15],Tampbloc[7]);
	
	bloc[8] = gmul(Inv[0],Tampbloc[8])^gmul(Inv[1],Tampbloc[9])^gmul(Inv[2],Tampbloc[10])^gmul(Inv[3],Tampbloc[11]);
	bloc[9] = gmul(Inv[4],Tampbloc[8])^gmul(Inv[5],Tampbloc[9])^gmul(Inv[6],Tampbloc[10])^gmul(Inv[7],Tampbloc[11]);
	bloc[10] = gmul(Inv[8],Tampbloc[8])^gmul(Inv[9],Tampbloc[9])^gmul(Inv[10],Tampbloc[10])^gmul(Inv[11],Tampbloc[11]);
	bloc[11] = gmul(Inv[12],Tampbloc[8])^gmul(Inv[13],Tampbloc[9])^gmul(Inv[14],Tampbloc[10])^gmul(Inv[15],Tampbloc[11]);
	
	bloc[12] = gmul(Inv[0],Tampbloc[12])^gmul(Inv[1],Tampbloc[13])^gmul(Inv[2],Tampbloc[14])^gmul(Inv[3],Tampbloc[15]);
	bloc[13] = gmul(Inv[4],Tampbloc[12])^gmul(Inv[5],Tampbloc[13])^gmul(Inv[6],Tampbloc[14])^gmul(Inv[7],Tampbloc[15]);
	bloc[14] = gmul(Inv[8],Tampbloc[12])^gmul(Inv[9],Tampbloc[13])^gmul(Inv[10],Tampbloc[14])^gmul(Inv[11],Tampbloc[15]);
	bloc[15] = gmul(Inv[12],Tampbloc[12])^gmul(Inv[13],Tampbloc[13])^gmul(Inv[14],Tampbloc[14])^gmul(Inv[15],Tampbloc[15]);
	
}

void Inv_SubBytes(uchar* bloc){
	
	for(int i=0;i<16;i++)
		bloc[i] = InvSBox[bloc[i]];
}

void dechiffrer(uchar* bloc, uchar* Key, int Nr){
 
  int i;
  AddRoundKey(bloc,Key,Nr);
  Inv_ShiftRows(bloc);
  Inv_SubBytes(bloc);
  for(i = Nr-1;i> 0;i--){
  	AddRoundKey(bloc,Key,i);
  	Inv_MixColumns(bloc);
  	Inv_ShiftRows(bloc);
  	Inv_SubBytes(bloc);
  }
  AddRoundKey(bloc,Key,0);
}

void Dechiffrage (uchar* bloc, uchar* clef, int keyLength) {
  
  /* Initialiser la table de dechiffrage pour Sub */
  for (int i=0; i<256;i++)
  	InvSBox[SBoxKE[i]] = i;
  
  int Nr = howManyRound(keyLength);
  
  uchar* W = KeyExpansion(clef,keyLength);
  
  dechiffrer(bloc,W,Nr);
  
}
