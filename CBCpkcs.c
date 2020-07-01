#include "CBCpkcs.h"

/*------------- VARIABLES GLOBALES ----------------*/

char paddedString[50]; //Nom du fichier paddé

char cryptedFileName[50]; //Nom du fichier crypté


/*---------------UTILS-----------------------------*/

/* copie le contenue de <bloc> dans <copy> */
void bloc_copy(uchar* bloc, uchar* copy){
	for(int i=0;i<16;i++)
		copy[i] = bloc[i];
}

/* Méthode explicite */
uchar* randomBloc(){
	srand(time(0));	
	
	uchar* randomBloc = malloc(16*sizeof*randomBloc);
	for(int i=0;i<16;i++){
		randomBloc[i] = (rand() & 0xfff);
		//randomBloc[i] = 0x00;
	}
	
	return randomBloc;
}


/*----------------METHODE DE PADDING---------------*/

void Padding_file(char* fileName){
  printf("Chiffrement de %s ",fileName);
  
  uchar buffer[16];
  int nb_octets_lus;
  
  int k;    
  
  FILE* fichier;
  FILE* paddedFile = NULL;
  
  fichier = fopen(fileName,"r");
  if(fichier == NULL) {printf("Impossible d'ouvrir le fichier a padder\n");exit(1);}
  
  /* Creation du nouveau fichier */
  char newFileName[50];
  strcpy(newFileName,"padded-");
  strcat(newFileName,fileName);
  
  strcpy(paddedString,newFileName);
  
  paddedFile = fopen(newFileName,"w");
  
  /* Octet de bourrage */
  int pad ;
  
  nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier);   // Lecture du premier morceau
  while (nb_octets_lus != 0) {
  	/* Si on lit moins de 16 octets, c'est que l'on a besoin de bourrage */
  	if(nb_octets_lus < 16){
  		/* Conformément au bourrage standart PKCS5 */
  		pad = (16-nb_octets_lus);

  		for (k=0; k < nb_octets_lus; k++)
    			fprintf(paddedFile,"%c",buffer[k]);
    		
    		/* On écrit a la suite le nombre suffisant d'octet de bourrage */
  		for(int p = nb_octets_lus;p<16;p++)
  			fprintf(paddedFile,"%c",pad & 0xfff);

  	}
  	else
  		for (k=0; k < nb_octets_lus; k++)
    			fprintf(paddedFile,"%c",buffer[k]);
    		
  	nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier); // Lecture du morceau suivant
  }
  
  fclose(fichier);
  fclose(paddedFile);
  
}



/*------------CHIFFRAGES CIPHER BLOCK CHAINING--------*/

void CBC( uchar* Key){
  uchar buffer[16];
  int nb_octets_lus;
  
  int k;    
  
  FILE* cryptedFile = NULL;
  FILE* paddedFile;
  
  paddedFile = fopen(paddedString,"r");
  if(paddedFile == NULL) {printf("Impossible d'ouvrir le fichier paddé.\n");exit(1);}
  
  strcpy(cryptedFileName,"aes-");
  strcat(cryptedFileName,paddedString);
  
  cryptedFile = fopen(cryptedFileName,"w");
  
  printf("en %s \n",cryptedFileName);
  
  /* Initialisation du Vecteur Initial */
  uchar* initBloc = randomBloc();
  
  /* Ecriture du vecteur Initial */
  for (k=0; k < 16; k++)
  		fprintf(cryptedFile,"%c",initBloc[k]);
  
  nb_octets_lus = fread (buffer, 1, sizeof(buffer), paddedFile);   // Lecture du premier morceau
  while (nb_octets_lus != 0) {
  	
  	uchar currentBloc[16];
  	
  	/* XOR bit a bit entre le morceau et le vecteur */
  	for(k=0 ; k<16 ; k++)
  		currentBloc[k] = initBloc[k] ^ buffer[k];
  	
  	/* Chiffrage */
  	Chiffrage(currentBloc,Key,16);
  	
  	/* Ecriture */
  	for (k=0; k < nb_octets_lus; k++)  {
  		fprintf(cryptedFile,"%c",currentBloc[k]);
	}
	
	/* Le vecteur devient donc le précédent bloc traité */
	bloc_copy(currentBloc,initBloc);
 	
  	nb_octets_lus = fread (buffer, 1, sizeof(buffer), paddedFile); // Lecture du morceau suivant
  }
  
  free(initBloc);
  
  fclose(cryptedFile);
  fclose(paddedFile);
}

void Inv_CBC(char* cryptedFileName, uchar* Key){
  
  uchar buffer[16];
  int nb_octets_lus;
  
  int k;    
  
  /* Tableaux tres utiles pour manipuler les blocs */
  uchar padlingBuffer[16];
  uchar initBloc[16];
  uchar tampBloc[16];
  
  FILE* unCryptedFile = NULL;
  FILE* cryptedFile;
  
  cryptedFile = fopen(cryptedFileName,"r");
  if(cryptedFile == NULL) {printf("Impossible d'ouvrir le fichier crypté.\n");exit(1);}
  
  char unCryptedFileName[50];
  strcpy(unCryptedFileName,"aes-");
  strcat(unCryptedFileName,cryptedFileName);
  
  unCryptedFile = fopen(unCryptedFileName,"w");
  
  printf("Déchiffrement de %s en %s \n",cryptedFileName,unCryptedFileName);
  
  nb_octets_lus = fread (buffer, 1, sizeof(buffer), cryptedFile);   // Lecture du premier morceau
  /* C'est en théorie le vecteur initial */
  bloc_copy(buffer,initBloc);
  
  nb_octets_lus = fread (buffer, 1, sizeof(buffer), cryptedFile);  // Lecture du morceau suivant
  
  while (nb_octets_lus != 0) {
  	bloc_copy(buffer,tampBloc); //Nous allons stocké ce bloc intact pour pouvoir l'utiliser lors de l'évaluation du prochain
  	
  	/* Dechiffrage */
  	Dechiffrage(buffer,Key,16);
  	
  	/* XOR dans le sens inverse pour retrouver le bloc initial */
  	for(k=0 ; k<16 ; k++)
  		buffer[k] = initBloc[k] ^ buffer[k];

  	/* Le bloc precedement stocké devient le vecteur pour l'évaluation du prochain */
  	bloc_copy(tampBloc,initBloc);
  	
  	/* Nous allons maintenant enlevé si necessaire les bits de padding */
  	bloc_copy(buffer,padlingBuffer);
  	
  	int stop = -1; //indice du premier bit de padding
  	
  	nb_octets_lus = fread (buffer, 1, sizeof(buffer), cryptedFile); // Lecture du morceau suivant
  	
  	/* Si le morceau suivant est vide, c'est que nous sommes a la fin du fichier, il faut donc tester le padding */
  	if(nb_octets_lus == 0){
  		/* Boucle descendante en partant du dernier indice */
  		for(int i = 15;i>0;i--){
  			/* Si un bit correspond a la différence de taille de lui même et 16 */
  			if((int)padlingBuffer[i] == 16-i){
  				/* Il faut tester si ce n'est pas une coincidence, et que tout les précédent sont égaux (tous de padding) */
  				for(int j=i+1;j<16;j++){
  					/* Si non, ce n'en est pas un */
  					if(padlingBuffer[i]!=padlingBuffer[j]){
  						stop = -1;
  						break;
  					}
  					/* On stock l'indice */
  					else
  						stop = i;
  				}
  			}
  		}
  		if(stop == -1) stop = 16;
  		/* On ecrit tout jusqu'a l'indice du premier bit de padding */
  		for (k=0; k < stop; k++)
  			fprintf(unCryptedFile,"%c",padlingBuffer[k]);
			
  	}
  	else{
  		for (k=0; k < nb_octets_lus; k++)
  			fprintf(unCryptedFile,"%c",padlingBuffer[k]);

 	}
  }
    
  fclose(cryptedFile);
  fclose(unCryptedFile);
}



/* -----------------CHIFFRAGES SANS CBC --------------*/

/** Ces deux methodes ne sont là qu'a titre indicatif et on été faite dans la continuité du projet **/
/** Elles ne sont pas utile pour le projet final, mais permettent de bien comprendre l'AES**/

void withoutCBC( uchar* Key){
  uchar buffer[16];
  int nb_octets_lus;
  
  int k;    
  
  
  FILE* cryptedFile = NULL;
  FILE* paddedFile;
  
  printf(" padded file : %s \n",paddedString);
  
  paddedFile = fopen(paddedString,"r");
  if(paddedFile == NULL) {printf("aie\n");exit(1);}
  
  
  
  strcpy(cryptedFileName,"aes-");
  strcat(cryptedFileName,paddedString);
  
  printf("crypted file name : %s \n",cryptedFileName);
  
  cryptedFile = fopen(cryptedFileName,"w");
  
  nb_octets_lus = fread (buffer, 1, sizeof(buffer), paddedFile);   // Lecture du premier morceau
  while (nb_octets_lus != 0) {
  	
  	Chiffrage(buffer,Key,16);
  	
  	
  	for (k=0; k < nb_octets_lus; k++)  {
  		fprintf(cryptedFile,"%c",buffer[k]);
	}
	
	nb_octets_lus = fread (buffer, 1, sizeof(buffer), paddedFile); // Lecture du morceau suivant
  }
  
  
  fclose(cryptedFile);
  fclose(paddedFile);
}

void Inv_withoutCBC(char* cryptedFileName, uchar* Key){
  uchar buffer[16];
  int nb_octets_lus;
  
  int k;    
  
  uchar padlingBuffer[16];
  
  FILE* unCryptedFile = NULL;
  FILE* cryptedFile;
  
  printf("crypted file name : %s \n",cryptedFileName);
  
  cryptedFile = fopen(cryptedFileName,"r");
  if(cryptedFile == NULL) {printf("aie\n");exit(1);}
  
  char unCryptedFileName[50];
  strcpy(unCryptedFileName,"aes-");
  strcat(unCryptedFileName,cryptedFileName);
  
  unCryptedFile = fopen(unCryptedFileName,"w");
  
 
  
  nb_octets_lus = fread (buffer, 1, sizeof(buffer), cryptedFile);   // Lecture du premier morceau
  
  
  while (nb_octets_lus != 0) {
  	Dechiffrage(buffer,Key,16);
  	
  	bloc_copy(buffer,padlingBuffer);
  	
  	int stop = -1;
  	
  	nb_octets_lus = fread (buffer, 1, sizeof(buffer), cryptedFile); 
  	if(nb_octets_lus == 0){
  		printf("bloc de fin trouvé\n");
  		for(int i = 15;i>0;i--){
  			printf(" %d : %d \n", (int)padlingBuffer[i], 16-i);
  			if((int)padlingBuffer[i] == 16-i){
  				printf("je rentre\n");
  				for(int j=i+1;j<16;j++){
  					if(padlingBuffer[i]!=padlingBuffer[j]){
  						stop = -1;
  						break;
  					}
  					else
  						stop = i;
  				}
  				printf("le pad est a %d \n",stop);
  			}
  		}
  		
  		for (k=0; k < stop; k++)  {
  			
  				fprintf(unCryptedFile,"%c",padlingBuffer[k]);
			
		}
  	}
  	else{
  		for (k=0; k < nb_octets_lus; k++)  {
  			fprintf(unCryptedFile,"%c",padlingBuffer[k]);
		}
 	}
 	
  }
  
  fclose(cryptedFile);
  fclose(unCryptedFile);
}
