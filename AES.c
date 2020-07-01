#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/stat.h>

#include "KeyExp.h" //-> TP B.3
#include "aesC.h"  //-> TP C.1 et C.2
#include "CBCpkcs.h" //-> TP F.1 et F.2
#include "md5sum.h" //-> md5sum du mot de passe

/* Vous pouvez tester l'algorithme sur butokuden.jpg */
/* Ou sur test.txt qui est plus petit, plus pratique */
/* Pour analyser les contenus au fur et a mesure.    */

/* Utiliser "./scriptDelete" ("sudo chmod +x scriptDelete.sh" avant) */
/* pour supprimer les fichiers créée dont vous n'avez plus besoin entre deux instances */


int main(int argc, char* argv[]){
	/* Aucun argument: chiffrement du bloc nul, clef nulle */
	if(argc==1){
		Chiffrage(blocNul,clefNulle,16);
		printf("\n");
		printf("Résultat: ");
		affiche_bloc_matriciel(blocNul);
		printf("\n");
	}
	/* 1 argument: -e || -d (de)chiffrement du bloc nul, clef nulle */
	else if(argc==2){
		char* option = argv[1];
		
		if(option[1] == 'e')
			Chiffrage(blocNul,clefNulle,16);
		if(option[1] == 'd')
			Dechiffrage(blocNul,clefNulle,16);
		
		printf("\n");
		printf("Résultat: ");
		affiche_bloc_matriciel(blocNul);
		printf("\n");
	}
	/* 2 arguments: -e || -d (de)chiffrement */
	/* d'un fichier(arg 2), clef nulle */
	else if(argc==3){
		char* option = argv[1];
		char fileName[50];
		strcpy(fileName,argv[2]);
		
		if(option[1] == 'e'){
			Padding_file(fileName);  
			CBC( clefNulle);
		}
		if(option[1] == 'd')
			Inv_CBC(fileName, clefNulle);
		
	}
	/* 3 arguments: Idem + mot de passe(arg 3) */
	/* clef = md5sum arg3 */
	else if(argc==4){
		char* option = argv[1];
		char* fileName = argv[2];
		char* mdp = argv[3];
		
		StringToMd5(mdp);
		if(option[1] == 'e'){
			Padding_file(fileName);
			CBC( clef);
		}
		if(option[1] == 'd')
			Inv_CBC(fileName, clef);
	}
	else{
		printf("Mauvais nombre d'arguments (0-1-2-3).\n");
		return 0;
	}
	return 0;
}
