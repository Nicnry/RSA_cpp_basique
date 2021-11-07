/*
-----------------------------------------------------------------------------------
Nom du fichier :    	henry_labo16.cpp
Auteur(s)      :    	Nicolas Henry
Date creation  :    	31.10.2021
Laboratoire n° :    	16
Description    :		Ce laboratoire implémente la méthode de cryptographie à clé publique proposée en 1973 par Clifford Christopher Cocks, connue sous le nom de RSA. Programme qui demande à l’utilisateur deux nombres premiers p != q ainsi qu’un nombre e premier avec (p - 1) * (q - 1) (on se limitera à des valeurs p * q et e < 2^31 - 1). Le programme vérifie que p et q sont très probablement premier avec un test rapide (test_rapide_primalite(uint32_t nombre)). Le programme calcule d, l’inverse de e % (p - 1) * (q - 1) avec l’algorithme d’Euclide étendu (euclide_etendu(int32_t nombre1, int32_t nombre2, int32_t& inverse)). Le programme affiche la clé publique (n et e) ainsi que la clé secrète d. Finalement, le programme vérifie que (m^e % n)^d % n === m pour tout m < n, autrement dit, on arrive bien à retrouver univoquement le message d’origine m à partir du message crypté c = m^e % n. À noter que pour ce programme, les types utilisés sont uint32_t, int32_t et uint64_t, vu que nous utilisons des nombres qui peuvent très vite être grands, ainsi que plus le nombre est grand, plus la "sécurité" sera élevée, il est important de s'assurer que le type utilisé permette les calculs souhaité.
-----------------------------------------------------------------------------------
*/

#include <iostream>
#include <random>
#include <cstdint>
#include <cstdlib> // return EXIT_SUCCESS

using namespace std;

/**
 * La graine va servir à générer un nombre aléatoire. Il est déclarer hors du main
 * afin d'être accessible dans toutes les fonctions. C'est un subterfuge pour ce
 * labo, il est fortement décommendé de faire ceci pour de la vrai cryptographie.
 * le nombre choisi pour la graine est aléatoire, d'autres chiffres iraient aussi.
 */
const uint32_t GRAINE = 27387;
auto generateur_aleatoire = bind(uniform_int_distribution<uint32_t>(2, numeric_limits<uint32_t>::max()), mt19937(GRAINE));

/**
 *
 * @brief La fonction d’exponentiation modulaire (b^e mod m), où b, e et m sont
 * des entiers positifs. Pour implanter cette fonction efficacement, peut
 * remarquer que si e est pair, sa valeur vaut (((b2) mod m)(e/2)), ce qui permet
 * de diviser par 2 le nombre de  multiplications. Si b est impair, sa valeur vaut
 * : (b * be−1 mod m). On en dérive un algorithme efficace donné dans l'énoncé, et
 * est implanté dans une fonction de ce programme. Enfin, une fonction de
 * verification valide si la fonction de l'exponentiation modulaire est le même
 * résultat que (b^e mod m).
 * @param base
 * @param exposant
 * @param modulo
 * @return resultat
 */
uint32_t exponentiation_modulaire(uint64_t base, uint32_t exposant, uint32_t modulo);

/**
 * @brief La problèmatique est la factorisation des nombres en informatiques qui
 * est extrêmement complexe, ici on "factorise" afin de savoir si un nombre est
 * premier ou non.
 * @param nombre
 * @return Si le nombre est premier ou non (true = premier).
 */
bool test_rapide_primalite(uint32_t nombre);

/**
 * @brief Cette fonction retourne 2 éléments, le PGDC en return, ainsi
 * que l'inverse par référence. L'inverse est le nombre qui permet de retrouver le
 * même résultat de (nombre^x % modulo) et (nombre^y % modulo), dans ce cas, y est
 * l'inverse de x et le résultat serait identique. Plus d'informations sur :
 * https://fr.wikipedia.org/wiki/Algorithme_d%27Euclide_%C3%A9tendu.
 * @param nombre1
 * @param nombre2
 * @param inverse : retourne l'inverse par référence
 * @return PGDC de 2 nombres.
 */
uint32_t euclide_etendu(int32_t nombre1, int32_t nombre2, int32_t& inverse);

/**
 *
 * @brief Cette fonction n'est pas obligatoire, elle sert juste pour la lisibilité
 * dans les conditions et pour valider que le message est correctement chiffré et
 * déchiffré.
 * @param nombre1
 * @param nombre2
 * @return Si 2 nombres sont identiques.
 */
bool est_identique(uint32_t nombre1, uint32_t nombre2);

/**
 *
 * @brief Cette fonction n'est pas obligatoire, elle sert juste pour la lisibilité
 * dans les conditions. Elle ne verifie que si le nombre dépasse
 * numeric_limits<uint32_t>::max() et non pas le minimum vu qu'on est en non-signé.
 * @param nombre1
 * @param nombre2
 * @return Si la multiplication des 2 nombres fait un overflow.
 */
bool est_overflow(uint32_t nombre1, uint32_t nombre2);

int main() {
	/**
	 * p, q et e sont des nombres premiers saisis par l'utilisateur. Dans ce
	 * programme, ils sont nommés de cette manière car cela reprend le nommage du
	 * chiffrement RSA. la variable e fait partie de la clé publique.
	 */
	uint32_t p, q, e;

	//Saisie de 2 nombres premiers (p et q).
	bool saisie_fausse;
	cout << "Veuillez entrer 2 nombres premier ou p est différent de q et inferieur a 2147483647" << endl;

	do {
		cin >> p >> q;
		/**
		 * On vérifie si p et q sont différents, ainsi que s'ils sont premier et
		 * qu'ils ne provoquent pas un débordement.
		 */

		if (cin.fail() || est_identique(p, q) || !test_rapide_primalite(p) || !test_rapide_primalite(q) || est_overflow(p, q)) {
			saisie_fausse = true;
			cin.clear(); //Reset des bits d'erreurs.
			cout << "Saisie incorrecte. Veuillez svp recommencer." << endl;
		} else {
			saisie_fausse = false;
		}
		cin.ignore(numeric_limits<streamsize>::max(), '\n'); // vide le buffer.
	} while(saisie_fausse);

	//Saisie e (premier et inférieur à (p - 1) * (q - 1)).
	saisie_fausse = true; //On remet le booléen à true pour les prochaines saisies.
	cout << "Veuillez entrer un nombre premier avec (p - 1) * (q - 1)" << endl;

	/**
	 * (p - 1) * (q - 1) = phi, dans le cadre de RSA, on utilise une notion
	 * découverte par Euler voir https://fr.wikipedia.org/wiki/Indicatrice_d%27Euler.
	 */
	uint32_t phi_euler = (p - 1) * (q - 1);
	/**
	 * d est l’inverse de e modulo phi_euler avec l’algorithme d’Euclide étendu. On
	 * l'instancie à 0 vu qu'il sera passé par référence et que (dans mon
	 * environnement en tout cas) une variable qui n'a pas une valeur assignée lors
	 * de la déclaration peut avoir n'importe quelle valeur, c'est important.
	 * (Evidemment on sait ce que va faire la fonction, mais on ne le sait pas toujours.
	 */
	int32_t d = 0;
	do {
		cin >> e;
		/**
		 * On verifie le pgdc de phi_euler et e, et on retourne l'inverse pour d On
		 * verifie également si e est plus petit que phi_euler.
		 */

		if (cin.fail() || !((euclide_etendu(int32_t(phi_euler), int32_t(e), d) == 1) && e < phi_euler)) {
			saisie_fausse = true;
			cin.clear(); //Reset des bits d'erreurs
			cout << "Saisie incorrecte. Veuillez svp recommencer." << endl;
		} else {
			saisie_fausse = false;
		}
		cin.ignore(numeric_limits<streamsize>::max(), '\n'); // vide le buffer.
	} while(saisie_fausse);

	/**
	 * n est la 2ème partie de la clé publique (avec e) calculé par p * q qui
	 * doivent rester secret (voir https://fr.wikipedia.org/wiki/Chiffrement_RSA#Cr%C3%A9ation_des_cl%C3%A9s point 2).
	 */
	uint32_t n = p * q;

	//Affichage demandé.
	cout << "Cle publique (n, e) : (" << n << ", " << e << ")" << endl;
	cout << "Cle secrete (d) : " << d << endl;

	//Saisie du message à transmettre.
	uint32_t message;
	saisie_fausse = true; //On remet le booléen à true pour les prochaines saisies.
	cout << "Veuillez entrer votre message (nombre < " << n << ")" << endl;
	do {
		cin >> message;
		//On verifie si le message est plus petit que n.
		if (cin.fail() || message >= n) {
			saisie_fausse = true;
			cin.clear(); //Reset des bits d'erreurs
			cout << "Saisie incorrecte. Veuillez svp recommencer." << endl;
		} else {
			saisie_fausse = false;
		}
		cin.ignore(numeric_limits<streamsize>::max(), '\n'); // vide le buffer.
	} while(saisie_fausse);

	//On chiffre le message.
	uint32_t message_chiffre = exponentiation_modulaire(uint64_t(message), e, n);
	cout << "Message chiffre : " << message_chiffre << endl;

	//Déchiffrement du message.
	uint32_t message_dechiffre = exponentiation_modulaire(message_chiffre, uint32_t (d), n);
	cout << "Le message : " << message_dechiffre << endl;

	//Vérification si le programme à bien fonctionné.
	cout << "Le message dechiffre correspond au message ? : " << boolalpha << est_identique(message, message_dechiffre);
	return EXIT_SUCCESS;
}

uint32_t exponentiation_modulaire(uint64_t base, uint32_t exposant, uint32_t modulo) {
	uint64_t resultat = 1;
	while (exposant > 0) {
		if (!(exposant % 2)) {
			base = base * base % modulo;
			exposant /= 2;
		} else {
			resultat = resultat * base % modulo;
			exposant--;
		}
	}
	return uint32_t(resultat);
}

bool test_rapide_primalite(uint32_t nombre) {
	//Utilisation d'une variable, car souvent répété dans la fonction.
	uint32_t nombre_moins_1 = nombre - 1;
	//1 et 0 ne sont pas premier,
	if (nombre < 2) {
		return false;
	}
	/**
	 * 2 est le premier nombre premier et empêche tous les nombres paires d'être
	 * premier. Tester si l'utilisateur rentre 3 (car generateur_aleatoire
	 * retournera 2 et ça ferra modulo 2 donc boucle infinie plus tard dans la
	 * fonction). */
	if (nombre == 2 || nombre == 3) {
		return true;
	}

	uint32_t nombre_aleatoire;
	//Tester 10 fois pour s'assurer de la primalité
	for (int i = 1; i <= 10; i++) {
		//Generation d'un nombre aléatoire, on vérifie avec % si le nombre dépasse nombre-1
		do {
			nombre_aleatoire = generateur_aleatoire() % nombre_moins_1;
		} while(nombre_aleatoire < 2);
		/**
		 * Si l'exponentiation modulaire retourne autre chose que 1, c'est que le
		 * nombre n'est pas premier (le PGDC d'un nombre premier ne peut être que
		 * lui même et 1, donc si on trouve autre chose que 1...)
		 */
		if(exponentiation_modulaire(uint64_t(nombre_aleatoire), nombre_moins_1, nombre) != 1) {
			return false;
		}
		/**
		 * les noms de variables q et u viennent de la formule mathématique fournie
		 * ici : https://fr.wikipedia.org/wiki/Algorithme_d%27Euclide_%C3%A9tendu,
		 * mais pour résumer, ce sont des variables temporaires qu'on doit utiliser
		 * en informatique et qui ne sont pas expliquée mathématiquement, c'est une
		 * contrainte du language C++ qui ne permet pas d'affecter plusieurs
		 * variables en une seule fois.
		 */
		uint32_t q = 1;
		uint32_t u = nombre_moins_1;
		//Tant que u n'est pas pair (divisible par 2) il est candidat.
		while (!(u % 2) && q == 1) {
			u /= 2;
			q = exponentiation_modulaire(nombre_aleatoire, u, nombre);
			//Si q n'est pas premier et (nombre - 1), c'est qu'il n'est pas premier...
			if (q != 1 && q != nombre_moins_1) {
				return false;
			}
		}
	}
	return true;
}

uint32_t euclide_etendu(int32_t nombre1, int32_t nombre2, int32_t& inverse) {
	int32_t pgdc = nombre1;
	int32_t pgdc_prime = nombre2;
	inverse = 0;
	int32_t inverse_prime = 1;
	while (pgdc_prime != 0) {
		// partie entière de pgdc et pgdc' car int, q est le nom fournit dans l'algo.
		int32_t q = pgdc / pgdc_prime;
		int32_t pgdc_temp = pgdc;
		int32_t inverse_temp = inverse;
		pgdc = pgdc_prime;
		inverse = inverse_prime;
		pgdc_prime = pgdc_temp - q * pgdc_prime;
		inverse_prime = inverse_temp - q * inverse_prime;
	}
	if (inverse < 0) {
		inverse = inverse + nombre1;
	}
	return uint32_t(pgdc);
}

bool est_identique(uint32_t nombre1, uint32_t nombre2) {
	return nombre1 == nombre2;
}

bool est_overflow(uint32_t nombre1, uint32_t nombre2) {
	return nombre1 >= numeric_limits<uint32_t>::max() / nombre2;
}
