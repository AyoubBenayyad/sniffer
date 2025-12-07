#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Variable globale pour compter les erreurs 404 (Exercice 8)
int compte_erreurs = 0;

// Exercice 4 : Affiche ce qu'il y a apres "HTTP"
void print_after_http(char *buffer) {
    char *ptr = strstr(buffer, "HTTP");
    if (ptr != NULL) {
        printf("Reste du buffer : %s\n", ptr + 4);
    } else {
        printf("Pas de 'HTTP' trouvé.\n");
    }
}

// Exercice 5 : Detecte si on a une erreur 404
int detectHttp404(char *buffer) {
    // On cherche "HTTP"
    if (strstr(buffer, "HTTP") != NULL) {
        // Et on cherche "404"
        if (strstr(buffer, "404") != NULL) {
            return 1;
        }
    }
    return 0;
}

// Exercice 6, 8, 9 : Fonction de reception simulee
void recv(char *buffer) {
    int resultat;
    resultat = detectHttp404(buffer);

    if (resultat == 1) {
        printf("-> Erreur 404 détectée !\n");
        compte_erreurs++;
    }

    // Declenchement de l'alarme au bout de 2 erreurs
    if (compte_erreurs >= 2) {
        printf("ALARME : Trop d'erreurs 404 détectées (Comportement suspect) !\n");
        compte_erreurs = 0; // Remise a zero
    }
}

int main() {
    printf("--- Test du programme ---\n");

    // Reponse OK
    char reponse_ok[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Test</html>";
    
    // Reponse 404
    char reponse_erreur[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\nErreur...";
    
    printf("\nTest appel Exercice 4 :\n");
    print_after_http(reponse_ok);

    printf("\nTest simulation reception (Ex 7, 8, 9) :\n");
    
    printf("Reception normale...\n");
    recv(reponse_ok);
    
    printf("Reception 404 (1ere)...\n");
    recv(reponse_erreur);
    
    printf("Reception normale...\n");
    recv(reponse_ok);
    
    printf("Reception 404 (2eme) -> Alarme attendue...\n");
    recv(reponse_erreur); 

    return 0;
}
