#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Global variable for Exercise 8
 * Counts the number of consecutive 404 errors.
 */
int error404_count = 0;

/**
 * Exercise 4: Function that takes a char buffer and prints everything after "HTTP"
 * if it exists.
 */
void print_after_http(char *buffer) {
    char *ret = strstr(buffer, "HTTP");
    if (ret != NULL) {
        printf("Content after 'HTTP': %s\n", ret + 4);
    } else {
        printf("No 'HTTP' found in the buffer.\n");
    }
}

/**
 * Exercise 5: Checks if the buffer contains "HTTP" AND "404".
 * Returns 1 if true, 0 otherwise.
 */
int detectHttp404(char *buffer) {
    if (strstr(buffer, "HTTP") != NULL) {
        if (strstr(buffer, "404") != NULL) {
            return 1;
        }
    }
    return 0;
}

/**
 * Exercise 6 & 8 & 9: Recv function simulation
 * Checks for 404 errors and manages the alarm.
 */
void recv(char *buffer) {
    int retour;
    retour = detectHttp404(buffer);

    if (retour == 1) {
        printf("[!] 404 Error Detected!\n");
        error404_count++;
    } else {
        // Optionnel : remettre à zéro si on reçoit une requête valide ?
        // Le sujet ne le précise pas explicitement, mais pour "2 erreurs consécutives" ou "série",
        // on pourrait le remettre à 0. Ici on suit la consigne "Atteint 2".
        // Si on interprète strictement "compter le nombre de fois", on incrémente.
        // Si c'est une détection de "comportement suspect", on peut imaginer un reset.
        // Pour ce TP simple, on incrémente juste.
    }

    // Exercise 9: Alarm trigger
    if (error404_count >= 2) {
        printf("ALARM: Suspicious behavior detected (Two 404 errors)!\n");
        error404_count = 0; // Reset counter
    }
}

int main() {
    printf("--- Test Analysis Logic ---\n");

    // Sample HTTP Response (valid 200 OK)
    char valid_response[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>...</html>";
    
    // Sample HTTP Response (404 Error)
    char error_response[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\nError...";
    
    // Sample non-HTTP data
    char junk_data[] = "Some random data without the keyword.";

    printf("\n[Test Ex 4] Print after HTTP:\n");
    print_after_http(valid_response);
    print_after_http(junk_data);

    printf("\n[Test Ex 7] Simulate Reception:\n");
    
    printf("1. Receiving valid response...\n");
    recv(valid_response);
    
    printf("2. Receiving 1st 404 error...\n");
    recv(error_response);
    
    printf("3. Receiving valid response...\n");
    recv(valid_response);
    
    printf("4. Receiving 2nd 404 error...\n");
    recv(error_response); 
    // Should trigger alarm here

    return 0;
}
