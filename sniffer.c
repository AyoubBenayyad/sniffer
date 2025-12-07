#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SIZE_ETHERNET 14

// Compteur pour l'alarme (Exercice 8)
int compteur_404 = 0;

// Fonction de detection de l'erreur 404 (Exercice 5)
int detectHttp404(const char *buffer) {
    if (strstr(buffer, "HTTP") != NULL) {
        if (strstr(buffer, "404") != NULL) {
            return 1;
        }
    }
    return 0;
}

// Fonction appelée à chaque paquet capturé (Callback)
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff) {
    struct ip *ipHeader;
    char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    // Récupération de l'entête IP
    ipHeader = (struct ip*)(buff + SIZE_ETHERNET);
    size_ip = ipHeader->ip_hl * 4;
    
    // Récupération de l'entête TCP
    struct tcphdr *tcpHeader = (struct tcphdr*)(buff + SIZE_ETHERNET + size_ip);
    size_tcp = tcpHeader->th_off * 4;

    // Le contenu (payload) se trouve après les entêtes
    payload = (char *)(buff + SIZE_ETHERNET + size_ip + size_tcp);
    
    int t_headers = SIZE_ETHERNET + size_ip + size_tcp;
    size_payload = h->len - t_headers;

    // Exercice 14 : Afficher IP destination et taille
    printf("[Paquet] Dest IP: %s | Taille: %d octets\n", inet_ntoa(ipHeader->ip_dst), h->len);

    // Exercice 15 : Afficher le contenu ASCII
    if (size_payload >= 200) {
        printf("--- Debut du contenu ---\n");
        for (int i = 0; i < size_payload; i++) {
            // On affiche que les caractères imprimables
            if (isprint(payload[i]) || payload[i] == '\n') {
                printf("%c", payload[i]);
            } else {
                printf(".");
            }
        }
        printf("\n------------------------\n");
    }

    // Exercice 18 : Detection et Alarme
    if (size_payload > 0) {
        // Copie dans un buffer propre pour éviter les problèmes
        char buffer_analyse[4096];
        int len = size_payload;
        if (len > 4095) len = 4095;
        
        memcpy(buffer_analyse, payload, len);
        buffer_analyse[len] = '\0'; // Fin de chaine

        if (detectHttp404(buffer_analyse)) {
            printf("ATTENTION : Erreur 404 détectée !\n");
            compteur_404++;
        }
    }

    // Verification du compteur
    if (compteur_404 >= 2) {
        printf("!!! ALARME : Comportement suspect détecté (2 erreurs 404) !!!\n");
        compteur_404 = 0; // On remet à zéro
    }
}

int main(int argc, char *argv[]) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filtre[] = "tcp src port 80"; // Filtre pour avoir que le HTTP venant du serveur
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Exercice 10 : Trouver le périphérique
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        // Si on trouve pas, on prend celui en argument ou 'any'
        if (argc > 1) {
            dev = argv[1];
        } else {
            dev = "any"; 
        }
        printf("Périphérique non trouvé auto, tentative avec : %s\n", dev);
    } else {
        printf("Périphérique trouvé : %s\n", dev);
    }

    // Exercice 12 : Masque et Réseau
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("Erreur lookupnet\n");
        net = 0;
        mask = 0;
    }

    // Exercice 11 : Ouverture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Impossible d'ouvrir %s : %s\n", dev, errbuf);
        return 2;
    }

    // Exercice 13 : Application du filtre
    if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
        printf("Erreur filtre compile\n");
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Erreur filtre set\n");
        return 2;
    }
    printf("Filtre '%s' appliqué.\n", filtre);

    // Exercice 14 : Boucle de capture
    printf("Lancement de la capture (Ctrl+C pour arrêter)...\n");
    pcap_loop(handle, -1, callback, NULL);

    pcap_close(handle);
    return 0;
}
