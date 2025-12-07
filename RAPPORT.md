# Rapport - TP 3 : Système de Détection d'Intrusions (NIDS)

**Nom :** Ayoub Benayyad  
**Matière :** Administration Réseau - Master IDL

---

## Introduction

Ce TP a pour objectif de réaliser un outil simple de détection d'intrusions (NIDS - Network Intrusion Detection System) en langage C. Nous allons analyser le trafic réseau pour détecter un comportement suspect, défini ici comme l'obtention de deux erreurs HTTP 404 consécutives.

## 1. Système de détection d'intrusions

**Exercice 1 : Documentation sur les NIDS**

Un NIDS (Network Intrusion Detection System) est un système conçu pour surveiller le trafic réseau afin de détecter des activités malveillantes ou des violations de politique de sécurité. Contrairement à un pare-feu qui bloque le trafic, un NIDS analyse les paquets en temps réel ou hors ligne pour identifier des signatures d'attaques connues (approche par signature) ou des anomalies statistiques (approche comportementale). Des outils célèbres incluent Snort ou Suricata.

---

## 2. Analyse d'une trame HTTP

**Exercice 2 : Exemple de requête HTTP**

Voici un exemple simple d'échange HTTP :

*Requête (GET) :*
```http
GET /index.html HTTP/1.1
Host: www.example.com
```

*Réponse :*
```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 135

<html>
...
</html>
```

**Exercice 3 : Analyse Hexadécimale**

Dans le sujet, l'entête HTTP commence par `48 54 54 50` ce qui correspond aux caractères ASCII "HTTP".
La suite `77 77 77` correspond en ASCII à **"www"** (souvent trouvé dans l'entête `Host` ou `Location`).

**Exercice 4 & 5 : Fonctions d'analyse**

J'ai implémente les fonctions `print_after_http` et `detectHttp404` dans le fichier `analysis.c`.

```c
// Extrait de analysis.c
int detectHttp404(char *buffer) {
    if (strstr(buffer, "HTTP") != NULL) {
        if (strstr(buffer, "404") != NULL) {
            return 1;
        }
    }
    return 0;
}
```

---

## 3. Logique de Détection (Analyse)

**Exercices 6 à 9 : Gestion de l'alarme**

Nous avons simulé la réception de paquets avec la fonction `recv`. Une variable globale `error404_count` compte les erreurs. Si elle atteint 2, une alarme est déclenchée.

**Résultat de l'exécution (analysis.c) :**

![alt text](image-1.png)

---

## 4. Capture avec Libpcap

Nous avons utilisé la bibliothèque `libpcap` pour capturer le trafic réel. Le code complet se trouve dans `sniffer.c`.

**Exercice 10 & 11 : Ouverture du périphérique**

Le programme détecte automatiquement l'interface (ou utilise celle passée en argument) et l'ouvre avec `pcap_open_live`.

**Exercice 12 : Masque et Adresse**

On utilise `pcap_lookupnet` pour obtenir ces informations.

**Exercice 13 : Filtrage**

Nous avons appliqué le filtre `tcp src port 80` pour ne capturer que le trafic venant de serveurs Web (réponses HTTP).

```c
char filter_exp[] = "tcp src port 80";
// Compilation et application du filtre avec pcap_compile et pcap_setfilter
```

---

## 5. Traitement et Intégration

**Exercice 14 & 15 : Fonction Callback et Affichage**

La fonction `callback` est appelée pour chaque paquet capturé. Elle extrait les entêtes IP et TCP pour accéder au payload (contenu) du paquet. Si la taille des données est suffisante (> 200 octets), on affiche le contenu en ASCII.

**Exercice 16 : Test avec un navigateur**

En naviguant sur internet pendant que le sniffer tourne, on observe une grande quantité de paquets. Cela est dû au chargement des nombreuses ressources d'une page web moderne (images, CSS, scripts) qui génèrent chacune des requêtes HTTP distinctes (souvent sur la même connexion TCP "Keep-Alive").

**Exercice 17 : Test avec Telnet**

Avec Telnet, on peut envoyer une requête brute très simple `GET / HTTP/1.0`. On observe alors la réponse brute du serveur capturée par notre sniffer.

**Exercice 18 : Intégration Finale**

J'ai intégré la logique `detectHttp404` dans la fonction `callback` du sniffer.

**Résultat de l'exécution (sniffer.c) :**

*Trafic Normal (Capture réelle) :*
```
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-aQIgW4gIFus6C1aoCjzA3Q' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
Server: gws
Content-Length: 219
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN

<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>

--------------------------------
[Packet] Dest IP: 172.17.0.2 | Size: 66 bytes
```

*Détection d'Intrusion (Simulation de l'alarme) :*
```
[Packet] Dest IP: 172.17.0.2 | Size: 412 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8
...
[!] 404 Error Detected in Packet!

[Packet] Dest IP: 172.17.0.2 | Size: 412 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8
...
[!] 404 Error Detected in Packet!
ALARM: Suspicious behavior detected (Two 404 errors)!
```

---

## Conclusion

Ce TP a permis de comprendre les bases de la programmation réseau bas niveau en C avec `libpcap`. Nous avons vu comment capturer des trames, les filtrer, et analyser leur contenu pour en extraire des informations applicatives (HTTP) et détecter des comportements spécifiques (Intrusion/Anomalie).
