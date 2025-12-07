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

**Important**: Les navigateurs modernes utilisent HTTPS par défaut, qui est chiffré. Le sniffer ne peut analyser que le trafic HTTP non chiffré (port 80).

**Test effectué**: Navigation vers `http://example.com` et pages inexistantes pour déclencher des erreurs 404.

**Résultats de capture (Navigateur Web):**

*Trafic Normal (HTTP 200 OK):*
```
[Packet] Dest IP: 10.16.37.152 | Size: 364 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 200 OK
Server: nginx
Content-Length: 90
Via: 1.1 google
Date: Sun, 07 Dec 2025 01:37:23 GMT
Content-Type: text/html
Cache-Control: public,must-revalidate,max-age=0,s-maxage=3600

<meta http-equiv="refresh" content="0;url=https://support.mozilla.org/kb/captive-portal"/>
--------------------------------
```

*Détection d'erreurs 404 (Navigation vers pages inexistantes):*
```
[Packet] Dest IP: 10.16.37.152 | Size: 970 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 404 Not Found
Accept-Ranges: bytes
Content-Type: text/html
ETag: "bc2473a18e003bdb249eba5ce893033f:1760028122.592274"
Last-Modified: Thu, 09 Oct 2025 16:42:02 GMT
Server: AkamaiNetStorage
Content-Length: 513
Expires: Sun, 07 Dec 2025 16:39:46 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Sun, 07 Dec 2025 16:39:46 GMT
Connection: keep-alive

<!doctype html><html lang="en"><head><title>Example Domain</title>...
--------------------------------
[!] 404 Error Detected in Packet!
ALARM: Suspicious behavior detected (Two 404 errors)!
```

**Observation**: En naviguant sur internet pendant que le sniffer tourne, on observe une grande quantité de paquets. Cela est dû au chargement des nombreuses ressources d'une page web moderne (images, CSS, scripts) qui génèrent chacune des requêtes HTTP distinctes (souvent sur la même connexion TCP "Keep-Alive"). Le système détecte correctement les erreurs 404 et déclenche l'alarme après deux détections.

**Exercice 17 : Test avec Telnet**

Avec Telnet, on peut envoyer une requête brute très simple `GET / HTTP/1.0`. On observe alors la réponse brute du serveur capturée par notre sniffer.

**Exercice 18 : Intégration Finale**

J'ai intégré la logique `detectHttp404` dans la fonction `callback` du sniffer.

**Résultat de l'exécution (sniffer.c) :**

**Configuration:**
```
Device found: eth0
Net: 10.16.32.0
Mask: 255.255.240.0
Device eth0 opened.
Filter 'tcp src port 80' applied.
Starting capture loop...
```

**Trafic Normal (Capture réelle via navigateur) :**
```
[Packet] Dest IP: 10.16.37.152 | Size: 364 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 200 OK
Server: nginx
Content-Length: 90
Via: 1.1 google
Date: Sun, 07 Dec 2025 01:37:23 GMT
Content-Type: text/html
Cache-Control: public,must-revalidate,max-age=0,s-maxage=3600

<meta http-equiv="refresh" content="0;url=https://support.mozilla.org/kb/captive-portal"/>
--------------------------------
```

**Détection d'Intrusion (Test via navigateur - http://example.com/fakepage) :**
```
[Packet] Dest IP: 10.16.37.152 | Size: 970 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 404 Not Found
Accept-Ranges: bytes
Content-Type: text/html
ETag: "bc2473a18e003bdb249eba5ce893033f:1760028122.592274"
Last-Modified: Thu, 09 Oct 2025 16:42:02 GMT
Server: AkamaiNetStorage
Content-Length: 513
Expires: Sun, 07 Dec 2025 16:37:40 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Sun, 07 Dec 2025 16:37:40 GMT
Connection: keep-alive

<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href="https://iana.org/domains/example">Learn more</a></div></body></html>

--------------------------------
[!] 404 Error Detected in Packet!

[Packet] Dest IP: 10.16.37.152 | Size: 970 bytes
--- Content (First 200+ bytes) ---
HTTP/1.1 404 Not Found
Accept-Ranges: bytes
Content-Type: text/html
ETag: "bc2473a18e003bdb249eba5ce893033f:1760028122.592274"
Last-Modified: Thu, 09 Oct 2025 16:42:02 GMT
Server: AkamaiNetStorage
Content-Length: 513
Expires: Sun, 07 Dec 2025 16:39:46 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Sun, 07 Dec 2025 16:39:46 GMT
Connection: keep-alive

<!doctype html><html lang="en"><head><title>Example Domain</title>...

--------------------------------
[!] 404 Error Detected in Packet!
ALARM: Suspicious behavior detected (Two 404 errors)!
```

---

## Conclusion

Ce TP a permis de comprendre les bases de la programmation réseau bas niveau en C avec `libpcap`. Nous avons vu comment capturer des trames, les filtrer, et analyser leur contenu pour en extraire des informations applicatives (HTTP) et détecter des comportements spécifiques (Intrusion/Anomalie).
