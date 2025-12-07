# TP 3 : NIDS (Détection d'Intrusions)

Projet réalisé par Ayoub Benayyad.

## Compilation

Le projet peut se compiler sous Linux. Si vous êtes sous Windows, vous pouvez utiliser Docker.

**Commande pour compiler :**

```bash
# Pour la partie analyse (Ex 1-9)
gcc -o analysis analysis.c

# Pour le sniffer (Ex 10-18)
gcc -o sniffer sniffer.c -lpcap
```

## Exécution

### 1. Tester la partie Analyse
Ce programme teste juste la logique (détection de chaines de caractères).
```bash
./analysis
```

### 2. Lancer le Sniffer
Il faut les droits root pour capturer les paquets.
```bash
sudo ./sniffer
```
*(Si ça ne marche pas, essayez `sudo ./sniffer eth0` ou votre interface réseau)*

### Tests effectués

Pour tester l'alarme, j'utilise `curl` ou un navigateur pour générer deux erreurs 404 :
```bash
curl http://www.google.com/faux_lien_1
curl http://www.google.com/faux_lien_2
```
Cela déclenche le message `!!! ALARME !!!`.

---

## Pour Windows (Docker)

Comme je suis sous Windows, j'ai utilisé Docker pour que ce soit plus simple.
1. Construire : `docker build -t nids .`
2. Lancer : `docker run -it --name tp-nids nids`
3. Dans le conteneur, lancer `./sniffer &` puis faire des `curl`.
