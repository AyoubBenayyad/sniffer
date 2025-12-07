Administration r´eseau
Master IDL - parcours GLIA
Ann´ee universitaire 2009-2010
Syst`eme de d´etection d’intrusions
Le but de ce TP est de r´ealiser un outil simple de d´etection d’intrusions.
Utilisation : la r´ealisation d’un tel programme a deux buts majeurs.
– Les connaissances acquises lors de la r´ealisation de ce programme permettent
de cr´eer un logiciel d’´ecoute r´eseau (comme l’outil tcpdump).
– L’analyse de protocoles et les m´ecanismes au cœur des syst`emes de d´etection
d’intrusions sont manipul´es dans ce projet.
Consigne : le TP doit ˆetre r´ealis´e en C. Une partie du sujet ne peut ˆetre test´ee
qu’avec les droits administrateur. Cependant, le projet est con¸cu pour qu’une grande
partie puisse ˆetre faite sans avoir ces droits. Dans tous les cas, le projet peut ˆetre
compil´e sans droits administrateurs, et test´e a posteriori.
1 Syst`eme de d´etection d’intrusions
Exercice 1. Consultez sur Internet la documentation sur les NIDS (network intru-
sion detection system).
Un NIDS simple est compos´e de quatre parties : un m´ecanisme de capture de
trames (´etudi´e en partie 4), un m´ecanisme d’analyse de trame (´etudi´e en partie 2),
un m´ecanisme de signalement en cas de situation (qui sera pour nous un simple
printf) et un m´ecanisme de suivi d’´etat (´etudi´e en partie 3).
Un NIDS est sens´e d´etecter des comportements suspects. Dans le cadre de ce
TP, nous consid´ererons qu’un comportement suspect consiste `a obtenir deux fois
une erreur HTTP 4041. Ainsi, nous verrons que ce n’est pas un ´ev´enement isol´e
(l’obtention d’une erreur 404) qui d´eclenche une alarme, mais une s´erie d’´ev´enements.
2 Analyse d’une trame HTTP
Exercice 2. Trouvez sur Internet un exemple simple de requˆete HTTP (commande
GET) et la r´eponse associ´ee.
Consid´erez le paquet IP dont un extrait est indiqu´e ici :
45 00 02 77 c3 19 00 00 31 06 ee 5d d8 ef 3b 68
c0 a8 01 0a 00 50 89 ab 5d 6f ba ce 85 12 c9 38
80 18 00 59 c4 23 00 00 01 01 08 0a 05 1a f6 ca
00 1a 61 4d 48 54 54 50 2f 31 2e 30 20 33 30 32
1Pour ˆetre plus r´ealiste, il faudrait probablement consid´erer l’obtention de deux erreurs HTTP
404 pour un mˆeme serveur dans un certain intervalle de temps, mais nous laisserons cet aspect de
cˆot´e.
1
20 46 6f 75 6e 64 0d 0a 4c 6f 63 61 74 69 6f 6e
3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f
67 6c 65 2e 66 72 2f 0d 0a ...
Ce paquet IP encapsule une trame HTTP qui contient les donn´ees suivantes :
HTTP/1.0 302 Found
Location: http://www.google.fr/
...
Si l’on continuait l’affichage, on verrait apparaˆıtre les informations HTML incluses
dans l’entˆete HTTP.
Exercice 3. En sachant que HTTP s’´ecrit en hexad´ecimal 48 54 54 50, localisez
(manuellement) l’entˆete HTTP dans l’entˆete IP. R´eciproquement, que signifie 77 77
77 ?
Exercice 4. Faites une fonction2 qui prend en param`etre un tableau de caract`eres
et qui affiche tout ce qui suit la chaˆıne HTTP, si elle existe.
Exercice 5. Faites une fonction detectHttp404 qui prend en param`etre un tableau
de caract`eres et qui retourne 1 si ce qui suit contient la chaˆıne HTTP, mais que la
page en question n’a pas ´et´e trouv´ee suite `a une erreur 404.
3 Analyse
Dans cette partie, nous cherchons `a compter le nombre de fois o`u l’on obtient des
erreurs 404. Lorsqu’il y en a eu deux, nous affichons un message d’alarme et nous
r´einitialisons le compteur.
Exercice 6. Recopiez la fonction suivante :
void recv(char * buffer) {
int retour;
retour = detectHttp404(buffer);
}
Cette fonction sera remplac´ee ult´erieurement par la fonction callback.
Exercice 7. Appelez la fonction recv sur plusieurs tableaux que vous aurez initia-
lis´es manuellement dans votre main, incluant le tableau incluant une r´eponse HTTP
donn´e au pr´ealable dans ce sujet.
Exercice 8. Cr´eez une variable globale enti`ere qui est initialis´ee `a 0. Incr´ementez
la variable `a chaque fois qu’une erreur 404 est re¸cue.
Exercice 9. Quand le nombre d’erreurs 404 atteint 2, r´einitialisez le compteur `a 0
et signalez `a l’utilisateur une alarme.
2Cette fonction vous servira dans la suite `a d´ebugguer votre programme.
2
4 Capture
Il existe deux moyens principaux de capturer des trames : l’utilisation d’une socket
en mode RAW et l’interfa¸cage avec une librairie de capture (comme libpcap). Nous
nous concentrerons ici sur l’utilisation de la librairie libpcap3.
Remarque : pour ˆetre ex´ecut´ee, cette partie n´ecessite (1) que la librairie libpcap
soit install´ee et (2) que l’utilisateur dispose des droits administrateur.
Dans la suite, il faut inclure le fichier d’entˆete pcap.h et penser `a faire l’´edition
des liens en incluant la librairie libpcap4.
4.1 Ouverture et fermeture du p´eriph´erique de capture
Tout d’abord, il faut identifier le p´eriph´erique de capture. Pour cela, il faut utiliser
la fonction pcap_lookupdev qui prend en param`etre un tableau de PCAP_ERRBUF_SIZE
octets (le premier ´etant initialis´e `a ’\0’) et qui retourne un char *. Si la fonction
retourne NULL, le tableau pass´e en param`etre contient un message d’erreur. Un cas
d’erreur fr´equent est que l’utilisateur ne dispose pas des droits administrateur. Sinon,
la fonction retourne un pointeur sur le p´eriph´erique de capture.
Exercice 10. ´Ecrivez un programme qui d´etermine le p´eriph´erique de capture.
Une fois le p´eriph´erique d´etermin´e, on peut proc´eder `a son ouverture en utilisant
la fonction pcap_open_live. Cette fonction prend en param`etre un p´eriph´erique, une
taille maximale de paquets `a capturer, un entier indiquant si le p´eriph´erique doit
passer en mode promiscuit´e (nous laisserons cet entier `a 0), un entier qui sp´ecifie
le temps maximum `a attendre avant que la fonction ne quitte (nous sp´ecifierons ici
un -1) et un tableau d’au moins PCAP_ERRBUF_SIZE qui sera rempli en cas d’erreur
(il est initialis´e comme pr´ec´edemment). La fonction retourne un descripteur de type
pcap_t *.
Le p´eriph´erique de capture pourrait aussi ˆetre sp´ecifi´e par l’utilisateur en donnant
la chaˆıne eth0 en param`etre de la fonction pcap_open_live par exemple.
Le p´eriph´erique de capture est ferm´e au moyen de la fonction pcap_close qui
prend en param`etre le descripteur.
Exercice 11. ´Ecrivez un programme qui ouvre le p´eriph´erique de capture, puis qui
le ferme.
La fonction pcap_lookupnet permet de d´eterminer l’adresse r´eseau et le masque
utilis´es par le p´eriph´erique de capture. Elle prend en param`etre le descripteur du
p´eriph´erique, un pointeur sur l’adresse (dont le type est bpf_u_int32), un pointeur
sur le masque (dont le type est bpf_u_int32) et un pointeur sur le tableau d’erreurs
habituel.
Le type bpf_u_int32 correspond `a une adresse IPv4 stock´ee dans un entier 32
bits au format r´eseau. L’instruction int d = (ip&0xff000000)>>24; r´ecup`ere donc
le quatri`eme entier de l’adresse `a points.
Exercice 12. ´Ecrivez un programme qui affiche l’adresse du r´eseau et le masque du
p´eriph´erique de capture sous forme d’adresses `a points.
3Pour l’autre m´ethode, se reporter au TP sur l’utilisation de sockets de type RAW.
4On pourra faire gcc -o main -lpcap *.c.
3
4.2 Installation d’un filtre de capture
Avant de commencer `a capturer des paquets, nous allons installer un filtre de
capture. Ce filtre permet de pr´eselectionner les paquets `a capturer. Le format du
filtre est celui utilis´e par les outils comme tcpdump. Nous allons nous int´eresser
ici aux paquets dont le port source est le port HTTP. Le filtre correspondant est
tcp src port 80. Pour installer un filtre, il faut d’abord compiler ce filtre, puis
l’appliquer.
La compilation d’un filtre se fait au moyen de la fonction pcap_compile qui prend
en param`etre un descripteur, un pointeur sur une variable de type struct bpf_program
qui contiendra le r´esultat de la compilation, le filtre, un entier indiquant si la compi-
lation doit ˆetre optimis´ee ou non (nous passerons 0 en param`etre), et le masque de
sous-r´eseau. Si la fonction retourne un entier n´egatif, il y a eu une erreur (concernant
probablement un filtre mal construit) qui peut ˆetre obtenue en appelant la fonction
pcap_geterr sur le descripteur.
L’application d’un filtre se fait au moyen de la fonction pcap_setfilter qui
prend en param`etre un descripteur et un pointeur sur le filtre dont le type est
struct bpf_program.
Exercice 13. Cr´eez et appliquez un filtre pour ne recevoir que les paquets dont le
port source est HTTP.
4.3 Capture
Finalement, la capture s’initialise grˆace `a une fonction appel´ee pcap_loop. Cette
fonction prend en param`etre un descripteur, un nombre de paquets maximum `a
recevoir (ou -1 dans notre cas), un pointeur sur une fonction de callback (d´etaill´e
plus loin) et un pointeur sur un nom d’utilisateur (que nous laisserons `a NULL).
La fonction de callback est une fonction que nous devons ´ecrire et qui sera ap-
pel´e pour chaque paquet re¸cu (ou envoy´e) qui correspond `a notre filtre. Pour pas-
ser un pointeur sur la fonction callback `a la fonction pr´ec´edente, il suffit d’utiliser
&callback, avec callback une fonction ayant le prototype suivant :
void callback(u_char * user, const struct pcap_pkthdr * h, const u_char * buff);
Dans la fonction de callback, le paquet re¸cu est transmis par l’interm´ediaire du
tableau buff. Pour notre utilisation, nous pouvons faire :
struct iphdr * ipHeader;
ipHeader = (struct iphdr *)(buff+14);
Ensuite, nous pouvons utiliser les champs de l’entˆete IP ou des entˆetes suivants
comme nous l’avons vu au pr´ealable.
Exercice 14. ´Ecrivez un programme qui affiche la taille de chaque paquet HTTP
re¸cu ainsi que l’adresse IP de la destination.
4
Exercice 15. ´Ecrivez un programme qui affiche en ASCII (sans l’entˆete IP) chaque
paquet HTTP re¸cu de taille sup´erieure ou ´egale `a 200.
Exercice 16. Testez votre programme avec un navigateur classique. Qu’observez-
vous ? `A quoi est-ce dˆu ?
Exercice 17. Testez votre programme avec une session telnet5 en entrant GET / HTTP/1.0
suivi de deux fois entr´ee.
Exercice 18. Remplacez la fonction recv par la fonction callback.
5Utilisez par exemple telnet www.google.fr 80.
5