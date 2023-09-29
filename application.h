#ifndef __APPLICATION_H
#define __APPLICATION_H

#include <stdint.h>

/******************structures dns et bootp
 * 
 * Les structures dnshdr et bootphdr sont définies pour représenter les en-têtes des paquets DNS et BOOTP respectivement. 
 * Ces structures sont utilisées pour analyser les données des paquets réseau et extraire des informations importantes telles 
 * que les identifiants, les compteurs, les adresses IP, etc.
*/

struct dnshdr
{
    uint16_t query_id;
    uint16_t flags;
    uint16_t quest_count;
    uint16_t answ_count;
    uint16_t auth_count;
    uint16_t add_count;
};

struct bootphdr
{
    uint8_t msg_type;
    uint8_t hrdwr_type;
    uint8_t hrdwr_addr_length;
    uint8_t hops;
    uint32_t trans_id;
    uint16_t num_sec;
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    __u_char hrdwr_caddr[16];
    __u_char srv_name[64];
    __u_char bpfile_name[128];
    uint32_t magic_cookie;
};

/*****Affichage (dump) du contenu de divers paquets applicatifs (d'autres peuvent être implémentés)*************
 * Les fonctions bootp_view, dns_view, http_view, ftp_view, smtp_view, pop_view, imap_view, et telnet_view sont 
 * déclarées pour afficher le contenu des paquets correspondants. Chacune de ces fonctions prend deux arguments : 
 * un pointeur vers les données du paquet (const __u_char*) et la longueur du paquet (int).

Par exemple, void bootp_view(const __u_char*, int); indique que la fonction bootp_view prend en entrée un pointeur 
vers des données et la longueur de ces données pour afficher le contenu d'un paquet BOOTP.

Le but de ces fonctions est de parcourir les données du paquet et d'afficher les informations pertinentes pour chaque 
protocole applicatif spécifique. Cela pourrait inclure des informations de débogage, des statistiques ou simplement une 
visualisation du contenu du paquet à des fins de diagnostic.
*/
void bootp_view(const __u_char*, int);
void dns_view(const __u_char*, int);
void http_view(const __u_char*, int);
void ftp_view(const __u_char*, int);
void smtp_view(const __u_char*, int);
void pop_view(const __u_char*, int);
void imap_view(const __u_char*, int);
void telnet_view(const __u_char*, int);

#endif

/********************************~DNS~*****************************
 * Dans le monde de l’Internet, les machines du réseau sont identifiées par des adresses Ip. 
 * Néanmoins, ces adresses ne sont pas très agréables à manipuler, c’est pourquoi, on utilise les noms. 
 * L’objectif a alors été de permettre la résolution des noms de domaines qui consiste à assurer la conversion 
 * entre les noms d’hôtes et les adresses IP. La solution actuelle est l’utilisation des DNS (Domain Name System)
 * 
 *                     UTILISATION DU PROTOCOLE UDP
 * Un datagramme DNS en UDP est un paquet réseau qui transporte des requêtes ou des réponses DNS en utilisant le 
 * protocole UDP, avec une taille maximale de 512 octets de données. Si les données DNS excèdent cette limite, le 
 * paquet peut être tronqué, et le client peut être invité à réessayer en utilisant TCP pour obtenir la réponse complète.
 * 
 * Le port 53 est le port standard réservé pour les communications DNS. Les requêtes DNS sont envoyées à un serveur DNS sur 
 * le port 53 en UDP ou TCP, en fonction de la nature de la requête.
 * 
 *                     UTILISATION DU PROTOCOLE TCP
 * Le passage de DNS d'UDP (User Datagram Protocol) à TCP (Transmission Control Protocol) est nécessaire lorsque les données DNS 
 * dépassent la limite de 512 octets imposée par le protocole UDP. Lorsque TCP est utilisé pour DNS, les paquets DNS sont encapsulés 
 * dans des segments TCP, et il y a quelques différences clés par rapport à l'utilisation d'UDP :
 * 
 * Port 53 : Le port 53 est toujours utilisé comme port de destination pour les communications DNS, que ce soit en UDP ou en TCP. 
 *           Cela permet de garantir que le serveur DNS sur le port 53 puisse gérer les requêtes DNS entrantes.
 * 
 * Champ "longueur" : Lorsqu'un paquet DNS est encapsulé dans un segment TCP, un champ de deux octets appelé "longueur" est ajouté à 
 *                    l'en-tête DNS. Ce champ spécifie la longueur totale des données DNS contenues dans le segment TCP, à l'exclusion 
 *                    des deux octets utilisés pour représenter cette longueur.
 *                    Par exemple, si la longueur totale des données DNS, y compris l'en-tête DNS, est de 100 octets, alors la valeur du champ "longueur" 
 *                    sera de 98 (car il faut soustraire les 2 octets utilisés par le champ "longueur" lui-même).
 * 
 * Fragmentation : Contrairement à UDP, où les datagrammes DNS sont généralement fragmentés s'ils dépassent 512 octets, en utilisant TCP, il n'est pas nécessaire de 
 *                 fragmenter les données DNS. Le champ "longueur" dans l'en-tête DNS permet de spécifier la longueur totale des données, ce qui signifie que le serveur 
 *                 et le client peuvent transférer des données DNS plus importantes en une seule fois.
 * 
 *                     EN-TETE DNS BASE SUR 12 OCTETS
 * L'en-tête DNS (Domain Name System) est basé sur 12 octets. Il est composé des champs suivants :
 *  - id : Codé sur 16 bits, doit être recopié lors de la réponse permettant à l’application de départ de pouvoir identifier le datagramme de retour.
 *  - qr (query_id): Sur un 1 bit, ce champ permet d’indiquer s’il s’agit d’une requête (0) ou d’une réponse (1).
 *  - opcode : Sur 4 bits, ce champ permet de spécifier le type de requête :

        0 – Requête standard (Query)
        1 – Requête inverse (Iquery)
        2 – Status d’une requête serveur (Status)
        3-15 – Réservé pour des utilisations futurs

 *  - Aa: Le flag Aa, sur un bit, signifie « Authoritative Answer ». Il indique une réponse d’une entité autoritaire.
 *  - Tc: Le champ Tc , sur un bit, indique que ce message a été tronqué.
 *  - Rd: Le flag Rd, sur un bit, permet de demander la récursivité en le mettant à 1.
 *  - Ra: Le flag Ra, sur un bit, indique que la récursivité est autorisée.
 *  - Le flag Z, sur trois bits, est réservé pour une utilisation futur. Il doit être placé à 0 dans tout les cas. Désormais, cela est divisé en 3 bits : 1 bit pour Z, 1 bit pour AA (Authentificated Answer) qui indique si la réponse et authentifiée, et 1 bit NAD (Non-Authenticated Data) qui indique si les données sont non-authentifiées.
 *  - Le champ Rcode, basé sur 4 bits, indique le type de réponse.

        0 – Pas d’erreur
        1 – Erreur de format dans la requête
        2 – Problème sur serveur
        3 – Le nom n’existe pas
        4 – Non implémenté
        5 – Refus
        6-15 – Réservés

 *  
 *  - Qdcount: Codé sur 16 bits, il spécifie le nombre d’entrée dans la section « Question ».
 *  - Ancount: Codé sur 16 bits, il spécifie le nombre d’entrée dans la section « Réponse ».
 *  - Nscount: Codé sur 16 bits, il spécifie le nombre d’entrée dans la section « Autorité ».
 *  - Arcount: Codé sur 16 bits, il spécifie le nombre d’entrée dans la section « Additionnel ».
 * 
 *   */