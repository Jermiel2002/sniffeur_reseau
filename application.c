
/********************************************************
	NOM du projet : Sniffer réseau
********************************************************

Auteur(s) : KOUNOUHO Kpessou Jermiel
Date de la derniere revision :
Version :
Auteur(s) revision :
Date de revision :

*/

#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "application.h"
/*
********************************************
COUCHE APPLICATIVE (7) MODELE OSI
********************************************
*/

/*Gestion des paquets bootp / dhcp*/
void bootp_view(const __u_char *packet, int data_size)
{
	struct bootphdr *bootp = (struct bootphdr*)(packet);
	int i, j, l;
	u_int32_t tmp;

	printf("\033[1m");
	printf("\t\t\t▭▭▭ BOOTP ▭▭▭\n");
	printf("\033[0m");
	printf("\t\t\tMessage type : ");

	switch (bootp->msg_type)
	{
	case 1:
		printf("Request\n");
		break;
	case 2:
		printf("Reply");
		break;	
	default:
		printf("Unknown\n");
		break;
	}

	printf("\t\t\tHardware type : ");
	switch (bootp->hrdwr_type)
	{
	case 1:
		printf("Ethernet\n");
		break;
	case 6:
		printf("IEEE 802\n");
	case 18:
		printf("Fibre channel\n");
	case 20:
		printf("Serial line\n");
		break;
	default:
		printf("Unknown\n");
		break;
	}
	printf("\t\t\tHardware address lenght : %d bytes\n", bootp->hrdwr_addr_length);
	printf("\t\t\tHops : %d\n", bootp->hops);
	printf("\t\t\tTransaction ID : 0x%08x\n", ntohl(bootp->trans_id));
	printf("\t\t\tSeconds elapsed : %d\n", ntohs(bootp->num_sec));
	printf("\t\t\tClient IP address : %s\n" inet_ntoa(bootp->ciaddr));
	printf("\t\t\tYour IP address : %s\n", inet_ntoa(bootp->yiaddr));
	printf("\t\t\tNext server IP address : %s\n", inet_ntoa(bootp->siaddr));
	printf("\t\t\tRelay agent IP address : %s\n", inet_ntoa(bootp->giaddr));

	if(bootp->hrdwr_addr_length == 6)
	{
		printf("\t\t\tCLient MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
			bootp->hrdwr_caddr[0],
			bootp->hrdwr_caddr[1],
			bootp->hrdwr_caddr[2],
			bootp->hrdwr_caddr[3],
			bootp->hrdwr_caddr[4],
			bootp->hrdwr_caddr[5]);

		printf("\t\t\tClient hardware address padding : ");
		for(i = 6; i<16;i++){
			printf("%02x", bootp->hrdwr_caddr[i]);
		}
		printf("\n");
	}
	else{
		printf("\t\t\tClient hardware address unknown : ");
		for(i=0; i<16; i++){
			printf("%02x", bootp->hrdwr_caddr[i]);
		}
		printf("\n");
	}	

	printf("\t\t\tServer host name : ");
	if(bootp->srv_name[0] != 0){
		for(i=0; i<64 && bootp-srv_name[i] != 0; i++){
			if(isprint(bootp->srv_name[i]))
				printf("%c", bootp->srv_name[i]);
			else
				printf(".");
		}
		printf("\n");
	}
	else {
		printf("not given\n");
	}

	printf("\t\t\tBoot file name : ");
	if(bootp->bpfile_name[0] != 0) {
		for(i=0; i<128 && bootp->bpfile_name[i] != 0; i++){
			if(isprint(bootp->bpfile_name[i]))
				printf("%c", bootp->bpfile_name[i]);
			else
				printf(".");
		}
		else{
			printf("Not given\n");
		}

		if(ntohl(bootp->magic_cookie) == 0x63825363)
	}
}




/*Gestion des paquets DNS*/



/*Gestion des paquets http*/



/*Gestion des paquets ftp*/



/*Gestion des paquets smptp*/



/*Gestion des paquets POP*/



/*Gestion des paquets IMAP*/


/*Gestion des paquets TELNET*/