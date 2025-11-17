#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#include "common.h"

void echo_client(int socketFd) {
	
	int flag = 1;  // Flag pour gérer l'affichage du message
    char buff[MSG_LEN];
    int ret;

	struct pollfd fds[2];
    fds[0].fd = socketFd;
    fds[0].events = POLLIN;

    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    while (1) {

		if(flag == 1) {
			printf("Message : ");  // Affiche "Message :" avant l'entrée clavier
			fflush(stdout);  // S'assurer que le texte est bien affiché avant la saisie
		}
		
        ret = poll(fds, 2, -1);  // Attendre les événements
        if (ret == -1) {
            perror("poll");
            break;
        }

		// Si une réponse du serveur est prête à être lue
        if (fds[0].revents & POLLIN) {
            memset(buff, 0, MSG_LEN);
            ssize_t n = recv(socketFd, buff, MSG_LEN, 0);

            if (n <= 0) {
                printf("Serveur déconnecté ou erreur.\n");
                break;
            }

			printf("\n");	
            printf("Reçu du serveur : %s", buff);  // Affiche la réponse du serveur
			printf("\n");

			flag = 1;  // Permet de réafficher "Message :" après réception
        }
		
        // Si une entrée clavier est prête à être lue
        if (fds[1].revents & POLLIN) {
			
            memset(buff, 0, MSG_LEN);
            ssize_t n = read(STDIN_FILENO, buff, MSG_LEN);

			// Si l'utilisateur tape "/quit", déconnexion du client
			if (strncmp(buff, "/quit\n", 6) == 0) {
				send(socketFd, buff, n, 0);  // Envoie "/quit" au serveur
				printf("Déconnecté...\n");
				close(socketFd);  // Ferme la socket côté client
				exit(0);  // Termine le processus du client
			}

            if (n <= 0 || strncmp(buff, "exit\n", 5) == 0) {
                printf("Client fermé.\n");
                break;
            }
			
            send(socketFd, buff, n, 0);  // Envoie le message au serveur
			printf("Message envoyé !\n");

			flag = 0;  // Permet de ne pas afficher "Message :" immédiatement
        }
    }
}


int handle_connect(const char *server_name, const char *server_port) {
    struct addrinfo hints, *result, *rp;
    int sfd;

    // Initialisation de la structure hints pour getaddrinfo
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;        // IPv4 ou IPv6
    hints.ai_socktype = SOCK_STREAM;    // Socket TCP

    // Résolution du nom du serveur et du port
    if (getaddrinfo(server_name, server_port, &hints, &result) != 0) {
        perror("getaddrinfo()");
        exit(EXIT_FAILURE);
    }

    // Boucle pour essayer chaque adresse renvoyée par getaddrinfo
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;  // Si la création de la socket échoue, essayer la suivante
        }
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;  // Si la connexion réussit, on sort de la boucle
        }
        close(sfd);  // Si la connexion échoue, fermer la socket
    }

    if (rp == NULL) {
        fprintf(stderr, "Impossible de se connecter au serveur\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);  // Libération de la mémoire utilisée par getaddrinfo
    return sfd;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_name> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_name = argv[1];  // Nom du serveur ou adresse IP
    const char *server_port = argv[2];  // Port du serveur

    // Se connecter au serveur
    int sfd = handle_connect(server_name, server_port);

    // Lancer le client ECHO avec gestion simultanée des entrées clavier et messages du serveur
    echo_client(sfd);

    // Fermer la connexion
    close(sfd);

    return EXIT_SUCCESS;
}
