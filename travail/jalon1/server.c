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

#define MAX_CLIENTS 10

// Structure pour les clients connectés
struct ClientNode {
    int socket;
    struct sockaddr_in addr;
    struct ClientNode *next;
};

struct ClientList {
    struct ClientNode *head;
};

// Fonction pour afficher les clients
void show_clients(struct ClientList *clientList) {
    struct ClientNode *current = clientList->head;

    if (current != NULL) {
        printf("Clients connectés :\n");
    } else {
        printf("Aucun client connecté.\n");
    }

    while (current != NULL) {
        printf("Socket FD : %d, IP : %s\n", current->socket, inet_ntoa(current->addr.sin_addr));
        current = current->next;
    }
    printf("\n");
}

// Fonction pour ajouter un client
void append_client(struct ClientList *clientList, int socketFD, struct sockaddr_in clientAddr) {
    struct ClientNode *newNode = malloc(sizeof(*newNode));
    newNode->socket = socketFD;
    newNode->addr = clientAddr;
    newNode->next = clientList->head;
    clientList->head = newNode;
}

// Fonction pour retirer un client
void remove_client(struct ClientList *clientList, int socketFD) {
    struct ClientNode *current = clientList->head;
    struct ClientNode *previous = NULL;

    while (current != NULL) {
        if (current->socket == socketFD) {
            if (previous == NULL) {
                clientList->head = current->next;
            } else {
                previous->next = current->next;
            }
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
}

// Fonction pour libérer la mémoire de la liste
void cleanup_client_list(struct ClientList *clientList) {
    struct ClientNode *current = clientList->head;
    struct ClientNode *nextNode = NULL;

    while (current != NULL) {
        nextNode = current->next;
        free(current);
        current = nextNode;
    }

    free(clientList);
}

// Fonction pour lier le serveur
int setup_server(char *argv[]) {
    int serverSocket;
    struct sockaddr_in serverAddr;

    char *portStr = argv[1];
    int port = atoi(portStr);

    printf("Port : %d\n", port);

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int option = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) == -1) {
        perror("setsockopt");
        return EXIT_FAILURE;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        perror("bind");
        return EXIT_FAILURE;
    }

    return serverSocket;
}

// Fonction pour gérer une nouvelle connexion
void handle_new_connection(int *clientCount, struct pollfd fds[], int serverSocket, struct ClientList *clientList) {
    if (fds[0].revents & POLLIN) {
        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        memset(&clientAddr, 0, addrLen);

        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrLen);
        if (clientSocket == -1) {
            perror("accept");
            return;
        }

        fds[*clientCount].fd = clientSocket;
        fds[*clientCount].events = POLLIN;

        (*clientCount)++;

        append_client(clientList, clientSocket, clientAddr);
        show_clients(clientList);
    }
}

// Fonction pour gérer la réception et l'envoi de messages
void handle_communication(int *clientCount, struct pollfd fds[], struct ClientList *clientList) {
    for (int i = 1; i < *clientCount; i++) {
        if (fds[i].revents & POLLIN) {
            char buffer[MSG_LEN];
            int len = recv(fds[i].fd, buffer, sizeof(buffer) - 1, 0);
            if (len <= 0) {
                printf("Client %d déconnecté.\n", fds[i].fd);
                remove_client(clientList, fds[i].fd);
                close(fds[i].fd);
                fds[i] = fds[*clientCount - 1];
                (*clientCount)--;
                i--;
            } else {
                buffer[len] = '\0';
                if (strcmp(buffer, "/quit\n") == 0) {
                    printf("Client %d déconnecté.\n", fds[i].fd);
                    remove_client(clientList, fds[i].fd);
                    show_clients(clientList);
                    close(fds[i].fd);
                    fds[i] = fds[*clientCount - 1];
                    (*clientCount)--;
                    i--;
                } else {
                    printf("Message reçu : %s", buffer);
                    send(fds[i].fd, buffer, len, 0);
                    printf("Réponse envoyée !\n");
                }
            }
        }
    }
}

// Fonction pour libérer la mémoire
void cleanup_resources(int *clientCount, struct pollfd fds[], struct ClientList *clientList) {
    for (int i = 0; i < *clientCount; i++) {
        close(fds[i].fd);
    }

    cleanup_client_list(clientList);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Arguments manquants.\n");
        return EXIT_FAILURE;
    }

    int serverSocket = setup_server(argv);

    if (listen(serverSocket, MAX_CLIENTS) != 0) {
        perror("listen() error");
        exit(EXIT_FAILURE);
    }

    struct pollfd fds[MAX_CLIENTS];
    fds[0].fd = serverSocket;
    fds[0].events = POLLIN;

    int clientCount = 1;

    struct ClientList *clientList = malloc(sizeof(struct ClientList));
    clientList->head = NULL;

    while (1) {
        int ret = poll(fds, clientCount, -1);
        if (ret == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        handle_new_connection(&clientCount, fds, serverSocket, clientList);
        handle_communication(&clientCount, fds, clientList);

        if (clientCount == 1) {
            printf("Plus de clients connectés : arrêt du serveur.\n");
            break;
        }
    }

    cleanup_resources(&clientCount, fds, clientList);

    return EXIT_SUCCESS;
}
