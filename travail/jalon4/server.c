#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

#include "common.h"
#include "msg_struct.h"

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m" 


void display_client_list(struct clientListe *listeClient){
	struct nodeClient *current = listeClient->premier;

	if (current != NULL)
	{
		fprintf(stdout, "The client register contains :\n");
	}
	else
	{
		fprintf(stdout, "The client register is empty\n");
	}

	while (current != NULL)
	{
		printf("Client FD: %d, IP: %s\n", current->socketFD, inet_ntoa(current->address.sin_addr));
		current = current->next;
	}
	fprintf(stdout, "\n");
}


struct nodeClient *get_client(struct clientListe *listeClient, int fd) {
    if (listeClient == NULL) {
        return NULL; 
    }

    struct nodeClient *current = listeClient->premier;
    while (current != NULL) {
        if (current->socketFD == fd) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}


void display_channel_list(struct channelListe *listeChannel){
	struct nodeChannel *current = listeChannel->premier;

	if (current != NULL){
		fprintf(stdout, "The channel register contains :\n");
	}
	else{
		fprintf(stdout, "The channel register is empty\n");
	}
	while (current != NULL){
		printf("-%s\n", current->channelName);
		current = current->next;
	}
	printf("\n");
}



void add_client(struct clientListe *listeClient, int newSocketFD, struct sockaddr_in clientAddress)
{
	struct nodeClient *newClient = malloc(sizeof(*newClient));
	newClient->socketFD = newSocketFD;
	newClient->address = clientAddress;
	newClient->connection_time = time(NULL);
	newClient->next = listeClient->premier;
	listeClient->premier = newClient;
}


void delete_client(struct clientListe *listeClient, int socketFD)
{
	struct nodeClient *current = listeClient->premier;
	struct nodeClient *previous = NULL;

	while (current != NULL)
	{
		if (current->socketFD == socketFD)
		{
			if (previous == NULL)
			{
				listeClient->premier = current->next;
			}
			else
			{
				previous->next = current->next;
			}
			free(current);
			return;
		}
		previous = current;
		current = current->next;
	}
}


void send_message(struct clientListe *listeClient, int fd, char *message){
	struct nodeClient *currentClient = get_client(listeClient, fd);

	struct message msgstruct;
	msgstruct.pld_len  = strlen(message) + 1;
	snprintf(msgstruct.nick_sender, MSG_LEN, "%s", currentClient->nickname);

	if(send(fd, &msgstruct, sizeof(msgstruct), 0) <= 0) {
		fprintf(stdout, "Error: Failure to send message structure to client %d.\n", fd);
		return;
	}

	if(send(fd, message, msgstruct.pld_len, 0) <= 0) {
		fprintf(stdout, "Error: Failure to send message to client %d.\n", fd);
		return;
	}
	memset(message, 0, msgstruct.pld_len);

	fprintf(stdout, "Echo sent\n");
}


void free_client_list(struct clientListe *listeClient)
{
	struct nodeClient *current = listeClient->premier;
	struct nodeClient *nextNode = NULL;

	while (current != NULL)
	{
		nextNode = current->next;
		free(current);
		current = nextNode;
	}

	free(listeClient);
}

void free_channel_client_list(struct channelClientList *clientList) {
    if (clientList == NULL) return;

    struct channelClientNode *current = clientList->premier;
    struct channelClientNode *nextNode = NULL;

    while (current != NULL) {
        nextNode = current->next;
        free(current);
        current = nextNode;
    }

    free(clientList); 
}

void free_channel_list(struct channelListe *listeChannel) {
    if (listeChannel == NULL){ 
		return;
	}

    struct nodeChannel *currentChannel = listeChannel->premier;
    struct nodeChannel *nextChannel = NULL;

    while (currentChannel != NULL) {
        nextChannel = currentChannel->next;

        if (currentChannel->clientList != NULL) {
            free_channel_client_list(currentChannel->clientList);
            currentChannel->clientList = NULL;
        }

        free(currentChannel); 
        currentChannel = nextChannel;
    }

    free(listeChannel);  
}


struct nodeChannel *find_channel_by_name(struct channelListe *listeChannel, char *name){
	if (listeChannel == NULL) {
        return NULL; 
    }

	struct nodeChannel *current = listeChannel->premier;
    while (current != NULL) {
        if (strcmp(current->channelName, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

char* generate_channel_list(struct channelListe *listeChannel) {
    char* channel_list = malloc(MSG_LEN);

	if(listeChannel->premier == NULL){
		strcpy(channel_list, "No channel available\n");
		return channel_list;
	}

    strcpy(channel_list, "Available channels are\n");

	if (channel_list == NULL) {
		return NULL;
	}

    struct nodeChannel *current = listeChannel->premier;
    while(current != NULL) {
        strcat(channel_list, "  - ");
        strcat(channel_list, current->channelName);
        strcat(channel_list, "\n");
        current = current->next;
	}

    return channel_list;
}

char* generate_nickname_list_of_a_channel(struct clientListe *listeClient, struct channelListe *listeChannel, char channelName[]) {
    if (listeChannel == NULL || channelName == NULL) {
        return NULL;
    }

    char* nickname_list = (char*)malloc(MSG_LEN * sizeof(char));
    if (nickname_list == NULL) {
        return NULL;
    }
    
    snprintf(nickname_list, MSG_LEN, "Online users in this channel are\n");

    struct nodeChannel *channel = find_channel_by_name(listeChannel, channelName);
    if (channel == NULL || channel->clientList == NULL) {

        free(nickname_list);
        return NULL;
    }

    struct channelClientNode *currentNode = channel->clientList->premier;
    size_t current_length = strlen(nickname_list);

    while (currentNode != NULL) {
        struct nodeClient *currentClient = currentNode->client;
        if (currentClient == NULL) {
            free(nickname_list);
            return NULL; 
        }

        size_t available_space = MSG_LEN - current_length - 1; 
        size_t required_space = strlen(currentClient->nickname) + 6; 

        if (required_space > available_space) {
            break;
        }

        int written = snprintf(nickname_list + current_length, available_space, "  - %s\n", currentClient->nickname);
        if (written < 0 || (size_t)written >= available_space) {
            break;
        }

        current_length += written; 
        currentNode = currentNode->next; 
    }

    return nickname_list;
}



void create_channel(struct clientListe *listeClient, struct channelListe *listeChannel, char *channelName, struct nodeClient *creator, int creatorFD) {
    if (listeChannel == NULL || channelName == NULL || creator == NULL) {
        return;
    }

    struct nodeChannel *newChannel = (struct nodeChannel *)malloc(sizeof(struct nodeChannel));
    if (newChannel == NULL) {
        return;
    }

    strncpy(newChannel->channelName, channelName, NICKNAME_LEN - 1);
    newChannel->channelName[NICKNAME_LEN - 1] = '\0';

    newChannel->clientList = (struct channelClientList *)malloc(sizeof(struct channelClientList));
    if (newChannel->clientList == NULL) {
        free(newChannel); 
        return;
    }
    newChannel->clientList->premier = NULL;  
	newChannel->clientList->clientNumber = 1;

    struct channelClientNode *creatorNode = (struct channelClientNode *)malloc(sizeof(struct channelClientNode));
    if (creatorNode == NULL) {
        free(newChannel->clientList);
        free(newChannel); 
        return;
    }
    creatorNode->client = creator;
    creatorNode->next = NULL;
    newChannel->clientList->premier = creatorNode;
    
    newChannel->next = listeChannel->premier; 
    listeChannel->premier = newChannel;

    creator->is_in_a_channel = 1;
	creator->permission = 2; 
    strncpy(creator->channelName, channelName, NICKNAME_LEN - 1);
    creator->channelName[NICKNAME_LEN - 1] = '\0';

	fprintf(stdout, "There are %d users in this channel\n", newChannel->clientList->clientNumber);
}

int join_channel(struct channelListe *listeChannel, const char *channelName, struct nodeClient *new_client) {
    struct nodeChannel *current_channel = listeChannel->premier;
    while (current_channel != NULL) {
        if (strcmp(current_channel->channelName, channelName) == 0) {
            break;  
        }
        current_channel = current_channel->next;
    }

    struct channelClientNode *current_channel_client_node = current_channel->clientList->premier;
    while (current_channel_client_node != NULL) {
        if (current_channel_client_node->client == new_client) {
            fprintf(stdout, "%s You have already joined the channel %s%s\n", channelName, RED, RESET);
            return -1;
        }
        current_channel_client_node = current_channel_client_node->next;
    }

    struct channelClientNode *new_channel_client_node = malloc(sizeof(new_channel_client_node));

    new_channel_client_node->client = new_client;
    new_channel_client_node->next = NULL;

    if (current_channel->clientList->premier == NULL) {
        current_channel->clientList->premier = new_channel_client_node;
    } 
	else {
        struct channelClientNode *current = current_channel->clientList->premier;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_channel_client_node; 
    }

	current_channel->clientList->clientNumber++;

    new_client->is_in_a_channel = 1;
	new_client->permission = 0;
    strncpy(new_client->channelName, channelName, NICKNAME_LEN - 1);
    new_client->channelName[NICKNAME_LEN - 1] = '\0';

	fprintf(stdout, "There are %d users in this channel\n", current_channel->clientList->clientNumber);

    return 0;
}

int delete_channel(struct channelListe *liste, const char *nomChannel) {
    if (liste == NULL || nomChannel == NULL) {
        return -1;
    }

    struct nodeChannel *actuel = liste->premier;
    struct nodeChannel *precedent = NULL;

    while (actuel != NULL) {
        if (strcmp(actuel->channelName, nomChannel) == 0) {
            if (precedent != NULL) {
                precedent->next = actuel->next;
            } 
			else {
                liste->premier = actuel->next;
            }

            if (actuel->clientList != NULL) {
                free_channel_client_list(actuel->clientList);
            }

            free(actuel); 
            actuel = NULL; 

            return 0; 
        }
        precedent = actuel;
        actuel = actuel->next;
    }

    return -1; 
}

int leave_channel(struct clientListe *listeClient, struct channelListe *listeChannel, const char *channelName, struct nodeClient *client, int clientFD) {
    if (listeChannel == NULL || channelName == NULL || client == NULL) {
        return -1;  
    }

    struct nodeChannel *current_channel = listeChannel->premier;

    while (current_channel != NULL) {
        if (strcmp(current_channel->channelName, channelName) == 0) {
            break;  
        }
        current_channel = current_channel->next;
    }

    if (current_channel == NULL) {
        return -1;  
    }

    struct channelClientNode *prev = NULL;
    struct channelClientNode *current = current_channel->clientList->premier;

    while (current != NULL) {
        if (current->client == client) { 
            if (prev == NULL) {
                current_channel->clientList->premier = current->next;
            } 
			else {
                prev->next = current->next;
            }

			char message[MSG_LEN];
			current_channel->clientList->clientNumber--;
			fprintf(stdout, "There are %d users in this channel\n", current_channel->clientList->clientNumber);

			snprintf(message, MSG_LEN, "You have left the channel %.128s\n", current_channel->channelName);
			send_message(listeClient, clientFD, message);

			if(current_channel->clientList->clientNumber == 0){
				snprintf(message, MSG_LEN, "You were the last user in this channel, %.128s has been destroyed\n", current_channel->channelName);
				send_message(listeClient, clientFD, message);
				delete_channel(listeChannel, current_channel->channelName);
			}
			
            client->is_in_a_channel = 0;
			client->permission = -1;
            memset(client->channelName, 0, NICKNAME_LEN); 

            free(current);
            current = NULL;

            return 0;  
        }
        prev = current;
        current = current->next;
    }

    return -1;  
}

int is_in_a_channel(struct nodeClient *currentClient){
	int flag = 0;
	if(currentClient->is_in_a_channel == 1){
		flag = 1;
	}

	return flag;
}


int verif_channel_name(struct clientListe *listeClient, struct channelListe *listeChannel, const char *channelName, int clientFD) {
    struct nodeChannel *current = listeChannel->premier;
	char reminder_msg[MSG_LEN]; 
	int flag = 0;

	if(listeChannel == NULL || channelName == NULL) {
    	return 1;
	}

	if(strlen(channelName) > MAX_LEN_NICKNAME){
		snprintf(reminder_msg, MSG_LEN, "%sThe channel name you have provided is too long. Please choose another one using '/create <other_channel_name>'\n%s", RED, RESET);
		send_message(listeClient, clientFD, reminder_msg);
		flag = 1;
	}

	for (int i = 0; i < strlen(channelName); i++){
        if (!((channelName[i] >= 'A' && channelName[i] <= 'Z') || (channelName[i] >= 'a' && channelName[i] <= 'z'))){
			if(flag == 1){
				break;
			}
			else{
				flag = 1;
				snprintf(reminder_msg, MSG_LEN, "%sAvoid using any special caracters or space for your channel name. Please choose another one using '/create <other_channel_name>'\n%s", RED, RESET);
				send_message(listeClient, clientFD, reminder_msg);
			}
        }
    }

	if(listeChannel->premier != NULL){
		while (current != NULL) {
			if(strcmp(current->channelName, channelName) == 0) {
				snprintf(reminder_msg, MSG_LEN, "%sThe name %s is already taken for another channel. Please choose another one using '/create <other_channel_name>'\n%s", RED, channelName, RESET);
				send_message(listeClient, clientFD, reminder_msg);
				flag = 1;
			}
			current = current->next; 
		}
	}
return flag;
}


int is_channel_exist(struct clientListe *listeClient, struct channelListe *listeChannel, const char *channelName, int clientFD){
	struct nodeChannel *current = listeChannel->premier;
	char reminder_msg[MSG_LEN];
	int flag = 0; 
	int count = 0;

	if(listeChannel->premier != NULL){
		while (current != NULL) {
			if(strcmp(current->channelName, channelName) == 0) {
				count++;
			}
			current = current->next; 
		}
	}

	if(count == 0){
		snprintf(reminder_msg, MSG_LEN, "%sThe name (%s) you provided is not registered in the channel list.\n%s", RED, channelName, RESET);
		send_message(listeClient, clientFD, reminder_msg);
		flag = 1;
	}

	return flag;
}


struct nodeClient *find_client_by_nickname(struct clientListe *listeClient, char *nickname){
	if (listeClient == NULL) {
        return NULL; 
    }

	struct nodeClient *current = listeClient->premier;
    while (current != NULL) {
        if (strcmp(current->nickname, nickname) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}


int handle_bind(char *argv[])
{
	int sfd;
	struct sockaddr_in servaddr;

	char *port_number = argv[1];
	int port = atoi(port_number);

	fprintf(stdout, "Use the following address to connect to the server : 127.0.0.1.\n");
	fprintf(stdout, "The port number is : %d\n", port);

	sfd = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
	{
		perror("setsockopt");
		return EXIT_FAILURE;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if (bind(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("bind");
		return EXIT_FAILURE;
	}

	return sfd;
}



void new_client_conexion(int *clientCount, struct pollfd fds[], int sfd, struct clientListe *listeClient)
{
	if (fds[0].revents & POLLIN) 
	{
		struct sockaddr_in clientAddress;
		socklen_t clientAddressLen = sizeof(clientAddress);

		memset(&clientAddress, 0, clientAddressLen);

		int newSocketFD = accept(sfd, (struct sockaddr *)&clientAddress, &clientAddressLen);
		if (newSocketFD == -1)
		{
			perror("accept");
			return;
		}

		fds[*clientCount].fd = newSocketFD;
		fds[*clientCount].events = POLLIN;

		(*clientCount)++;

		add_client(listeClient, newSocketFD, clientAddress);

		char welcome_msg[] = "\n[Server] : Please login using '/nick <nickname>'\n";
        send_message(listeClient, newSocketFD, welcome_msg);

		display_client_list(listeClient);
	}
}

void send_message_struct(struct clientListe *listeClient, int fd, struct message *msg) {
    struct nodeClient *currentClient = get_client(listeClient, fd);


    strncpy(msg->nick_sender, currentClient->nickname, MAX_LEN_NICKNAME - 1);
    msg->nick_sender[MAX_LEN_NICKNAME - 1] = '\0';


    if (send(fd, msg, sizeof(struct message), 0) <= 0) {
        fprintf(stdout, "Error: Failure to send message structure to client %d.\n", fd);
        return;
    }


    if (msg->pld_len > 1) {
        if (send(fd, msg->infos, msg->pld_len, 0) <= 0) {
            printf("Error: Failure to send message content to client %d.\n", fd);
            return;
        }
    }

    fprintf(stdout, "Message struct sent!\n");
}
char *serialize_message_struct(struct message *msg) {
 
    char *serialized = malloc(MSG_LEN);
    if (serialized == NULL) {
        return NULL;
    }


    snprintf(serialized, MSG_LEN, "%d:%.128s:%.512s", msg->type, msg->nick_sender, msg->infos);

    return serialized;
}



int verif_nickname(char *nickname, struct clientListe *listeClient, int currentFD){
	struct nodeClient *currentClient = listeClient->premier;
	char reminder_msg[MSG_LEN]; 
	int flag = 1;
	int count = 0;

	if(strlen(nickname) > MAX_LEN_NICKNAME){
		snprintf(reminder_msg, MSG_LEN, "%s The nickname you provided is too long. Please choose another using '/nick <nickname>'\n%s", RED, RESET);
		send_message(listeClient, currentFD, reminder_msg);
		flag = 0;
	}

	if(flag != 0){
		for (int i = 0; i < strlen(nickname); i++){
			if (!((nickname[i] >= 'A' && nickname[i] <= 'Z') || (nickname[i] >= 'a' && nickname[i] <= 'z'))){
				count++;
				flag = 0;
			}
		}
	}

	if(count !=0){
		snprintf(reminder_msg, MSG_LEN, "%sAvoid using any special caracters or space in your nickname. Please choose another using '/nick <nickname>'%s\n", RED, RESET);
		send_message(listeClient, currentFD, reminder_msg);
	}

	if(flag != 0){
		while (currentClient != NULL) {
			if(strcmp(currentClient->nickname, nickname) == 0){
				snprintf(reminder_msg, MSG_LEN, "%sThe nickname you provided is already taken. Please choose another using '/nick <nickname>'\n%s", RED, RESET);
				send_message(listeClient, currentFD, reminder_msg);
				flag = 0;
			}
			currentClient = currentClient->next;
		}
	}

	if(flag == 1){
		struct nodeClient *clientToAuthentified = get_client(listeClient, currentFD);
		if(clientToAuthentified->authenticated == 0){
			snprintf(reminder_msg, MSG_LEN, "\nNickname registered successfully. Welcome to the server %s.\nYou can see the list of the commands available on the server with %s/cmd%s\nYou can obtain information on a precise command by typing /man <the_command>, ex: /man /nick\n", nickname, BLUE, RESET);
			clientToAuthentified->authenticated = 1;
			strcpy(clientToAuthentified->nickname, nickname);
			send_message(listeClient, currentFD, reminder_msg);
		}
		else{
			snprintf(reminder_msg, MSG_LEN, "\nYour new nickname has been registered successfully.\n");
			clientToAuthentified->authenticated = 1;
			strcpy(clientToAuthentified->nickname, nickname);
			send_message(listeClient, currentFD, reminder_msg);
		}
		return EXIT_SUCCESS;
	}
	else{
		return EXIT_FAILURE;
	}
}


char* generate_nickname_list(struct clientListe *listeClient, int *clientCount) {
    char* nickname_list = malloc(MSG_LEN);
    strcpy(nickname_list, "Online users are\n");

    struct nodeClient *current = listeClient->premier;
    while(current != NULL) {
        strcat(nickname_list, "  - ");
        strcat(nickname_list, current->nickname);
        strcat(nickname_list, "\n");
        current = current->next;
	}

    return nickname_list;
}

char *display_cmd(){
	char* display = malloc(MSG_LEN);
    strcpy(display, "Commands available on this server are:\n");

	const char *cmd_list[] = {"/cmd", "/man", "/nick", "/who", "/whois", "/msgall", "/msg", "/create", "/join", "/leave", "/channel_list", "/who_channel", "/kick", "/send"};

	for(int i=0; i<14; i++){
		strcat(display, "  - ");
        strcat(display, cmd_list[i]);
        strcat(display, "\n");
	}

	return display;
}




void extract_after_keyword(const char* source, const char* keyword, char* result) {
    const char* keyword_position = strstr(source, keyword);

    if (keyword_position != NULL) {
        keyword_position = keyword_position + strlen(keyword);
		strcpy(result, keyword_position);
		result[strlen(result) - 1] = '\0';
    } 
	else {
        result[0] = '\0';
    }
}

int use_command(char message[MSG_LEN]){
	const char *cmd_list[] = {"/cmd", "/man", "/nick", "/who", "/whois", "/msgall", "/msg", "/create", "/join", "/leave", "/channel_list", "/who_channel", "/kick", "/send"};
	for(int i = 0; i<14 ; i++){
		if(strncmp(cmd_list[i], message, strlen(cmd_list[i])) == 0){
			return 0;
		}
	}
	return 1;
}


char **extract_after_keyword_file(char *buff, char *keyword)
{
	char *found = strstr(buff, keyword);
	if (found)
	{
		char **result = malloc(3 * sizeof(char *));
		if (!result)
		{
			return NULL;
		}


		for (int i = 0; i < 3; i++)
		{
			result[i] = NULL;
		}


		found += strlen(keyword);


		char *token = strtok(found, " ");
		for (int i = 0; i < 3 && token != NULL; i++)
		{
			result[i] = strdup(token);
			token = strtok(NULL, " ");
		}
		return result;
	}
	return NULL;
}

void print_file_transfer_request(FileTransferRequest *request) {
    if (request == NULL) {
       fprintf(stdout, "FileTransferRequest is NULL\n");
        return;
    }

    fprintf(stdout, "File Transfer Request Details:\n");
    fprintf(stdout, "Sender: %s\n", request->sender);
    fprintf(stdout, "Sender FD: %d\n", request->sender_fd);
    fprintf(stdout, "Sender IP: %s\n", request->sender_ip);
    fprintf(stdout, "Sender Port: %d\n", request->sender_port);
    fprintf(stdout, "Receiver: %s\n", request->receiver);
    fprintf(stdout, "Receiver FD: %d\n", request->receiver_fd);
    fprintf(stdout, "Receiver IP: %s\n", request->receiver_ip);
    fprintf(stdout, "Receiver Port: %d\n", request->receiver_port);
    fprintf(stdout, "Filename: %s\n", request->filename);
    fprintf(stdout, "Filepath: %s\n", request->filepath);
    fprintf(stdout, "Status: %d\n", request->status);
}

void print_msgstruct(struct message msgstruct) {
    fprintf(stdout, "Message Structure Details:\n");
    fprintf(stdout, "Type: %d\n", msgstruct.type);
    fprintf(stdout, "Payload Length: %d\n", msgstruct.pld_len);
    fprintf(stdout, "Sender Nickname: %s\n", msgstruct.nick_sender);
    fprintf(stdout, "Infos: %s\n", msgstruct.infos);
}





void add_file_transfer_request(FileTransferList *list, FileTransferRequest *newRequest)
{

	if (list->premier == NULL)
	{
		
		list->premier = newRequest;
	}
	else
	{
		FileTransferRequest *current = list->premier;
		while (current->next != NULL)
		{
			current = current->next;
		}
	
		current->next = newRequest;
	}

	newRequest->next = NULL;
}



void free_memory(int *clientCount, struct pollfd fds[], struct clientListe *listeClient) {
    for (int i = 0; i < *clientCount; i++) {
        close(fds[i].fd);
    }
    free_client_list(listeClient);
    listeClient = NULL;
}


void free_fileTransferRequest(FileTransferRequest *request) {
    if (request == NULL) return;


    free(request);
}

void free_fileTransferList(FileTransferList *list) {
    if (list == NULL) return;

    FileTransferRequest *current = list->premier;
    FileTransferRequest *next;

    while (current != NULL) {
        next = current->next;
        free_fileTransferRequest(current);
        current = next;
    }

    free(list);
}


void reception_and_emission(int *clientCount, struct pollfd fds[], struct clientListe *listeClient, struct channelListe *listeChannel, struct FileTransferList *FileTransferList ){
    struct message msgstruct;
    char buff[MSG_LEN];
    for(int i = 1; i < *clientCount; i++){
        if(fds[i].revents & POLLIN){
            memset(&msgstruct, 0, sizeof(struct message));
            memset(buff, 0, MSG_LEN);


            int len = recv(fds[i].fd, &msgstruct, sizeof(struct message), 0);
            if(len <= 0){
                fprintf(stdout, "Client with FD=%d was disconnected or there was an error when communicating.\n", fds[i].fd);
				fprintf(stdout, "\n");
                delete_client(listeClient, fds[i].fd);
                close(fds[i].fd);
                fds[i] = fds[*clientCount - 1];
                (*clientCount)--;
                i--; 
                continue;
            }
			

            len = recv(fds[i].fd, buff, msgstruct.pld_len, 0);
            if(len <= 0){
                fprintf(stdout, "Error: Connection with client FD=%d was lost\n", fds[i].fd);
				fprintf(stdout, "\n");
                delete_client(listeClient, fds[i].fd);
                close(fds[i].fd);
                fds[i] = fds[*clientCount - 1];
                (*clientCount)--;
                i--; 
                continue;
            }
			else if(strcmp(buff, "/quit\n") == 0){  				
				fprintf(stdout, "Client %d was disconnected\n", fds[i].fd);
				fprintf(stdout, "\n");
                delete_client(listeClient, fds[i].fd);
                close(fds[i].fd);
                fds[i] = fds[*clientCount - 1];
                (*clientCount)--;
                i--; 
                continue;
			}

			struct nodeClient *currentClient = get_client(listeClient, fds[i].fd);
			snprintf(msgstruct.nick_sender, MSG_LEN, "%s", currentClient->nickname);


			if((msgstruct.type == NICKNAME_NEW) || (currentClient->authenticated == 0)){
                if(strncmp(buff, "/nick", 5) == 0){
            		char nickname[MSG_LEN];


					snprintf(nickname, MSG_LEN, "%s", msgstruct.infos);
					
					if(verif_nickname(nickname, listeClient,  fds[i].fd) == EXIT_SUCCESS){
						snprintf(nickname, MSG_LEN, "%s", msgstruct.nick_sender);
					}
                } 
				else{
					char reminder_msg[MSG_LEN];
					snprintf(reminder_msg, MSG_LEN, "%s", "Please authenticate using '/nick <nickname>' and respect all the criterias\n");
					
					send_message(listeClient, fds[i].fd, reminder_msg);
					continue;
				}
;
			}
			else if(msgstruct.type == NICKNAME_LIST){
				char* nickname_list = generate_nickname_list(listeClient, clientCount);
				send_message(listeClient, fds[i].fd, nickname_list);
				fprintf(stdout, "pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
				free(nickname_list);
			}
			else if(msgstruct.type == NICKNAME_INFOS){	
				char nickname_aimed[MSG_LEN];

				snprintf(nickname_aimed, MSG_LEN, "%s",  msgstruct.infos);

				struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nickname_aimed);
				if(clientAimed == NULL){
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "Error: User was not found.\n");

					send_message(listeClient, fds[i].fd, message);
					printf("\n");
				}
				else{
					char info[MSG_LEN];
					char ip[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &clientAimed->address.sin_addr, ip, INET_ADDRSTRLEN);

					char time_buff[80];

					struct tm* time_info = localtime(&clientAimed->connection_time);
					strftime(time_buff, sizeof(time_buff), "%Y-%m-%d %H:%M:%S", time_info); 

					snprintf(info, MSG_LEN, "%s is connected since %s with IP address %s and port number %d", clientAimed->nickname, time_buff, ip, ntohs(clientAimed->address.sin_port));
					strcat(info, "\n");

					send_message(listeClient, fds[i].fd, info);
				}

				fprintf(stdout, "pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
				fprintf(stdout, "\n");
			}
			else if(msgstruct.type == BROADCAST_SEND){
				char message[MSG_LEN];
				char message_to_broadcast[MSG_LEN];

				for(int j = 1; j < *clientCount; j++) {
        			if(fds[j].fd != fds[i].fd) {
            			extract_after_keyword(buff, "/msgall ", message);
						snprintf(message_to_broadcast, MSG_LEN, "[%s]: %s\n", currentClient->nickname, message);
            			send_message(listeClient, fds[j].fd, message_to_broadcast);
        			}
				}
				printf("pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);

				char confirmation[MSG_LEN]; 
				snprintf(confirmation, MSG_LEN, "Broadcast done\n"); 

				send_message(listeClient, fds[i].fd, confirmation);
				printf("\n");
				}
			else if(msgstruct.type == UNICAST_SEND){
				char nickname[MSG_LEN];
                
				snprintf(nickname, MSG_LEN, "%s", msgstruct.infos);
				char *first_space = strchr(nickname, ' ');
				if (first_space != NULL){
					*first_space = '\0';
    			}

				if(strlen(nickname) == 0){
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "Please enter a nickname\n");

					send_message(listeClient, fds[i].fd, message);
				}
				
				struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nickname);
				if(clientAimed == NULL){
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "%s[Server] -- Error: User %s does not exist\n%s", RED, nickname, RESET);
					send_message(listeClient, fds[i].fd, message);
					fprintf(stdout, "\n");
				}
				else{
					char message[MSG_LEN];
					extract_after_keyword(buff, nickname, message);

					char message_to_broadcast[MSG_LEN];
					snprintf(message_to_broadcast, MSG_LEN, "[%s]:%s\n", currentClient->nickname, message);

					struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nickname);
				
					send_message(listeClient, clientAimed->socketFD, message_to_broadcast);
					fprintf(stdout, "pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
					
					snprintf(message, MSG_LEN, "Your message has been sent\n");
					send_message(listeClient, fds[i].fd, message);
					fprintf(stdout, "\n");
				}
			}
			else if(msgstruct.type == ASK_CMD){
				char *command_list = display_cmd();

				send_message(listeClient, fds[i].fd, command_list);
				fprintf(stdout, "\n");
				free(command_list);
			}
			else if(msgstruct.type == MAN_CMD){
				char cmd[MSG_LEN];
				snprintf(cmd, MSG_LEN, "%s", msgstruct.infos);

				if(strcmp(cmd, "/nick") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to register your nickname. Once you've register you can change it by using this command again.\ne.g '/nick <nickname>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/who") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to get the list of clients connected to the server\ne.g '/whos'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/whois") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to acquire information regarding a specific client\ne.g '/whois <nickname>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/msgall") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to broadcast a message to all the clients connected oto the server\ne.g '/msgall <message>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/msg") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to send a private message to another user.\ne.g '/msg <nickname> <message>\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/create") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to create a channel.\ne.g '/create <channel_name>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/create") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to join a channel.\ne.g '/join <channel_name>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/leave") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to leave a channel. If you were the last user in said channel, the channel will be deleted.\ne.g '/leave <channel_name>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/who_channel") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to know who is in a specific channel.\ne.g /who_channel\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/kick") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to kick someone from a specific channel. Admins or users with additionnal rights are not affected\ne.g '/kick <nickname>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else if(strcmp(cmd, "/send") == 0){
					snprintf(buff, MSG_LEN, "[Server] : This command is used to send a file to another user.\ne.g '/send <file_name> <nickname>'\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
				else{
					snprintf(buff, MSG_LEN, "[Server] : This command does not exist.\nUse /cmd to see the commands available on this server\n");
					send_message(listeClient, fds[i].fd, buff);
					fprintf(stdout, "\n");
				}
			}
			else if(msgstruct.type == MULTICAST_CREATE){
				char channelName[MSG_LEN];
				char message[MSG_LEN];
				snprintf(channelName, MSG_LEN, "%s",  msgstruct.infos);

				if(currentClient->is_in_a_channel == 1){
					leave_channel(listeClient, listeChannel, currentClient->channelName, currentClient, fds[i].fd);
				}

				if((verif_channel_name(listeClient, listeChannel, channelName, fds[i].fd)) == 0){
					create_channel(listeClient, listeChannel, channelName, currentClient, fds[i].fd);

					snprintf(message, MSG_LEN, "[Server] : You have created the channel %.128s\n", channelName);

					send_message(listeClient, fds[i].fd, message);
				}
			}	
			else if(msgstruct.type == MULTICAST_JOIN){
				char channelName[MSG_LEN];
				char message[MSG_LEN];

				snprintf(channelName, MSG_LEN, "%s",  msgstruct.infos);

				if((currentClient->is_in_a_channel == 1) && (strcmp(channelName, currentClient->channelName)) != 0){
					leave_channel(listeClient, listeChannel, currentClient->channelName, currentClient, fds[i].fd);
				}	

				if(is_channel_exist(listeClient, listeChannel,  channelName, fds[i].fd) == 0){
					printf("uhfje\n");
					if(strcmp(channelName, currentClient->channelName) == 0){
						snprintf(message, MSG_LEN, "%s[Server] : You have already joined the server %.128s%s\n", RED, channelName, RESET);

						send_message(listeClient, fds[i].fd, message);
					}
					else{
						join_channel(listeChannel, channelName, currentClient);

						snprintf(message, MSG_LEN, "%s[Server] : You have joined the channel %.128s%s\n", GREEN, channelName, RESET);

						send_message(listeClient, fds[i].fd, message);
					}
					for(int j = 1; j < *clientCount+1; j++){
						if(fds[j].fd != fds[i].fd) {
							struct nodeClient *receiverClient = get_client(listeClient, fds[j].fd);
							if(receiverClient == NULL) {
								continue;
							}
							if(strcmp(receiverClient->channelName, channelName) == 0) {
								snprintf(message, MSG_LEN, "[%.128s]> INFO> : %.128s has joined %.128s\n", channelName, currentClient->nickname, channelName);
								send_message(listeClient, fds[j].fd, message);
							}
						}
					}
				}
			}
			else if(msgstruct.type == MULTICAST_QUIT){
				char channelName[MSG_LEN];
				snprintf(channelName, MSG_LEN, "%s", currentClient->channelName);

				char message[MSG_LEN];

				if(currentClient->is_in_a_channel == 0){
					snprintf(message, MSG_LEN, "%s[Sever]: You are not currently in a channel.\n%s", RED, RESET);
					send_message(listeClient, fds[i].fd, message);
				}
				else{
					for(int j = 1; j < *clientCount+1; j++){
						if(fds[j].fd != fds[i].fd) {
							struct nodeClient *receiverClient = get_client(listeClient, fds[j].fd);
							if(receiverClient == NULL) {
								continue;
							}
							
							if(strcmp(receiverClient->channelName, currentClient->channelName) == 0) {
								snprintf(message, MSG_LEN, "[%.128s]> INFO> %.128s has left %.128s\n", currentClient->channelName, currentClient->nickname, currentClient->channelName);
								send_message(listeClient, fds[j].fd, message);
							}
						}
				}

				leave_channel(listeClient, listeChannel, channelName, currentClient, fds[i].fd);
				send_message(listeClient, fds[i].fd, message);
				}
			}
			else if(msgstruct.type == MULTICAST_SEND){
				char message[MSG_LEN];
				for(int j = 1; j < *clientCount+1; j++){
					if(fds[j].fd != fds[i].fd) {
						struct nodeClient *receiverClient = get_client(listeClient, fds[j].fd);
						if(receiverClient == NULL) {
							continue;
						}
						
						if(strcmp(receiverClient->channelName, currentClient->channelName) == 0) {
							snprintf(message, MSG_LEN, "[%.512s]: %.128s", currentClient->nickname, buff);
							send_message(listeClient, fds[j].fd, message);
						}
					}
				}
				char confirmation[MSG_LEN];
				snprintf(confirmation, MSG_LEN, "Multicast done\n"); 

				send_message(listeClient, fds[i].fd, confirmation);
				fprintf(stdout, "pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
			}
			else if(msgstruct.type == MULTICAST_LIST){
				char* channel_list = generate_channel_list(listeChannel);
				
				send_message(listeClient, fds[i].fd, channel_list);
				free(channel_list);

			}
			else if(msgstruct.type == MULTICAST_WHO){
				if(currentClient->is_in_a_channel == 1){
					char liste[MSG_LEN];

					snprintf(liste, MSG_LEN, "%s", generate_nickname_list_of_a_channel(listeClient, listeChannel, currentClient->channelName));
					send_message(listeClient, fds[i].fd, liste);
				}
				else{
					char liste[MSG_LEN];

					snprintf(liste, MSG_LEN, "%sYou are not currently in a channel, therefore you cannot use this command\n%s", RED, RESET);
					send_message(listeClient, fds[i].fd, liste);
				}
			}
			else if(msgstruct.type == MULTICAST_KICK){
				if(currentClient->is_in_a_channel == 1){
					char nameClientToKick[MSG_LEN];
					snprintf(nameClientToKick, MSG_LEN, "%s", msgstruct.infos);

					struct nodeClient *clientTokick = find_client_by_nickname(listeClient, nameClientToKick);

					char message[MSG_LEN];

					if(clientTokick == NULL){
						snprintf(message, MSG_LEN, "%s[Server] -- Error: %.512s does not exist.\n%s", RED, nameClientToKick, RESET);
						send_message(listeClient, fds[i].fd, message);
						break;
					}
					else if(strcmp(clientTokick->channelName, currentClient->channelName) != 0){
						snprintf(message, MSG_LEN, "%s[Server] -- Error: %.512s is not in the same channel.\n%s", RED, nameClientToKick, RESET);
						send_message(listeClient, fds[i].fd, message);
					}
					else if(currentClient->permission < 1){
						snprintf(message, MSG_LEN, "%s[Server]: You do not have the permission to kick someone\n%s", RED, RESET);
						send_message(listeClient, fds[i].fd, message);
					}
					else if(clientTokick->permission > currentClient->permission){
						snprintf(message, MSG_LEN, "%s[Server]: You cannot kick an user with more rights/permissions\n%s", RED, RESET);
						send_message(listeClient, fds[i].fd, message);
					}
					else{
						for(int j = 1; j < *clientCount+1; j++){
							if(fds[j].fd != fds[i].fd) {
								struct nodeClient *receiverClient = get_client(listeClient, fds[j].fd);
								if(receiverClient == NULL) {
									continue;
								}
								
								if((strcmp(receiverClient->channelName, currentClient->channelName) == 0) && (strcmp(receiverClient->nickname, clientTokick->nickname) != 0)) {
									snprintf(message, MSG_LEN, "[%.128s]> INFO> %.128s kicked %.512s\n", currentClient->channelName, currentClient->nickname, clientTokick->nickname);
									send_message(listeClient, fds[j].fd, message);
								}
							}
						}
						leave_channel(listeClient, listeChannel, currentClient->channelName, clientTokick, clientTokick->socketFD);

						snprintf(message, MSG_LEN, "You kicked %.512s from the channel %.128s\n", clientTokick->nickname, currentClient->channelName);

						send_message(listeClient, fds[i].fd, message);

						snprintf(message, MSG_LEN, "You have been kicked by %.512s from the channel %.128s\n", currentClient->nickname, currentClient->channelName);

						send_message(listeClient, clientTokick->socketFD, message);
					}
				}
				else{
					char liste[MSG_LEN];

					snprintf(liste, MSG_LEN, "%sYou are not currently in a channel, therefore you can't use this command\n%s", RED, RESET);
					send_message(listeClient, fds[i].fd, liste);
				}
			}
<<<<<<< HEAD
=======
			else if(msgstruct.type == MULTICAST_MUTE){
				if(currentClient->is_in_a_channel == 1){
					char nameClientToMute[MSG_LEN];
					snprintf(nameClientToMute, MSG_LEN, "%s", msgstruct.infos);

				
					struct nodeClient *clientToMute = find_client_by_nickname(listeClient, nameClientToMute);
	
					if((clientToMute != NULL)){
						if((clientToMute != NULL) && (strcmp(clientToMute->channelName, currentClient->channelName) == 0) && (currentClient->permission > clientToMute->permission)){
							
							struct nodeChannel *channel = find_channel_by_name(listeChannel, clientToMute->channelName);
							muteClientInChannel(channel, clientToMute,mutedClients);

							char message[MSG_LEN];
							snprintf(message, MSG_LEN, "%sYou have been muted by %.128s. Wait to be unmuted to chat again in this channel.\n%s", RED, currentClient->nickname, RESET);

							send_message(listeClient, clientToMute->socketFD, message);

							snprintf(message, MSG_LEN, "%.128s has been muted.\n", clientToMute->nickname);

							send_message(listeClient, fds[i].fd, message);
						}
						else if(currentClient->permission <= clientToMute->permission){
							char message[MSG_LEN];
							snprintf(message, MSG_LEN, "%sYou cannot mute %.512s because he possesses more rights/permissions.\n%s", RED, clientToMute->nickname, RESET);

							send_message(listeClient, currentClient->socketFD, message);
						}
						else{
							char message[MSG_LEN];
							snprintf(message, MSG_LEN, "%s%.512s is not in the channel\n%s", RED, clientToMute->nickname, RESET);

							send_message(listeClient, currentClient->socketFD, message);
						}
					}
					else{
						char message[MSG_LEN];
						snprintf(message, MSG_LEN, "%sThe client you want to mute does not exist\n%s", RED, RESET);

						send_message(listeClient, currentClient->socketFD, message);
					}
				}
				else{
					char liste[MSG_LEN];

					snprintf(liste, MSG_LEN, "%sYou are not currently in a channel, therefore you can't use this command\n%s", RED, RESET);
					send_message(listeClient, fds[i].fd, liste);
				}
			}
			else if(msgstruct.type == MUTED){
				char message[MSG_LEN];
				snprintf(message, MSG_LEN, "You are muted. Wait to be unmuted to chat again on this channel\n");

				send_message(listeClient, fds[i].fd, message);
			}
			else if(msgstruct.type == MULTICAST_UNMUTE){
				if(currentClient->is_in_a_channel == 1){
					char nameClientToUnMute[MSG_LEN];
					snprintf(nameClientToUnMute, MSG_LEN, "%s", msgstruct.infos);

					struct nodeClient *clientToUnMute = find_client_by_nickname(listeClient, nameClientToUnMute);

					struct nodeChannel *currentChannel = find_channel_by_name(listeChannel, currentClient->channelName);

					struct mutedClientList *clientListMuted = currentChannel->mutedClients;

					if((clientToUnMute != NULL)){
						if((clientToUnMute != NULL) && (strcmp(clientToUnMute->channelName, currentClient->channelName) == 0) && (currentClient->permission > clientToUnMute->permission)){
							
							removeMutedClient(clientListMuted, clientToUnMute);

							char message[MSG_LEN];

							snprintf(message, MSG_LEN, "You have been unmute\n");
							send_message(listeClient, clientToUnMute->socketFD, message);	
						}
						else if(currentClient->permission <= clientToUnMute->permission){
							char message[MSG_LEN];
							snprintf(message, MSG_LEN, "%sYou cannot unmute %.128s because he possesses more rights/permissions.\n%s", RED, clientToUnMute->nickname, RESET);

							send_message(listeClient, currentClient->socketFD, message);
						}
						else{
							char message[MSG_LEN];
							snprintf(message, MSG_LEN, "%s%.128s is not in the channel\n%s", RED, clientToUnMute->nickname, RESET);

							send_message(listeClient, currentClient->socketFD, message);
						}
					}
					else{
						char message[MSG_LEN];
						snprintf(message, MSG_LEN, "%sThe client you want to mute does not exist\n%s", RED, RESET);

						send_message(listeClient, currentClient->socketFD, message);
					}
				}	
				else{
					char liste[MSG_LEN];

					snprintf(liste, MSG_LEN, "%s are not in a channel, therefore you can't use this command\n%s", RED, RESET);
					send_message(listeClient, fds[i].fd, liste);
				}
			}
>>>>>>> dc7bc8c458fdaf56fae9a0255bd36e9a9d25cf99
			else if(msgstruct.type == FILE_REQUEST)
			{
				char **information = extract_after_keyword_file(buff, "/send");
				if (information != NULL && information[0] != NULL && information[1] != NULL)
				{
					char *nick_receive = information[0];
					char *file_name = information[1];
					struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nick_receive);

					if (clientAimed == NULL)
					{
						char message[MSG_LEN];
						snprintf(message, MSG_LEN, "[Server] -- Error: User %s does not exist\n", nick_receive);
						send_message(listeClient,fds[i].fd, message);
						fprintf(stdout, "\n");
					}
					else
					{
						FileTransferRequest *newFile = malloc(sizeof(FileTransferRequest));
						if (newFile != NULL) {
							strncpy(newFile->sender, currentClient->nickname, MAX_LEN_NICKNAME - 1);
							newFile->sender[MAX_LEN_NICKNAME - 1] = '\0';

							strncpy(newFile->receiver, nick_receive, MAX_LEN_NICKNAME - 1);
							newFile->receiver[MAX_LEN_NICKNAME - 1] = '\0';

							strncpy(newFile->filename, file_name, MSG_LEN - 1);
							newFile->filename[MSG_LEN - 1] = '\0';


							newFile->sender_fd = currentClient->socketFD;
							strncpy(newFile->sender_ip, inet_ntoa(currentClient->address.sin_addr), MAX_LEN_NICKNAME - 1);
							newFile->sender_ip[MAX_LEN_NICKNAME - 1] = '\0';
							newFile->sender_port = ntohs(currentClient->address.sin_port);

							
							newFile->receiver_fd = clientAimed->socketFD;
							strncpy(newFile->receiver_ip, inet_ntoa(clientAimed->address.sin_addr), MAX_LEN_NICKNAME - 1);
							newFile->receiver_ip[MAX_LEN_NICKNAME - 1] = '\0';
							newFile->receiver_port = ntohs(clientAimed->address.sin_port);

						
							snprintf(newFile->filepath, MSG_LEN, "%s", file_name);
							
							msgstruct.infos[sizeof(msgstruct.infos) - 1] = '\0';
							newFile->status = 0;
							newFile->next = NULL;
							newFile->clients = NULL;
							char message_to_send[MSG_LEN];
							snprintf(message_to_send, MSG_LEN, "%.128s wants to share a file named : %s. Accept? [Y/N]\n", currentClient->nickname, file_name);
							send_message(listeClient,newFile->receiver_fd, message_to_send);
							strncpy(msgstruct.infos, newFile->filepath, sizeof(msgstruct.infos));
							send_message_struct(listeClient, newFile->receiver_fd, &msgstruct);
							newFile->next = FileTransferList->premier;
							FileTransferList->premier = newFile;
							
						}
						else
						{
							fprintf(stdout, "Error: Failure to allocate memory to a new file transfer request.\n");
						}
						
					}
					for (int i = 0; i < 2; i++)
					{
						free(information[i]);
					}
					free(information);
				}
				else
				{
					fprintf(stdout, "Error: Failure to extract file transfer information.\n");
				}
			}
			else if(msgstruct.type == FILE_ACCEPT) {
				const char *message = "Here is the type";

		
				if (FileTransferList == NULL || FileTransferList->premier == NULL) {
					fprintf(stderr, "FileTransferList or its first element is NULL\n");
					return;
				}

			
				strncpy(msgstruct.infos, FileTransferList->premier->filepath, sizeof(msgstruct.infos));
				msgstruct.infos[sizeof(msgstruct.infos) - 1] = '\0';
				send_message_struct(listeClient, FileTransferList->premier->receiver_fd, &msgstruct);

				
				msgstruct.type = SETUP_LISTENER;
				msgstruct.pld_len = strlen(message) + 1;
				
			
				snprintf(msgstruct.nick_sender, sizeof(msgstruct.nick_sender), "%s", FileTransferList->premier->sender);

				print_file_transfer_request(FileTransferList->premier);
				print_msgstruct(msgstruct);

				send_message_struct(listeClient, FileTransferList->premier->sender_fd, &msgstruct);
				
			}
			else if (msgstruct.type == FILE_REJECT)
			{
				
				char message[MSG_LEN];
				snprintf(message, MSG_LEN, "%s rejected the transfer\n", FileTransferList->premier->receiver);
				send_message(listeClient,FileTransferList->premier->sender, message);
				
				
				if (FileTransferList->premier->status == 1)
				{
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "The transfer has already been accepted\n");
					send_message(listeClient,fds[i].fd, message);
				}
				else if (FileTransferList->premier->status == 2)
				{
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "The transfer has been rejected\n");
					send_message(listeClient,fds[i].fd, message);
				}
				else if (FileTransferList->premier->status == 3)
				{
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "The transfer has been completed\n");
					send_message(listeClient,fds[i].fd, message);
				}
				else
				{
					perror("Error: Structure failed");
					return;
				}
			}
			else if(msgstruct.type == FILE_ACK) {
				
				memset(&msgstruct, 0, sizeof(struct message));
            	memset(buff, 0, MSG_LEN);
				msgstruct.type = FILE_ACK;
				char message[MSG_LEN];
				snprintf(message, MSG_LEN, "File transfer completed successfully.\n");
				send_message(listeClient,FileTransferList->premier->sender_fd, message);
				send_message(listeClient,FileTransferList->premier->receiver_fd, message);
				fprintf(stdout, "\n");
			}
			else{ 
				char message[MSG_LEN];
				snprintf(message, MSG_LEN, "[Echo]: %.1015s", buff);
				send_message(listeClient, fds[i].fd, message);
				fprintf(stdout, "\n");
			}
        }
    }
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("Invalid input : Please use './server <port_number>' \n");
		return EXIT_FAILURE;
	}

	int sfd = handle_bind(argv);

	if (listen(sfd, 5) != 0)
	{
		perror("listen() error");
		exit(EXIT_FAILURE);
	}

	struct pollfd fds[MAX_CLIENT_NUMBER];
	fds[0].fd = sfd;
	fds[0].events = POLLIN;

	int clientCount = 1;

	struct clientListe *listeClient = malloc(sizeof(struct clientListe));
	if(listeClient==NULL)
	{
		exit(EXIT_FAILURE);
	}
	listeClient->premier = NULL;

	struct channelListe *listeChannel = malloc(sizeof(struct clientListe));
	if(listeChannel==NULL)
	{
		exit(EXIT_FAILURE);
	}
	listeChannel->premier = NULL;



	
	struct FileTransferList *FileTransferList = malloc(sizeof(struct FileTransferList));
	if (FileTransferList == NULL)
	{
		exit(EXIT_FAILURE);
	}
	FileTransferList->premier = NULL;

	while (1)
	{
		int ret = poll(fds, clientCount, -1);
		if (ret == -1)
		{
			perror("poll");
			exit(EXIT_FAILURE);
		}

		new_client_conexion(&clientCount, fds, sfd, listeClient);
		reception_and_emission(&clientCount, fds, listeClient, listeChannel, FileTransferList);

		if (clientCount == 1)
		{
			fprintf(stdout, "There is not any clients connected anymore: server shutdown\n");
			break;
		}
	}
	
	free_memory(&clientCount, fds, listeClient);
	free_channel_list(listeChannel);
	free_fileTransferList(FileTransferList);

	return EXIT_SUCCESS;
}
