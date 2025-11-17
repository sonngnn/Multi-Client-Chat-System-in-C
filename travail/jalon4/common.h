#define SERV_PORT "8080"
#define SERV_ADDR "127.0.0.1"
#define MSG_LEN (1024)
#define MAX_CLIENT_NUMBER (10)
#define MAX_LEN_NICKNAME (15)
#define MAX_SALONS (2)
#define NOM_SALON_LEN (15)
#define NICKNAME_LEN (1024)
#define MAX_CHANNEL_NUMBER (10)
#define MAX_CHANNEL_CLIENT_NUMBER (10)
#define MAX_FILE_TRANSFER_NUMBER (10)
#define MAX_FILE_TRANSFER_CLIENT_NUMBER (10)
#define MAX_FILE_TRANSFER_NAME (1024)
#define MAX_FILE_TRANSFER_PATH (1024)
#define MAX_FILE_TRANSFER_IP (1024)

struct info{
    short s;
    long l;
};


struct clientListe{
    struct nodeClient *premier;
};

struct nodeClient{
    int socketFD;
    int authenticated;
    int is_in_a_channel;
    int permission;
    char channelName[NICKNAME_LEN];
    time_t connection_time;
    char nickname[NICKNAME_LEN];
    struct sockaddr_in address;
    struct nodeClient *next;
};


struct channelListe{
    struct nodeChannel *premier;
};

struct channelClientList {
    struct channelClientNode *premier;
    int clientNumber;
};

struct channelClientNode {
    struct nodeClient *client; 
    struct channelClientNode *next;
};

struct nodeChannel{
    char channelName[NICKNAME_LEN];
    struct channelClientList *clientList;
    struct nodeChannel *next;
};


typedef struct FileTransferRequest {
    char sender[MAX_LEN_NICKNAME];
    int sender_fd;
    char sender_ip[MAX_LEN_NICKNAME];
    int sender_port;
    char receiver[MAX_LEN_NICKNAME];
    int receiver_fd;
    char receiver_ip[MAX_LEN_NICKNAME];
    int receiver_port;
    char filename[MSG_LEN];
    char filepath[MSG_LEN];
    int status;
    struct nodeClient *clients;
    struct FileTransferRequest *next;
}FileTransferRequest;

typedef struct FileTransferList {
    FileTransferRequest *premier;
}FileTransferList;
