#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <time.h>
#include <netdb.h>
#include <strings.h>
#include <cursesw.h>

#define BUFFER_SIZE 4096


unsigned short check_sum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

uint32_t get_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
}

bool
check_packet ( icmp* packet ) {
    unsigned short packet_cksum = packet->icmp_cksum;
    packet->icmp_cksum = 0;
    bool result = (packet_cksum == check_sum((unsigned short*)packet, sizeof(*packet)));
    packet->icmp_cksum = packet_cksum;
    return result;
}

int
main ( int argc, char *argv[] ) {
    const char *hostName;
    if (argc < 2) {
        hostName = "www.github.com";
    } else {
        hostName = argv[1];
    }

    struct hostent *hp;
    if ((hp = gethostbyname(hostName)) == 0) {
        printf("get host name error\n");
        return 3;
    }

    sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    bcopy(hp->h_addr, &dest.sin_addr, hp->h_length);

    if (dest.sin_addr.s_addr == (unsigned)-1) {
        printf("not valid host\n");
        return 2;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if ( sock < 0 ) {
        close(sock);
        printf("failed create socket. R U sudo?\n");
        return 3;
    }

    struct timeval time_out = {0};
    time_out.tv_sec = 5;
    time_out.tv_usec =0;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &time_out, sizeof(timeval))<0){
        printf("failed set socket opt\n");
        return 3;
    }

    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&time_out,
            sizeof(time_out)) < 0){
        printf("failed set socket opt\n");
        return 3;
    }

    sockaddr_in src = {0};
    src.sin_family = AF_INET;

    if ( bind(sock, (sockaddr*)&src, sizeof(src)) < 0 ) {
        close(sock);
        printf("cant open socket\n");
        return 4;
    }

    icmp out = {0};
    out.icmp_type = 13;
    out.icmp_id = getpid();
    out.icmp_otime = htonl(get_time());
    out.icmp_cksum = check_sum((unsigned short*)&out, sizeof(out));

    if ( sendto(sock, &out, sizeof(out), 0, (sockaddr*)&dest, (socklen_t)(sizeof(dest))) != sizeof(out) ) {
        close(sock);
        printf("Unable to send icmp request\n");
        return 5;
    }

    ip* ip_resp = NULL;
    icmp* icmp_resp = NULL;
    char buf[BUFFER_SIZE];
    do {
        ssize_t recv_bytes = recvfrom(sock, buf, BUFFER_SIZE, 0, 0, 0);
        if (recv_bytes < 0) {
            printf("rejected connection\n");
            return 7;
        }
        ip_resp = (ip*)buf;
        icmp_resp = (icmp*)(buf + (ip_resp->ip_hl << 2));
    } while ( icmp_resp->icmp_type != 14 );
    close(sock);

    if ( !check_packet(icmp_resp) ) {
        printf("failed response check\n");
        return 6;
    }

    long curTime = get_time();
    long origin_time = ntohl(icmp_resp->icmp_otime);
    long receive_time = ntohl(icmp_resp->icmp_rtime);
    long transmit_time = ntohl(icmp_resp->icmp_ttime);
    long process_time = transmit_time - receive_time;
    long rtt = curTime - origin_time - process_time;
    if (rtt < 0)
        printf("received invalid response! rtt < 0 \n");
    long diff = curTime - transmit_time - rtt/2; //approximate value



    printf("\ndiff =  %li ms\n", diff);
    return 0;
}
