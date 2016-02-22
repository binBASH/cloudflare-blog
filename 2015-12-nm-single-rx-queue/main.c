#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h> 

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

// embedded lua
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

lua_State *L;

/* tagged vlan frame */
struct ether_vlan {
        __u8    ether_dhost[ETH_ALEN];
        __u8    ether_shost[ETH_ALEN];
        __u16   vlan_tpid;
        __u16   vlan_tci;
        __u16   ether_type;
} __attribute__ ((__packed__));

void dump(char *pkt, int pkt_len) {
    int ip_version;
    char src[64], dst[64];
    u_int16_t ether_type, ether_size;
    struct ether_header * eth;
    struct iphdr * ip;
    struct ip6_hdr * ip6;
    struct tcphdr * tcp;

    ip = NULL;
    ip6 = NULL;
    tcp = NULL;

    eth = (struct ether_header *) pkt;
    ether_type = eth->ether_type == htons (ETHERTYPE_VLAN) ?
        ((struct ether_vlan *) pkt)->ether_type : eth->ether_type;
    ether_size = eth->ether_type == htons (ETHERTYPE_VLAN) ?
        sizeof (struct ether_vlan) : sizeof (struct ether_header);

    switch (ntohs (ether_type)) {
    default :
        return;

    case ETHERTYPE_IP:
        ip = (struct iphdr *)(pkt + ether_size);
        tcp = (struct tcphdr *)(pkt + ether_size + ip->ihl * 4);
        ip_version = 4;

        inet_ntop (AF_INET, &ip->saddr, src, sizeof src);
        inet_ntop (AF_INET, &ip->daddr, dst, sizeof dst);
        break;

    case ETHERTYPE_IPV6:
        ip6 = (struct ip6_hdr *)(pkt + ether_size);
        tcp = (struct tcphdr *)(pkt + ether_size + sizeof *ip6);
        ip_version = 6;

        inet_ntop (AF_INET6, &ip6->ip6_src, src, sizeof src);
        inet_ntop (AF_INET6, &ip6->ip6_dst, dst, sizeof dst);
        break;
    }

    const char * ip_proto;

    switch(ip_version == 4 ? ip->protocol : ip6->ip6_nxt) {
        case IPPROTO_TCP:
            ip_proto = "TCP";
            break;
        case IPPROTO_UDP:
            ip_proto = "UDP";
            break;
        case IPPROTO_ICMP:
            ip_proto = "ICMP";
            break;
        case IPPROTO_ICMPV6:
            ip_proto = "ICMP6";
            break;
        case IPPROTO_IP:
            ip_proto = "IP";
            break;
        default:
            ip_proto = "UNKNOWN";
            break;
                }

    if( ip_version == 4 && strncmp(ip_proto, "ICMP", 4) == 0 ) {
        const char * icmp_type;
        struct icmphdr* icmp;
        icmp = (struct icmphdr*) (pkt + sizeof (struct iphdr));

        switch(icmp->type) {
            case ICMP_ECHO:
                icmp_type = "ECHO";
                break;
            case ICMP_REDIRECT:
                icmp_type = "REDIRECT";
            default:
                break;
            }

        printf("ICMP-%s -> %x\n", icmp_type, icmp->type);
    }

    printf("[IP%d - %s] %s:%u -> %s:%u\n", ip_version, ip_proto, src, ntohs(tcp->source), dst, ntohs(tcp->dest));
}

void dumphex(const void* data, size_t size) {
    const int chars_per_line = 16;
    char ascii[chars_per_line+1];
    size_t i, j;
    ascii[chars_per_line] = '\0';
    for (i = 0; i < size; ++i) {
        if ( i % chars_per_line == 0 ) {
            printf("%04zX   ", i);
        }
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % chars_per_line] = ((unsigned char*)data)[i];
        } else {
            ascii[i % chars_per_line] = '.';
        }
        if ((i+1) % (chars_per_line/2) == 0 || i+1 == size) {
            //printf(" ");
            if ((i+1) % chars_per_line == 0) {
                printf("  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % chars_per_line] = '\0';
                /*
                if ((i+1) % chars_per_line <= chars_per_line/2) {
                    printf(" ");
                }
                */
                for (j = (i+1) % chars_per_line; j < chars_per_line; ++j) {
                    printf("   ");
                }
                printf("  %s \n", ascii);
            }
        }
    }
}

static int filter_packet(lua_State *L, int cb_ref, char *buf, int len) {
    int offset = 0;
    int z;

    printf("Type: 0x%x - 0x%04x - 0x%x\n Len: %d\n", *((uint8_t *) (buf + 14)), *((uint16_t *) (buf + 12)), *((uint8_t *) (buf + 23)), len);

    // Allow ARP
    if ( *((uint16_t *) (buf + 12)) == 0x0608) {
        return 1;
    }

    dump(buf, len);
    dumphex(buf, len);

    lua_rawgeti(L, LUA_REGISTRYINDEX, cb_ref);
    lua_pushlstring(L, buf, len);
    lua_pushinteger(L, len);
    if ( lua_pcall(L, 2, 1, 0) != 0 ) {
        fprintf(stderr, "%s\n", lua_tostring(L, -1));
        exit(1);
    }

    // Retrieve result
    if ( !lua_isnumber(L, -1) ) {
        fprintf(stderr, "Lua function must return a number!\n");
        exit(1);
    }

    z = lua_tonumber(L, -1);
    lua_pop(L, 1);  // pop returned value

    printf("Return value from LUA script: %d\n", z);
    if (z) {
        return 0;
    }

    // Allow STP
    if ( *((uint16_t *) (buf + 12)) == 0x2700) {
        return 1;
    }

    // Allow IPv6 neighbor solicitation
    if (*((uint16_t *) (buf + 12)) == 0xdd86 &&
        *((uint8_t *)  (buf + 23)) == 0x80) {
        return 1;
    }

    // GRE encapsulated
    if (*((uint16_t *) (buf + 12)) == 0x0008 &&
        *((uint8_t *)  (buf + 23)) == 0x2f) {
        offset = 24;
        printf("Decoded GRE\n-----------\nType: 0x%x - 0x%04x - 0x%x\n Len: %d\n", *((uint8_t *) (buf + offset + 14)), *((uint16_t *) (buf + offset + 12)), *((uint8_t *) (buf + offset + 23)), len);
    }   

    // Allow ICMP
    if (*((uint16_t *) (buf + offset + 12)) == 0x0008 &&
        *((uint8_t *)  (buf + offset + 23)) == 0x1) {
        return 1;
    }

    // Allow SSH
    if (*((uint16_t *) (buf + offset + 12)) == 0x0008 &&
        *((uint8_t *)  (buf + offset + 23)) == 0x6) {
        return 1;
    }

    // Drop anything else
    return 0;
}

static void receiver(lua_State *L, int cb_ref, struct nm_desc *d, unsigned int ring_id) {
    struct pollfd fds;
    struct netmap_ring *ring;
    unsigned int i, len;
    char *buf;
    time_t now;
    int pps;

    now = time(NULL);
    pps = 0;

    while (1) {
        fds.fd     = d->fd;
        fds.events = POLLIN;

        int r = poll(&fds, 1, 1000);
        if (r < 0) {
            if (errno != EINTR) {
                perror("poll()");
                exit(3);
            }
        }

        if (time(NULL) > now) {
            printf("[+] receiving %d pps\n", pps);
            pps = 0;
            now = time(NULL);
        }

        ring = NETMAP_RXRING(d->nifp, ring_id);

        while (!nm_ring_empty(ring)) {
            i   = ring->cur;
            buf = NETMAP_BUF(ring, ring->slot[i].buf_idx);
            len = ring->slot[i].len;

            pps++;

            if (filter_packet(L, cb_ref, buf, len)) {
                // forward packet to kernel
                ring->flags         |= NR_FORWARD;
                ring->slot[i].flags |= NS_FORWARD;
                printf("+++ PASS\n");
            } else {
                // drop packet
                printf("--- DROP\n");
            }

            ring->head = ring->cur = nm_ring_next(ring, i);
        }
    }
}

void handle_signal(int signal) {
    // Find out which signal we're handling
    switch (signal) {
        case SIGHUP:
            printf("Caught SIGHUP, reloading\n");

            lua_getglobal(L, "reload_all");
            int rl_ref = luaL_ref(L, LUA_REGISTRYINDEX);

            lua_rawgeti(L, LUA_REGISTRYINDEX, rl_ref);
            if ( lua_pcall(L, 0, 0, 0) != 0 ) {
                fprintf(stderr, "%s\n", lua_tostring(L, -1));
                exit(1);
            }

            break;
        case SIGINT:
            printf("Caught SIGINT, exiting now\n");
            exit(0);
        default:
            fprintf(stderr, "Caught wrong signal: %d\n", signal);
            return;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [interface] [RX ring number]\n", argv[0]);
        exit(1);
    }

    struct sigaction sa;

    // Setup the sighub handler
    sa.sa_handler = &handle_signal;

    // Restart the system call, if at all possible
    sa.sa_flags = SA_RESTART;

    // Block every signal during the handler
    sigfillset(&sa.sa_mask);

    // Intercept SIGHUP and SIGINT
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        perror("Error: cannot handle SIGHUP"); // Should not happen
    }

    L = luaL_newstate();
    luaL_openlibs(L); /* Load Lua libraries */

    // Try loading the file containing the script and run it
    if ( luaL_loadfile(L, "script.lua") || lua_pcall(L, 0, 0, 0) ) {
        fprintf(stderr, "Couldn't load file: %s\n", lua_tostring(L, -1));
        exit(1);
    }

    lua_getglobal(L, "callback");
    int cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    char netmap_ifname[IFNAMSIZ + 21];
    const char *interface;
    unsigned int ring_id;
    struct nm_desc *d;

    interface = argv[1];
    ring_id   = atoi(argv[2]);

    snprintf(netmap_ifname, sizeof netmap_ifname, "netmap:%s-%d/R", interface, ring_id);
    d = nm_open(netmap_ifname, NULL, 0, 0);

    if (!d) {
        perror("nm_open()");
        exit(2);
    }

    printf("[+] Receiving packets on interface %s, RX ring %d\n", interface, ring_id);
    receiver(L, cb_ref, d, ring_id);

    lua_close(L);

    return 0;
}
