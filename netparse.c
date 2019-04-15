#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <time.h>

#ifdef __USE_BSD
# undef __USE_BSD
#endif

#undef __NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define TERMINAL 0x01

typedef struct icmp_type_table {
   const char *type;
   const uint8_t type_code;
} icmp_type_table;

static const icmp_type_table icmp_types [] = {
   {"Echo Reply", ICMP_ECHOREPLY},
   {"Destination Unreachable", ICMP_DEST_UNREACH},
   {"Source Quench", ICMP_SOURCE_QUENCH},
   {"Redirect (change route)", ICMP_REDIRECT},
   {"Echo Request", ICMP_ECHO},
   {"Time Exceeded", ICMP_TIME_EXCEEDED},
   {"Parameter Problem", ICMP_PARAMETERPROB},
   {"Timestamp Request", ICMP_TIMESTAMP},
   {"Timestamp Reply", ICMP_TIMESTAMPREPLY},
   {"Information Request", ICMP_INFO_REQUEST},
   {"Information Reply", ICMP_INFO_REPLY},
   {"Address Mask Request", ICMP_ADDRESS},
   {"Address Mask Reply", ICMP_ADDRESSREPLY},
   {NULL, 0}
};

void
pcap_err(const int exit_value, char *format, ...) {
    va_list arg;

    va_start(arg, format);
    fprintf(stderr,"error: ");
    vfprintf(stderr, format, arg);
    fprintf(stderr, "\n");
    va_end(arg);

    exit(exit_value);
}

static size_t
get_term_size(void) {
   struct winsize w;
   ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
   return w.ws_col;
}

static void
dump_time(const struct timeval *tv, const int local) {
   if(tv == NULL) {
      warnx("%s: passing NULL as timeval", __func__);
      return;
   }

   struct tm *tod;

   if(local == 1)
      tod = localtime(&tv->tv_sec);
   else
      tod = gmtime(&tv->tv_sec);

   if(tod != NULL) {
      fprintf(stdout, "[%d.%d.%d %d:%d:%d.%ld" ,
            tod->tm_mday, tod->tm_mon, tod->tm_year + 1900 ,
            tod->tm_hour, tod->tm_min, tod->tm_sec, tv->tv_usec
         );

      if(local == 0)
         fprintf(stdout, " UTC");

      fprintf(stdout, "]\n");
   } else
      warnx("%s: can't obtain time", __func__);
}

void
dump(const unsigned char *buffer, const size_t buffer_s,
      const uint8_t flags) {
   /* line example: '__S__S|S__R' S=SPACE, R=RETURN
    * total_space = term size - 3;(SPACE, | , RETURN)
    * one element size = 4;
    * element on column = total_space / on element size
    */
   size_t t_siz = ((flags & TERMINAL) ? get_term_size() : 80);
   size_t elements_on_col = (t_siz - 3) / 4;

   size_t elem = 0;
   while(elem < buffer_s) {
      printf( "%02x ", buffer[elem]);

      elem++;
      if(elem % elements_on_col == 0 || elem == buffer_s) {
         /* print spaces insted of hex */
         if(elem == buffer_s && elem % elements_on_col != 0) {
            int count = elements_on_col - (elem % elements_on_col);
            int i = 0;
            while( i++ < count) {
               fprintf(stdout, "   ");
            }
         }

         fprintf(stdout, "| ");
         int j = (elem % elements_on_col == 0 ?
            elem - elements_on_col : elem - (elem % elements_on_col));
         while( j < elem) {
            char c = *(buffer + j++);
            if(isprint(c)) {
             fprintf(stdout, "%c", c);
            } else {
               fprintf(stdout, ".");
            }
         }
         fprintf(stdout,"\n");
      }
   }
}

const char *
icmp_type_code_to_string(const uint8_t type_code) {

    if(type_code > NR_ICMP_TYPES)
        return "invalid type\n";

    uint8_t index = 0;
    while(icmp_types[index].type !=  NULL) {
        if(icmp_types[index].type_code == type_code) {
            return icmp_types[index].type;
        }
        index++;
    }

    return "unknown type\n";
}

const char *
ip_protocol_type_to_string(const uint8_t code) {
    switch(code) {
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_IGMP:
        return "IGMP";
    case 4:
        return "IP-IP";
    case 6:
        return "TCP";
    case 8:
        return "EGP";
    case 9:
        return "IGRP";
    case 17:
        return "UDP";
    case 41:
        return "IPV6";
    case 43:
        return "IPV6-ROUTE";
    case 47:
        return "GRE";
    case IPPROTO_ICMPV6:
        return "ICMPV6";
    case 88:
        return "EIGRP";
    case 89:
        return "OSPF";
    default:
        return "unknown";
    }
}

const char *
eth_protocol_type_to_string(const uint16_t code) {
   switch(code) {
   case ETH_P_IPV6:
      return " (IPV6)\n";
   case ETH_P_IP:
      return " (IP)\n";
   case ETH_P_LOOP:
      return " (ethernet loopback packet)\n";
   case ETH_P_ARP:
      return " (ARP)\n";
   default:
      return " (unknown)\n";
   }
}

void
write_to_terminal(const char *format, ...) {

   va_list arg;

   FILE *terminal_output = fopen("/dev/tty", "w");

   if(!terminal_output) {
      err(errno, "%s: fopen: /dev/tty", __func__);
   }

   va_start(arg, format);
   vfprintf(terminal_output, format, arg);
   va_end(arg);

   fflush(terminal_output);
   fclose(terminal_output);
}

uint16_t get_eth_proto(const uint8_t *packet) {
    return ntohs(((const struct ethhdr *)packet)->h_proto);
}

static inline void
print_eth_addr(const char *prefix, const uint8_t addr[ETH_ALEN], FILE *out) {

    fprintf(out, "\t%s_MAC_addr:\t\t", prefix);

    for(uint8_t offset = 0; offset < ETH_ALEN; offset++) {

        if(offset == 0) {
            fprintf(out, "%02x", addr[offset]);
        } else {
            fprintf(out, ":%02x", addr[offset]);
        }

    }

    fputc('\n', out);
}

uint16_t
print_eth_h(const uint8_t *packet, FILE *out) {

    if(!packet || !out)
        return 0;

    fprintf(out, "[%s]\n", __func__);

    const struct ethhdr *eth_h = (const struct ethhdr *)packet;

    print_eth_addr("src", eth_h->h_source, out);
    print_eth_addr("dest", eth_h->h_dest, out);

    fprintf(out, "\tprotocol:\t\t0x%04x", ntohs(eth_h->h_proto));
    fprintf(out, "%s", eth_protocol_type_to_string(ntohs(eth_h->h_proto)));

    fflush(out);

    return sizeof(struct ethhdr);
}

uint16_t
print_ipv6_h(const uint8_t *packet, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const uint8_t *ip_header_begin = packet;

    const struct ip6_hdr *ip_h;
    ip_h = (const struct ip6_hdr *)ip_header_begin;

    char addr_ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip_h->ip6_src.s6_addr, addr_ipv6, INET6_ADDRSTRLEN);
    fprintf(out, "\tsource_adress:\t\t%s\n", addr_ipv6);

    inet_ntop(AF_INET6, ip_h->ip6_dst.s6_addr, addr_ipv6, INET6_ADDRSTRLEN);

    fprintf(out, "\tdestination_adress:\t%s\n", addr_ipv6);
    fprintf(out, "\tpayload_length:\t\t%u\n", ntohs(ip_h->ip6_plen));
    fprintf(out, "\tnext:\t\t\t%u\n", ip_h->ip6_nxt);
    fprintf(out, "\thops:\t\t\t%u\n", ip_h->ip6_hops);
    fprintf(out, "\tflow_info:\t\t%u\n", ip_h->ip6_flow);
    fprintf(out, "\ttraffic_class:\t\t%u\n", ip_h->ip6_vfc);

    return sizeof(struct ip6_hdr);
}

uint16_t
print_ipv4_h(const uint8_t *packet, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const struct iphdr *ip_h = (const struct iphdr *)packet;
    struct in_addr addr;

    addr.s_addr = ip_h->saddr;
    fprintf(out, "\tsrc_IP_address:\t\t%s\n", inet_ntoa(addr));

    addr.s_addr = ip_h->daddr;
    fprintf(out, "\tdest_IP_address:\t%s\n", inet_ntoa(addr));

    fprintf(out, "\tservice_type:\t\t%u ",ip_h->tos);
    switch(ip_h->tos) {
    case 0:
        fprintf(out, "(routine)\n");
        break;
    case 1:
        fprintf(out, "(priority)\n");
        break;
    case 2:
        fprintf(out, "(immediate)\n");
        break;
    case 3:
        fprintf(out, "(flash)\n");
        break;
    case 4:
        fprintf(out, "(flash_override)\n");
        break;
    case 5:
        fprintf(out, "(critic/ecp)\n");
        break;
    case 6:
        fprintf(out, "(internetwork_proto)\n");
        break;
    case 7:
        fprintf(out, "(network_proto)\n");
        break;
    default:
        fprintf(out, "(unknown)\n");
        break;
    }

    fprintf(out, "\tTTL:\t\t\t%u\n", ip_h->ttl);
    fprintf(out, "\tversion:\t\t%u\n", ip_h->version);
    fprintf(out, "\tprotocol_type:\t\t%u", ip_h->protocol);
    fprintf(out, " (%s)\n", ip_protocol_type_to_string(ip_h->protocol));
    fprintf(out, "\tIP_header_length:\t%uB\n",((unsigned int)(ip_h->ihl)) * 4);
    fprintf(out, "\ttotal_length: \t\t%u B\n", ntohs(ip_h->tot_len));
    fprintf(out, "\tID:\t\t\t%u\n", ntohs(ip_h->id));

    return sizeof(struct iphdr);
}

uint16_t
print_icmpv4_h(const uint8_t *start_icmpv4_h, FILE *out) {
    fprintf(out, "[%s]\n",__func__);

    struct icmphdr *icmp_h = (struct icmphdr *)start_icmpv4_h;

    fprintf(out, "\tmessage_type:\t\t%s\n", icmp_type_code_to_string(icmp_h->type));
    fprintf(out, "\tmessage_code:\t\t%u\n", icmp_h->code);
    fprintf(out, "\tchecksum:\t\t%u\n", icmp_h->checksum);

    return sizeof(struct icmphdr);
}

uint16_t
print_icmpv6_h(const uint8_t *packet, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    struct icmp6_hdr *icmp_h = (struct icmp6_hdr *)packet;

    fprintf(out, "\tmessage_type:\t\t%u\n", icmp_h->icmp6_type);
    fprintf(out, "\tmessage_code:\t\t%u\n", icmp_h->icmp6_code);
    fprintf(out, "\tchecksum:\t\t%u\n", icmp_h->icmp6_cksum);

    return sizeof(struct icmphdr);
}

uint16_t
print_udp_h(const uint8_t *start_udp_h, FILE *out) {
    fprintf(out, "[%s]\n",__func__);

    struct udphdr *udp_h = (struct udphdr *)start_udp_h;

    fprintf(out, "\tdestination_port:\t%u\n", ntohs(udp_h->dest));
    fprintf(out, "\tsource_port:\t\t%u\n", ntohs(udp_h->source));
    fprintf(out, "\tlength:\t\t\t%u\n", ntohs(udp_h->len));
    fprintf(out, "\tchecksum:\t\t%u\n", ntohs(udp_h->check));

    return sizeof(struct udphdr);
}

enum PORT_TYPE {
    SOURCE,
    DEST
};

uint16_t get_udp_port(const uint8_t *packet, enum PORT_TYPE type) {
    const struct udphdr *hdr = (const struct udphdr *)packet;

    switch (type) {
        case DEST:
            return ntohs(hdr->dest);
        case SOURCE:
            return ntohs(hdr->source);
    }
}

struct dhcphdr {
    uint8_t opcode;
    uint8_t hwtype;
    uint8_t hwlen;
    uint8_t hops;
    uint32_t transid;
    uint16_t elapsed;
    uint16_t flags;

    uint32_t clientip;
    uint32_t currentip;
    uint32_t serverip;
    uint32_t gatewayip;
};

uint16_t
print_dhcp_h(const uint8_t *packet, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const struct dhcphdr *hdr = (const struct dhcphdr *)packet;

    fprintf(out, "\topcode:\t\t\t%u\n", hdr->opcode);
    fprintf(out, "\thwtype:\t\t\t%u\n", hdr->hwtype);
    fprintf(out, "\thwlen:\t\t\t%u\n", hdr->hwlen);
    fprintf(out, "\thops:\t\t\t%u\n", hdr->hops);

    return sizeof(struct dhcphdr);
}

uint16_t
print_igmp_h(const uint8_t *start_igmp_h, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const struct igmp *igmp_h = (const struct igmp *)start_igmp_h;

    fprintf(out, "\ttype:\t\t\t%d\n", igmp_h->igmp_type);
    fprintf(out, "\tcode:\t\t\t%d\n", igmp_h->igmp_code);
    fprintf(out, "\tchecksum:\t\t%d\n", igmp_h->igmp_code);
    fprintf(out, "\tgroup_adress:\t\t%s\n", inet_ntoa(igmp_h->igmp_group));

    return sizeof(struct igmp);
}

uint16_t get_tcp_port(const uint8_t *packet, enum PORT_TYPE type) {
    const struct tcphdr *hdr = (const struct tcphdr *)packet;

    switch (type) {
        case DEST:
            return ntohs(hdr->dest);
        case SOURCE:
            return ntohs(hdr->source);
    }
}

uint16_t
print_tcp_h(const uint8_t *start_tcp_h, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const struct tcphdr *tcp_h;
    tcp_h = (const struct tcphdr *)start_tcp_h;

    fprintf(out, "\tdestination_port:\t%u\n", ntohs(tcp_h->dest));
    fprintf(out, "\tsource_port:\t\t%u\n", ntohs(tcp_h->source));
    fprintf(out, "\tsequence_number:\t%u\n", ntohl(tcp_h->seq));
    fprintf(out, "\tacknowlenge_number:\t%u\n", ntohl(tcp_h->ack_seq));
    fprintf(out, "\turgent_pointer:\t\t%u\n", ntohs(tcp_h->urg_ptr));
    fprintf(out, "\tdata_offset:\t\t%uB\n", tcp_h->doff * 4);
    fprintf(out, "\tchecksum:\t\t%x\n", ntohs(tcp_h->check));
    fprintf(out, "\twindow:\t\t\t%u\n", ntohs(tcp_h->window));

    fprintf(out, "\tflags: ");
//   if(tcp_h->ece)
//      fprintf(out, "ECE ");
//   if(tcp_h->cwr)
//      fprintf(out, "CWR ");
    if(tcp_h->ack)
        fprintf(out, "ACK ");
    if(tcp_h->psh)
        fprintf(out, "PSH ");
    if(tcp_h->rst)
        fprintf(out, "RST ");
    if(tcp_h->syn)
        fprintf(out, "SYN ");
    if(tcp_h->fin)
        fprintf(out, "FIN ");

    fputc('\n', out);
    fflush(out);

    // offset in 4 byte words
    return tcp_h->doff * 4;
}

struct arp_ipv4 {
    uint8_t orig[8];

    uint8_t ar_sha[ETH_ALEN]; // sender hardware address
    uint8_t ar_sip[4];        // sender IP address

    uint8_t ar_tha[ETH_ALEN]; // target hardware address
    uint8_t ar_tip[4];        // targer IP address
};

uint16_t
print_arp_h(const uint8_t *packet, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const struct arphdr *hdr = (const struct arphdr *)packet;

    fprintf(out, "\tHardware type:\t\t%u\n", ntohs(hdr->ar_hrd));
    fprintf(out, "\tProtocol type:\t\t%u\n", ntohs(hdr->ar_pro));

    fprintf(out, "\tHardware addrlen:\t%u\n", hdr->ar_hln);
    fprintf(out, "\tHardware addrlen:\t%u\n", hdr->ar_pln);

    fprintf(out, "\tOperation:\t\t");

    switch(ntohs(hdr->ar_op)) {
    case ARPOP_REQUEST:
        fprintf(out, "Request");
        break;
    case ARPOP_REPLY:
        fprintf(out, "Reply");
        break;
    case ARPOP_RREQUEST:
        fprintf(out, "RARP Request");
        break;
    case ARPOP_RREPLY:
        fprintf(out, "RARP Reply");
        break;
    default:
        fprintf(out, "TODO");
    }

    fputc('\n', out);

    if(ntohs(hdr->ar_pro) != ETH_P_IP) {
        goto done;
    }

    const struct arp_ipv4 *aip_hdr = (const struct arp_ipv4 *)packet;

    print_eth_addr("src", aip_hdr->ar_sha, out);
    print_eth_addr("dest", aip_hdr->ar_tha, out);

    struct in_addr addr;

    addr.s_addr = aip_hdr->ar_sip[0] | (aip_hdr->ar_sip[1] << 8) |
                  (aip_hdr->ar_sip[2] << 16) | (aip_hdr->ar_sip[3] << 24);
    fprintf(out, "\tsrc_IP_address:\t\t%s\n", inet_ntoa(addr));

    addr.s_addr = aip_hdr->ar_tip[0] | (aip_hdr->ar_tip[1] << 8) |
                  (aip_hdr->ar_tip[2] << 16) | (aip_hdr->ar_tip[3] << 24);
    fprintf(out, "\tdest_IP_address:\t%s\n", inet_ntoa(addr));

done:
    return sizeof(struct arphdr) + 2 * hdr->ar_hln + 2 * hdr->ar_pln;
}

void
usage() {
   fprintf(stderr,"usage: netparse --interface [name] --count [packets] ...\n");
   //XXX: add the other options
   exit(EXIT_SUCCESS);
}

uint32_t
get_ipv4_protocol(const uint8_t *packet) {
    return ((const struct iphdr *)packet)->protocol;
}

uint32_t
get_ipv6_protocol(const uint8_t *packet) {
    return ((const struct ip6_hdr *)packet)->ip6_nxt;
}

struct __attribute__((__packed__)) tlshdr {
    uint8_t record_type;
    uint16_t version;
    uint16_t length;
};

struct tls_hp_hdr {
    uint8_t handshake_type;

};

enum TLS_RECORD_TYPES {
    CHANGE_CIPHER_SPEC = 0x14,
    ALERT = 0x15,
    HANDSHAKE = 0x16,
    APPLICATION_DATA = 0x17
};

enum SSL_TLS_VERSIONS {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303
};

enum TLS_HANDSHAKE_TYPES {
    HELLO_REQUEST = 0x00,
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    NEW_SESSION_TICKET = 0x04,
    CERTIFICATE = 0x0b,
    SERVER_KEY_EXCHANGE = 0x0c,
    CERTIFICATE_REQUEST = 0x0d,
    SERVER_DONE = 0x0e,
    CERTIFICATE_VERIFY = 0x0f,
    CLIENT_KEY_EXCHANGE = 0x10,
    FINISHED = 0x14
};

uint16_t
print_tls_handshake_h(const uint8_t *start_h, FILE *out) {

    fprintf(out, "[%s]\n", __func__);

    fprintf(out, "\ttype: (%02x)\t\t", start_h[0]);

    switch(start_h[0]) {
    case HELLO_REQUEST:
        fprintf(out, "HelloRequest");
        break;
    case CLIENT_HELLO:
        fprintf(out, "ClientHello");
        break;
    case SERVER_HELLO:
        fprintf(out, "ServerHello");
        break;
    case NEW_SESSION_TICKET:
        fprintf(out, "NewSessionTicket");
        break;
    case CERTIFICATE:
        fprintf(out, "Certificate");
        break;
    case SERVER_KEY_EXCHANGE:
        fprintf(out, "ServerKeyExchange");
        break;
    case CERTIFICATE_REQUEST:
        fprintf(out, "CertificateRequest");
        break;
    case SERVER_DONE:
        fprintf(out, "ServerDone");
        break;
    case CERTIFICATE_VERIFY:
        fprintf(out, "CertificateVerify");
        break;
    case CLIENT_KEY_EXCHANGE:
        fprintf(out, "ClientKeyExchange");
        break;
    case FINISHED:
        fprintf(out, "Finished");
        break;
    }

    fputc('\n', out);

    return 1;
}


uint16_t
print_tls_h(const uint8_t *start_tls_h, FILE *out) {
    fprintf(out, "[%s]\n", __func__);

    const struct tlshdr tls_h = *(const struct tlshdr *)start_tls_h;

    fprintf(out, "\trecord_type: (%x)\t", tls_h.record_type);

    switch(tls_h.record_type) {
        case CHANGE_CIPHER_SPEC:
            fprintf(out, "ChangeCipherSpec");
            break;
        case HANDSHAKE:
            fprintf(out, "HandShake");
            break;
        case APPLICATION_DATA:
            fprintf(out, "ApplicationData");
            break;
        case ALERT:
            fprintf(out, "Alert");
            break;
    }

    fprintf(out, "\n\tversion: (0x%04x)\t", ntohs(tls_h.version));

    switch(ntohs(tls_h.version)) {
        case SSL_3_0:
            fprintf(out, "SSLv3");
            break;
        case TLS_1_0:
            fprintf(out, "TLSv1.0");
            break;
        case TLS_1_1:
            fprintf(out, "TLSv1.1");
            break;
        case TLS_1_2:
            fprintf(out, "TLSv1.2");
            break;
        default:
            fprintf(out, "Unknown", ntohs(tls_h.version));
    }

    fprintf(out, "\n\tlength:\t\t\t%d\n", ntohs(tls_h.length));

    size_t pos = sizeof(struct tlshdr);

    switch(tls_h.record_type) {
        case CHANGE_CIPHER_SPEC:
            break;
        case HANDSHAKE:
            pos += print_tls_handshake_h(start_tls_h + pos, stdout);
            break;
        case APPLICATION_DATA:
            break;
        case ALERT:
            break;
    }

    return pos + tls_h.length;
}

struct args {
    size_t packets;
    char *dev;
    uint8_t dump;
    uint8_t usage;
    uint8_t dump_time;
};

struct args *
parse_args(int argc, char **argv) {

   static const struct option opts[] = {
        { "count", required_argument, 0 , 'c'},
        { "dump", no_argument, 0, 'd'},
        { "interface", required_argument,  0, 'i' },
        { "help", no_argument,  0, 'h' },
        { "time-dump", no_argument, 0, 't'},
        { "tls-dump", no_argument, 0, 's'},
        { 0, 0, 0, 0  }
   };

    int opt = 0, idx = 0;
    struct args *args = malloc(sizeof(struct args));

    if(!args) {
        errx(1, "unable to allocate memory for arguments");
    }

    memset(args, 0, sizeof(struct args));

    while((opt = getopt_long_only(argc, argv, "c:i:dht", opts, &idx)) != -1) {
        switch (opt) {
        case 'h':
            args->usage = 1;
            break;
        case 'c':
            args->packets = atoi(optarg);

            if(!args->packets || args->packets < 0) {
                errx(2, "--count must be a positive integer");
            }

            break;
        case 'd':
            args->dump = 1;
            break;
        case 'i':
            args->dev = optarg;
            break;
        case 't':
            args->dump_time = 1;
            break;
        default:
            errx(2, "invalid option: %s", optarg);
        }
    }

    if(args->usage) {
        usage();
    }

    if(!args->dev) {
        errx(2, "--interface is a required argument, but is missinsg");
    }



    return args;
}

pcap_t *
open_device(const char *dev) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

    if(!pcap_handle) {
        pcap_err(EXIT_FAILURE, "pcap_open_live: %s", errbuf);
    }

    write_to_terminal("Using device : `%s'\n", dev);

    return pcap_handle;
}

int
main(int argc, char **argv) {

    struct args *args = parse_args(argc, argv);
    pcap_t *pcap_handle = open_device(args->dev);

    const uint8_t *packet = NULL;
    struct pcap_pkthdr header;
    int32_t counter = 0;
    uint32_t ip_protocol_type, eth_proto = 0, port;
    struct timeval tv;

    uint32_t pos = 0;

    while(1) {

        packet = pcap_next(pcap_handle, &header);

        if(args->dump_time) {
            gettimeofday(&tv, NULL);
            dump_time(&tv, 0);
        }

        pos = print_eth_h(packet, stdout);

        eth_proto = get_eth_proto(packet);

        switch(eth_proto) {
        case ETH_P_IPV6:
            ip_protocol_type = get_ipv6_protocol(packet + pos);
            pos += print_ipv6_h(packet + pos, stdout);
            break;
        case ETH_P_IP:
            ip_protocol_type = get_ipv4_protocol(packet + pos);
            pos += print_ipv4_h(packet + pos, stdout);
            break;
        case ETH_P_ARP:
            pos += print_arp_h(packet + pos, stdout);
            goto dump;
        default:
            write_to_terminal("Warning: unhandled eth protocol %d\n", eth_proto);
            goto dump;
        }

        uint16_t dest = 0, source = 0;

        switch(ip_protocol_type) {
        case IPPROTO_TCP:
            dest = get_tcp_port(packet + pos, DEST);
            source = get_tcp_port(packet + pos, SOURCE);

            pos += print_tcp_h(packet + pos, stdout);

            if (dest == 443 || source == 443) {
                pos += print_tls_h(packet + pos, stdout);
            }

            break;
        case IPPROTO_ICMP:
            pos += print_icmpv4_h(packet + pos, stdout);
            goto dump;
        case IPPROTO_ICMPV6:
            pos += print_icmpv6_h(packet + pos, stdout);
            goto dump;
        case IPPROTO_UDP:
            dest = get_udp_port(packet + pos, DEST);
            source = get_udp_port(packet + pos, SOURCE);

            pos += print_udp_h(packet + pos, stdout);

            if(dest == 67 || dest == 68 || source == 67 || source == 68) {
                pos += print_dhcp_h(packet + pos, stdout);
            } else if(dest == 443) {
                pos += print_tls_h(packet + pos, stdout);
            }

            break;
        case IPPROTO_IGMP:
            pos += print_igmp_h(packet + pos, stdout);
            goto dump;
        default:
            write_to_terminal("Unsupported protocol, number %d. See netinet/in.h",
                    ip_protocol_type);
            goto dump;
        }

        if(pos >= header.len) {
            goto dump;
        }

dump:
        fprintf(stdout, "\n");

        if(args->dump) {
            dump(packet, header.len, 0);
        }

        if(args->packets != 0 && (++counter >= args->packets)) {
            break;
        }
    }

    pcap_close(pcap_handle);

    exit(0);
}
