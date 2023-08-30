#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "dns.h"

struct options {
    enum rr_type type;
    enum opcode opcode;
    bool recurse;
    const char *dns_server;
    const char *target;
};

void print_usage_and_quit(void)
{
    printf("Usage: dns-query [-t TYPE|-o OPCODE|-r] target\n");
    printf("TYPE: A NS MD MF CNAME SOA MB MG MR NUL WKS PTR HINFO MINFO MX "
            "TXT RP AFSDB X25 ISDN RT NSAP NSAP_PTR SIG KEY PX GPOS AAAA "
            "LOC NXT EID NIMLOC SRV ATMA NAPTR KX CERT A6 DNAME SINK OPT "
            "APL DS SSHFP IPSECKEY RRSIG NSEC DNSKEY DHCID NSEC3 NSEC3PARAM "
            "TLSA SMIMEA HIP NINFO RKEY TALINK CDS CDNSKEY OPENPGPKEY CSYNC "
            "ZONEMD SVCB HTTPS SPF UINFO UID GID UNSPEC NID L32 L64 LP "
            "EUI48 EUI64 TKEY TSIG IXFR AXFR MAILB MAILA WILDCARD URI CAA "
            "AVC DOA AMTRELAY COUNT\n");
    printf("OPCODE: QUERY, IQUERY, STATUS\n");
    printf("-r: recurse\n");

    exit(1);
}

void parse_options(struct options *options, int argc, char *argv[])
{
    if (argc < 2) {
        print_usage_and_quit();
    }

    options->target = argv[argc - 1];

    for (size_t i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-t") == 0) {
            if (i + 1 == argc) {
                // -t was last argument
                print_usage_and_quit();
            }

            const char *type = argv[i + 1];
            if (type == NULL) {
                print_usage_and_quit();
            }

            bool found = false;
            for (size_t i = 0; i < TYPE_COUNT; i++) {
                const char *s = rr_type_strings[i];
                if (s == NULL) {
                    continue;
                }

                if (strcmp(type, s) == 0) {
                    options->type = i;
                    found = true;
                }
            }

            if (found) {
                i++;
            } else {
                print_usage_and_quit();
            }

        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 == argc) {
                // -f was last argument
                print_usage_and_quit();
            }

            const char *flag = argv[i + 1];

            if (strcmp(flag, "QUERY") == 0) {
                options->opcode = OPCODE_QUERY;
            } else if (strcmp(flag, "IQUERY") == 0) {
                options->opcode = OPCODE_IQUERY;
            } else if (strcmp(flag, "STATUS") == 0) {
                options->opcode = OPCODE_STATUS;
            } else {
                print_usage_and_quit();
            }
        } else if (strcmp(argv[i], "-r") == 0) {
            options->recurse = true;
        } else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 == argc) {
                // -s was last argument
                print_usage_and_quit();
            }

            const char *server = argv[i + 1];
            options->dns_server = server;
        }
    }
}

int main(int argc, char *argv[])
{
    struct options options = {
        // initialized with default values
        .type = TYPE_A,
        .recurse = true,
        .dns_server = "192.168.2.1",
        .target = ""
    };

    parse_options(&options, argc, argv);

    struct sockaddr_in addr_dns = {
        .sin_family = AF_INET,
        .sin_port = htons(53)
    };

    if (inet_aton(options.dns_server, (struct in_addr*)&addr_dns.sin_addr.s_addr) == 0) {
        fprintf(stderr, "invalid DNS server address: %s\n", options.dns_server);
        print_usage_and_quit();
    }

    socklen_t addr_dns_len = sizeof(addr_dns);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket: %s\n", strerror(errno));
        return 1;
    }

    struct dns_message query = {
        .header = {
            .id = 0x6969,
            .flags = (options.recurse ? MASK_RD : 0) |
                     (options.opcode << SHIFT_OPCODE),
            .num_questions = 1,
        },
        .queries = malloc(1 * sizeof(struct dns_query))
    };

    query.queries[0].type = options.type;
    query.queries[0].name = options.target;
    query.queries[0].class = CLASS_INTERNET;

    size_t buf_len;
    uint8_t *buf_send = serialize_dns_message(&buf_len, &query);
    printf("sending request...\n");
    if (sendto(sock, buf_send, buf_len, 0,
                (struct sockaddr*)&addr_dns, addr_dns_len) < 0) {
        fprintf(stderr, "failed to send data: %s\n", strerror(errno));
    }

    printf("retrieving response...\n");
    uint8_t buf_recv[512] = { 0 };
    size_t n = 0;
    if ((n = recvfrom(sock, buf_recv, sizeof(buf_recv), 0,
                    (struct sockaddr*)&addr_dns, &addr_dns_len)) < 0) {
        fprintf(stderr, "failed to receive data: %s\n", strerror(errno));
    }

    printf("received %zu bytes\n", n);

    return EXIT_SUCCESS;
}
