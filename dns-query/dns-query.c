#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct options {
        const char *dns_server;
};

enum opcode {
        OPCODE_QUERY    = 0, // standard query
        OPCODE_IQUERY   = 1, // inverse query
        OPCODE_STATUS   = 2 // status request
};

enum response_code {
        RESPONSE_CODE_NOERROR   = 0,
        RESPONSE_CODE_FORMERR   = 1, // format error
        RESPONSE_CODE_SERVFAIL  = 2,
        RESPONSE_CODE_NXDOMAIN  = 3, // nonexistent domain
};

enum class {
        CLASS_INTERNET      = 1,
        CLASS_CHAOS         = 3,
        CLASS_HESIOD        = 4,
        CLASS_QCLASS_NONE   = 254,
        CLASS_QCLASS_ANY    = 255
};

enum rr_type {
        A           = 1, // a host address  [RFC1035]
        NS          = 2, // an authoritative name server    [RFC1035]
        MD          = 3, // a mail destination (OBSOLETE - use MX)  [RFC1035]
        MF          = 4, // a mail forwarder (OBSOLETE - use MX)    [RFC1035]
        CNAME       = 5, // the canonical name for an alias [RFC1035]
        SOA         = 6, // marks the start of a zone of authority  [RFC1035]
        MB          = 7, // a mailbox domain name (EXPERIMENTAL)    [RFC1035]
        MG          = 8, // a mail group member (EXPERIMENTAL)      [RFC1035]
        MR          = 9, // a mail rename domain name (EXPERIMENTAL)        [RFC1035]
        NUL         = 10, // a null RR (EXPERIMENTAL)        [RFC1035]
        WKS         = 11, // a well known service description        [RFC1035]
        PTR         = 12, // a domain name pointer   [RFC1035]
        HINFO       = 13, // host information        [RFC1035]
        MINFO       = 14, // mailbox or mail list information        [RFC1035]
        MX          = 15, // mail exchange   [RFC1035]
        TXT         = 16, // text strings    [RFC1035]
        RP          = 17, // for Responsible Person  [RFC1183]
        AFSDB       = 18, // for AFS Data Base location      [RFC1183][RFC5864]
        X25         = 19, // for X.25 PSDN address   [RFC1183]
        ISDN        = 20, // for ISDN address        [RFC1183]
        RT          = 21, // for Route Through       [RFC1183]
        NSAP        = 22, // for NSAP address, NSAP style A record (DEPRECATED)      [RFC1706][status-change-int-tlds-to-historic]
        NSAP_PTR    = 23, // for domain name pointer, NSAP style (DEPRECATED)        [RFC1706][status-change-int-tlds-to-historic]
        SIG         = 24, // for security signature  [RFC2536][RFC2931][RFC3110][RFC4034]
        KEY         = 25, // for security key        [RFC2536][RFC2539][RFC3110][RFC4034]
        PX          = 26, // X.400 mail mapping information  [RFC2163]
        GPOS        = 27, // Geographical Position   [RFC1712]
        AAAA        = 28, // IP6 Address     [RFC3596]
        LOC         = 29, // Location Information    [RFC1876]
        NXT         = 30, // Next Domain (OBSOLETE)  [RFC2535][RFC3755]
        EID         = 31, // Endpoint Identifier     [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]          1995-06
        NIMLOC      = 32, // Nimrod Locator  [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]               1995-06
        SRV         = 33, // Server Selection        [1][RFC2782]
        ATMA        = 34, // ATM Address     [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
        NAPTR       = 35, // Naming Authority Pointer        [RFC3403]
        KX          = 36, // Key Exchanger   [RFC2230]
        CERT        = 37, // CERT    [RFC4398]
        A6          = 38, // A6 (OBSOLETE - use AAAA)        [RFC2874][RFC3226][RFC6563]
        DNAME       = 39, // DNAME   [RFC6672]
        SINK        = 40, // SINK    [Donald_E_Eastlake][draft-eastlake-kitchen-sink]                1997-11
        OPT         = 41, // OPT     [RFC3225][RFC6891]
        APL         = 42, // APL     [RFC3123]
        DS          = 43, // Delegation Signer       [RFC4034]
        SSHFP       = 44, // SSH Key Fingerprint     [RFC4255]
        IPSECKEY    = 45, // IPSECKEY        [RFC4025]
        RRSIG       = 46, // RRSIG   [RFC4034]
        NSEC        = 47, // NSEC    [RFC4034][RFC9077]
        DNSKEY      = 48, // DNSKEY  [RFC4034]
        DHCID       = 49, // DHCID   [RFC4701]
        NSEC3       = 50, // NSEC3   [RFC5155][RFC9077]
        NSEC3PARAM  = 51, // NSEC3PARAM      [RFC5155]
        TLSA        = 52, // TLSA    [RFC6698]
        SMIMEA      = 53, // S/MIME cert association [RFC8162]       SMIMEA/smimea-completed-template        2015-12-01
        HIP         = 55, // Host Identity Protocol  [RFC8005]
        NINFO       = 56, // NINFO   [Jim_Reid]      NINFO/ninfo-completed-template  2008-01-21
        RKEY        = 57, // RKEY    [Jim_Reid]      RKEY/rkey-completed-template    2008-01-21
        TALINK      = 58, // Trust Anchor LINK       [Wouter_Wijngaards]     TALINK/talink-completed-template        2010-02-17
        CDS         = 59, // Child DS        [RFC7344]       CDS/cds-completed-template      2011-06-06
        CDNSKEY     = 60, // DNSKEY(s) the Child wants reflected in DS       [RFC7344]               2014-06-16
        OPENPGPKEY  = 61, // OpenPGP Key     [RFC7929]       OPENPGPKEY/openpgpkey-completed-template        2014-08-12
        CSYNC       = 62, // Child-To-Parent Synchronization [RFC7477]               2015-01-27
        ZONEMD      = 63, // Message Digest Over Zone Data   [RFC8976]       ZONEMD/zonemd-completed-template        2018-12-12
        SVCB        = 64, // General Purpose Service Binding [RFC-ietf-dnsop-svcb-https-12]  SVCB/svcb-completed-template    2020-06-30
        HTTPS       = 65, // Service Binding type for use with HTTP  [RFC-ietf-dnsop-svcb-https-12]  HTTPS/https-completed-template  2020-06-30
        SPF         = 99, // [RFC7208]
        UINFO       = 100, // [IANA-Reserved]
        UID         = 101, // [IANA-Reserved]
        GID         = 102, // [IANA-Reserved]
        UNSPEC      = 103, // [IANA-Reserved]
        NID         = 104, // [RFC6742]       ILNP/nid-completed-template
        L32         = 105, // [RFC6742]       ILNP/l32-completed-template
        L64         = 106, // [RFC6742]       ILNP/l64-completed-template
        LP          = 107, // [RFC6742]       ILNP/lp-completed-template
        EUI48       = 108, // an EUI-48 address       [RFC7043]       EUI48/eui48-completed-template  2013-03-27
        EUI64       = 109, // an EUI-64 address       [RFC7043]       EUI64/eui64-completed-template  2013-03-27
        TKEY        = 249, // Transaction Key [RFC2930]
        TSIG        = 250, // Transaction Signature   [RFC8945]
        IXFR        = 251, // incremental transfer    [RFC1995]
        AXFR        = 252, // transfer of an entire zone      [RFC1035][RFC5936]
        MAILB       = 253, // mailbox-related RRs (MB, MG or MR)      [RFC1035]
        MAILA       = 254, // mail agent RRs (OBSOLETE - see MX)      [RFC1035]
        WILDCARD    = 255, // A request for some or all records the server has available      [RFC1035][RFC6895][RFC8482]
        URI         = 256, // URI     [RFC7553]       URI/uri-completed-template      2011-02-22
        CAA         = 257, // Certification Authority Restriction     [RFC8659]       CAA/caa-completed-template      2011-04-07
        AVC         = 258, // Application Visibility and Control      [Wolfgang_Riedel]       AVC/avc-completed-template      2016-02-26
        DOA         = 259, // Digital Object Architecture     [draft-durand-doa-over-dns]     DOA/doa-completed-template      2017-08-30
        AMTRELAY    = 260, // Automatic Multicast Tunneling Relay     [RFC8777]       AMTRELAY/amtrelay-completed-template    2019-02-06
        TA          = 32768, // DNSSEC Trust Authorities        [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]               2005-12-13
        DLV         = 32769 // DNSSEC Lookaside Validation (OBSOLETE)  [RFC8749][RFC4431]
};

struct dns_query {
        const char *name;
        enum rr_type type;
        enum class class;
};

struct dns_answer {
        const char *name;
        enum rr_type type;
        enum class class;
        int ttl;
        int len_rdata;
        uint8_t *rdata;
};

struct dns_message {
        // header flags
        bool qr; // query/reply
        enum opcode opcode;
        bool aa; // authoritative answer
        bool tc; // truncation
        bool rd; // recursion desired (query)
        bool ra; // recursion available (response)
        enum response_code response_code;

        // number of records of following sections
        int num_questions;
        int num_answer_rr; // always 0 for query
        int num_authority_rr; // always 0 for query
        int num_additional_rr; // always 0 for query

        struct dns_query *queries;
        struct dns_answer *answers;
};

void parse_options(struct options *options, int argc, char *argv[])
{

}

void serialize_dns_query(uint8_t *buf, const struct dns_query *dns_query)
{
    size_t name_len = strlen(dns_query->name) + 4;
    memcpy(buf, dns_query->name, name_len);

    uint16_t type   = htons(dns_query->type);
    uint16_t class  = htons(dns_query->class);

    memcpy(&buf[name_len + 0], &type, sizeof(type));
    memcpy(&buf[name_len + 2], &class, sizeof(class));
}

void serialize_dns_answer(uint8_t *buf, const struct dns_answer *dns_query)
{
    size_t name_len = strlen(dns_query->name) + 4;
    memcpy(buf, dns_query->name, name_len);

    uint16_t type       = htons(dns_query->type);
    uint16_t class      = htons(dns_query->class);
    uint32_t ttl        = htonl(dns_query->ttl);
    uint16_t len_rdata  = htons(dns_query->len_rdata);

    memcpy(&buf[name_len + 0], &type, sizeof(type));
    memcpy(&buf[name_len + 2], &class, sizeof(class));
    memcpy(&buf[name_len + 4], &ttl, sizeof(ttl));
    memcpy(&buf[name_len + 8], &len_rdata, sizeof(len_rdata));
}

uint8_t *serialize_dns_message(const struct dns_message *dns_message)
{
        size_t total_size = 2 + 2 * 4; // flags plus number of records in each section
        // sum of queries
        for (size_t i = 0; i < dns_message->num_questions; i++) {
                const struct dns_query *q = &dns_message->queries[i];
                total_size += strlen(q->name) + 4;
        }

        // sum of answers
        for (size_t i = 0; i < dns_message->num_answer_rr; i++) {
                const struct dns_answer *a = &dns_message->answers[i];
                total_size += strlen(a->name) + 10 + a->len_rdata;
        }

        uint8_t *buf = malloc(total_size);
}

int main(int argc, char *argv[])
{
        struct options options = {
                // initialized with default values
                .dns_server = "127.0.0.1"
        };

        parse_options(&options, argc, argv);

        struct sockaddr_in addr_dns = {
                .sin_family = AF_INET,
                .sin_addr.s_addr = inet_addr(options.dns_server),
                .sin_port = htons(53)
        };

        socklen_t addr_dns_len = sizeof(addr_dns);

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
                fprintf(stderr, "failed to create socket: %s\n", strerror(errno));
                return 1;
        }

        const uint8_t buf_send[] = {
                0x69
        };

        if (sendto(sock, buf_send, sizeof(buf_send), 0,
                   (struct sockaddr*)&addr_dns, addr_dns_len) < 0) {
                fprintf(stderr, "failed to send data: %s\n", strerror(errno));
        }

        uint8_t buf_recv[512] = { 0 };
        if (recvfrom(sock, buf_recv, sizeof(buf_recv), 0,
                     (struct sockaddr*)&addr_dns, &addr_dns_len) < 0) {
                fprintf(stderr, "failed to receive data: %s\n", strerror(errno));
        }

        return EXIT_SUCCESS;
}
