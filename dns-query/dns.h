#include <stdint.h>
#include <stddef.h>

enum opcode {
        OPCODE_QUERY    = 0, // standard query
        OPCODE_IQUERY   = 1, // inverse query
        OPCODE_STATUS   = 2 // status request
};

enum rcode {
        RCODE_NOERROR   = 0,
        RCODE_FORMERR   = 1, // format error
        RCODE_SERVFAIL  = 2,
        RCODE_NXDOMAIN  = 3, // nonexistent domain
};

enum shifts {
        SHIFT_RD        =  0,
        SHIFT_TC        =  1,
        SHIFT_OPCODE    =  3,
        SHIFT_QR        =  7,
        SHIFT_RCODE     =  8,
        SHIFT_AA        = 12,
        SHIFT_RA        = 15
};

enum masks {
        MASK_QR        = 0x1, // query or response
        MASK_OPCODE    = 0x7, // standard query, inverse query or status
        MASK_AA        = 0x1, // authoritative answer
        MASK_TC        = 0x1, // truncation
        MASK_RD        = 0x1, // recursion desired
        MASK_RA        = 0x1, // recursion available
        MASK_RCODE     = 0x1  // response code
};

enum class {
        CLASS_INTERNET      = 1,
        CLASS_CHAOS         = 3,
        CLASS_HESIOD        = 4,
        /* CLASS_QCLASS_NONE   = 254, */
        /* CLASS_QCLASS_ANY    = 255 */
};

enum rr_type {
        TYPE_A           = 1, // a host address  [RFC1035]
        TYPE_NS          = 2, // an authoritative name server    [RFC1035]
        TYPE_MD          = 3, // a mail destination (OBSOLETE - use MX)  [RFC1035]
        TYPE_MF          = 4, // a mail forwarder (OBSOLETE - use MX)    [RFC1035]
        TYPE_CNAME       = 5, // the canonical name for an alias [RFC1035]
        TYPE_SOA         = 6, // marks the start of a zone of authority  [RFC1035]
        TYPE_MB          = 7, // a mailbox domain name (EXPERIMENTAL)    [RFC1035]
        TYPE_MG          = 8, // a mail group member (EXPERIMENTAL)      [RFC1035]
        TYPE_MR          = 9, // a mail rename domain name (EXPERIMENTAL)        [RFC1035]
        TYPE_NUL         = 10, // a null RR (EXPERIMENTAL)        [RFC1035]
        TYPE_WKS         = 11, // a well known service description        [RFC1035]
        TYPE_PTR         = 12, // a domain name pointer   [RFC1035]
        TYPE_HINFO       = 13, // host information        [RFC1035]
        TYPE_MINFO       = 14, // mailbox or mail list information        [RFC1035]
        TYPE_MX          = 15, // mail exchange   [RFC1035]
        TYPE_TXT         = 16, // text strings    [RFC1035]
        TYPE_RP          = 17, // for Responsible Person  [RFC1183]
        TYPE_AFSDB       = 18, // for AFS Data Base location      [RFC1183][RFC5864]
        TYPE_X25         = 19, // for X.25 PSDN address   [RFC1183]
        TYPE_ISDN        = 20, // for ISDN address        [RFC1183]
        TYPE_RT          = 21, // for Route Through       [RFC1183]
        TYPE_NSAP        = 22, // for NSAP address, NSAP style A record (DEPRECATED)      [RFC1706][status-change-int-tlds-to-historic]
        TYPE_NSAP_PTR    = 23, // for domain name pointer, NSAP style (DEPRECATED)        [RFC1706][status-change-int-tlds-to-historic]
        TYPE_SIG         = 24, // for security signature  [RFC2536][RFC2931][RFC3110][RFC4034]
        TYPE_KEY         = 25, // for security key        [RFC2536][RFC2539][RFC3110][RFC4034]
        TYPE_PX          = 26, // X.400 mail mapping information  [RFC2163]
        TYPE_GPOS        = 27, // Geographical Position   [RFC1712]
        TYPE_AAAA        = 28, // IP6 Address     [RFC3596]
        TYPE_LOC         = 29, // Location Information    [RFC1876]
        TYPE_NXT         = 30, // Next Domain (OBSOLETE)  [RFC2535][RFC3755]
        TYPE_EID         = 31, // Endpoint Identifier     [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]          1995-06
        TYPE_NIMLOC      = 32, // Nimrod Locator  [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]               1995-06
        TYPE_SRV         = 33, // Server Selection        [1][RFC2782]
        TYPE_ATMA        = 34, // ATM Address     [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
        TYPE_NAPTR       = 35, // Naming Authority Pointer        [RFC3403]
        TYPE_KX          = 36, // Key Exchanger   [RFC2230]
        TYPE_CERT        = 37, // CERT    [RFC4398]
        TYPE_A6          = 38, // A6 (OBSOLETE - use AAAA)        [RFC2874][RFC3226][RFC6563]
        TYPE_DNAME       = 39, // DNAME   [RFC6672]
        TYPE_SINK        = 40, // SINK    [Donald_E_Eastlake][draft-eastlake-kitchen-sink]                1997-11
        TYPE_OPT         = 41, // OPT     [RFC3225][RFC6891]
        TYPE_APL         = 42, // APL     [RFC3123]
        TYPE_DS          = 43, // Delegation Signer       [RFC4034]
        TYPE_SSHFP       = 44, // SSH Key Fingerprint     [RFC4255]
        TYPE_IPSECKEY    = 45, // IPSECKEY        [RFC4025]
        TYPE_RRSIG       = 46, // RRSIG   [RFC4034]
        TYPE_NSEC        = 47, // NSEC    [RFC4034][RFC9077]
        TYPE_DNSKEY      = 48, // DNSKEY  [RFC4034]
        TYPE_DHCID       = 49, // DHCID   [RFC4701]
        TYPE_NSEC3       = 50, // NSEC3   [RFC5155][RFC9077]
        TYPE_NSEC3PARAM  = 51, // NSEC3PARAM      [RFC5155]
        TYPE_TLSA        = 52, // TLSA    [RFC6698]
        TYPE_SMIMEA      = 53, // S/MIME cert association [RFC8162]       SMIMEA/smimea-completed-template        2015-12-01
        TYPE_HIP         = 55, // Host Identity Protocol  [RFC8005]
        TYPE_NINFO       = 56, // NINFO   [Jim_Reid]      NINFO/ninfo-completed-template  2008-01-21
        TYPE_RKEY        = 57, // RKEY    [Jim_Reid]      RKEY/rkey-completed-template    2008-01-21
        TYPE_TALINK      = 58, // Trust Anchor LINK       [Wouter_Wijngaards]     TALINK/talink-completed-template        2010-02-17
        TYPE_CDS         = 59, // Child DS        [RFC7344]       CDS/cds-completed-template      2011-06-06
        TYPE_CDNSKEY     = 60, // DNSKEY(s) the Child wants reflected in DS       [RFC7344]               2014-06-16
        TYPE_OPENPGPKEY  = 61, // OpenPGP Key     [RFC7929]       OPENPGPKEY/openpgpkey-completed-template        2014-08-12
        TYPE_CSYNC       = 62, // Child-To-Parent Synchronization [RFC7477]               2015-01-27
        TYPE_ZONEMD      = 63, // Message Digest Over Zone Data   [RFC8976]       ZONEMD/zonemd-completed-template        2018-12-12
        TYPE_SVCB        = 64, // General Purpose Service Binding [RFC-ietf-dnsop-svcb-https-12]  SVCB/svcb-completed-template    2020-06-30
        TYPE_HTTPS       = 65, // Service Binding type for use with HTTP  [RFC-ietf-dnsop-svcb-https-12]  HTTPS/https-completed-template  2020-06-30
        TYPE_SPF         = 99, // [RFC7208]
        TYPE_UINFO       = 100, // [IANA-Reserved]
        TYPE_UID         = 101, // [IANA-Reserved]
        TYPE_GID         = 102, // [IANA-Reserved]
        TYPE_UNSPEC      = 103, // [IANA-Reserved]
        TYPE_NID         = 104, // [RFC6742]       ILNP/nid-completed-template
        TYPE_L32         = 105, // [RFC6742]       ILNP/l32-completed-template
        TYPE_L64         = 106, // [RFC6742]       ILNP/l64-completed-template
        TYPE_LP          = 107, // [RFC6742]       ILNP/lp-completed-template
        TYPE_EUI48       = 108, // an EUI-48 address       [RFC7043]       EUI48/eui48-completed-template  2013-03-27
        TYPE_EUI64       = 109, // an EUI-64 address       [RFC7043]       EUI64/eui64-completed-template  2013-03-27
        TYPE_TKEY        = 249, // Transaction Key [RFC2930]
        TYPE_TSIG        = 250, // Transaction Signature   [RFC8945]
        TYPE_IXFR        = 251, // incremental transfer    [RFC1995]
        TYPE_AXFR        = 252, // transfer of an entire zone      [RFC1035][RFC5936]
        TYPE_MAILB       = 253, // mailbox-related RRs (MB, MG or MR)      [RFC1035]
        TYPE_MAILA       = 254, // mail agent RRs (OBSOLETE - see MX)      [RFC1035]
        TYPE_WILDCARD    = 255, // A request for some or all records the server has available      [RFC1035][RFC6895][RFC8482]
        TYPE_URI         = 256, // URI     [RFC7553]       URI/uri-completed-template      2011-02-22
        TYPE_CAA         = 257, // Certification Authority Restriction     [RFC8659]       CAA/caa-completed-template      2011-04-07
        TYPE_AVC         = 258, // Application Visibility and Control      [Wolfgang_Riedel]       AVC/avc-completed-template      2016-02-26
        TYPE_DOA         = 259, // Digital Object Architecture     [draft-durand-doa-over-dns]     DOA/doa-completed-template      2017-08-30
        TYPE_AMTRELAY    = 260, // Automatic Multicast Tunneling Relay     [RFC8777]       AMTRELAY/amtrelay-completed-template    2019-02-06
        TYPE_COUNT
        /* TYPE_TA          = 32768, // DNSSEC Trust Authorities        [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]               2005-12-13 */
        /* TYPE_DLV         = 32769 // DNSSEC Lookaside Validation (OBSOLETE)  [RFC8749][RFC4431] */
};

extern const char *rr_type_strings[];

struct dns_query {
        const char *name;
        uint16_t type;
        uint16_t class;
} __attribute__((packed));

struct dns_answer {
        const char *name;
        uint16_t type;
        uint16_t class;
        uint32_t ttl;
        uint16_t len_rdata;
        uint8_t *rdata;
} __attribute__((packed));

struct dns_header {
        uint16_t id;
        uint16_t flags;

        // number of records of following sections
        uint16_t num_questions;
        uint16_t num_answer_rr; // always 0 for query
        uint16_t num_authority_rr; // always 0 for query
        uint16_t num_additional_rr; // always 0 for query
} __attribute__((packed));

struct dns_message {
        struct dns_header header;

        struct dns_query *queries;
        struct dns_answer *answers;
} __attribute__((packed));

uint8_t *serialize_dns_query(uint8_t *buf, const struct dns_query *dns_query);
uint8_t *serialize_dns_answer(uint8_t *buf, const struct dns_answer *dns_answer);
uint8_t *serialize_dns_address(uint8_t *buf, const char *encoded);
void serialize_dns_message(uint8_t **buf, size_t *len, const struct dns_message *dns_message);

// buf_full needed in case messages are compressed
const uint8_t *deserialize_dns_query(struct dns_query *dns_query, const uint8_t *buf, const uint8_t *buf_full);
const uint8_t *deserialize_dns_answer(struct dns_answer *dns_answer, const uint8_t *buf, const uint8_t *buf_full);
const uint8_t *deserialize_dns_address(const uint8_t *buf, const uint8_t *buf_full, char **decoded);
void deserialize_dns_message(struct dns_message *dns_message, size_t *len);
