#include "dns.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <netinet/in.h>

#define DNS_NAME_MAX 256

static const char *clas_strings[] = {
        [CLAS_INTERNET]    = "internet",
        [CLAS_CHAOS]       = "chaos",
        [CLAS_HESIOD]      = "hesiod"
};

static const char *rr_type_strings[] = {
        [TYPE_A]           = "A",
        [TYPE_NS]          = "NS",
        [TYPE_MD]          = "MD",
        [TYPE_MF]          = "MF",
        [TYPE_CNAME]       = "CNAME",
        [TYPE_SOA]         = "SOA",
        [TYPE_MB]          = "MB",
        [TYPE_MG]          = "MG",
        [TYPE_MR]          = "MR",
        [TYPE_NUL]         = "NUL",
        [TYPE_WKS]         = "WKS",
        [TYPE_PTR]         = "PTR",
        [TYPE_HINFO]       = "HINFO",
        [TYPE_MINFO]       = "MINFO",
        [TYPE_MX]          = "MX",
        [TYPE_TXT]         = "TXT",
        [TYPE_RP]          = "RP",
        [TYPE_AFSDB]       = "AFSDB",
        [TYPE_X25]         = "X25",
        [TYPE_ISDN]        = "ISDN",
        [TYPE_RT]          = "RT",
        [TYPE_NSAP]        = "NSAP",
        [TYPE_NSAP_PTR]    = "NSAP_PTR",
        [TYPE_SIG]         = "SIG",
        [TYPE_KEY]         = "KEY",
        [TYPE_PX]          = "PX",
        [TYPE_GPOS]        = "GPOS",
        [TYPE_AAAA]        = "AAAA",
        [TYPE_LOC]         = "LOC",
        [TYPE_NXT]         = "NXT",
        [TYPE_EID]         = "EID",
        [TYPE_NIMLOC]      = "NIMLOC",
        [TYPE_SRV]         = "SRV",
        [TYPE_ATMA]        = "ATMA",
        [TYPE_NAPTR]       = "NAPTR",
        [TYPE_KX]          = "KX",
        [TYPE_CERT]        = "CERT",
        [TYPE_A6]          = "A6",
        [TYPE_DNAME]       = "DNAME",
        [TYPE_SINK]        = "SINK",
        [TYPE_OPT]         = "OPT",
        [TYPE_APL]         = "APL",
        [TYPE_DS]          = "DS",
        [TYPE_SSHFP]       = "SSHFP",
        [TYPE_IPSECKEY]    = "IPSECKEY",
        [TYPE_RRSIG]       = "RRSIG",
        [TYPE_NSEC]        = "NSEC",
        [TYPE_DNSKEY]      = "DNSKEY",
        [TYPE_DHCID]       = "DHCID",
        [TYPE_NSEC3]       = "NSEC3",
        [TYPE_NSEC3PARAM]  = "NSEC3PARAM",
        [TYPE_TLSA]        = "TLSA",
        [TYPE_SMIMEA]      = "SMIMEA",
        [TYPE_HIP]         = "HIP",
        [TYPE_NINFO]       = "NINFO",
        [TYPE_RKEY]        = "RKEY",
        [TYPE_TALINK]      = "TALINK",
        [TYPE_CDS]         = "CDS",
        [TYPE_CDNSKEY]     = "CDNSKEY",
        [TYPE_OPENPGPKEY]  = "OPENPGPKEY",
        [TYPE_CSYNC]       = "CSYNC",
        [TYPE_ZONEMD]      = "ZONEMD",
        [TYPE_SVCB]        = "SVCB",
        [TYPE_HTTPS]       = "HTTPS",
        [TYPE_SPF]         = "SPF",
        [TYPE_UINFO]       = "UINFO",
        [TYPE_UID]         = "UID",
        [TYPE_GID]         = "GID",
        [TYPE_UNSPEC]      = "UNSPEC",
        [TYPE_NID]         = "NID",
        [TYPE_L32]         = "L32",
        [TYPE_L64]         = "L64",
        [TYPE_LP]          = "LP",
        [TYPE_EUI48]       = "EUI48",
        [TYPE_EUI64]       = "EUI64",
        [TYPE_TKEY]        = "TKEY",
        [TYPE_TSIG]        = "TSIG",
        [TYPE_IXFR]        = "IXFR",
        [TYPE_AXFR]        = "AXFR",
        [TYPE_MAILB]       = "MAILB",
        [TYPE_MAILA]       = "MAILA",
        [TYPE_WILDCARD]    = "WILDCARD",
        [TYPE_URI]         = "URI",
        [TYPE_CAA]         = "CAA",
        [TYPE_AVC]         = "AVC",
        [TYPE_DOA]         = "DOA",
        [TYPE_AMTRELAY]    = "AMTRELAY"
};

static const char *opcode_strings[] = {
        [OPCODE_QUERY]  = "standard query",
        [OPCODE_IQUERY] = "inverse query",
        [OPCODE_STATUS] = "server status request"
};

static const char *rcode_strings[] = {
        [RCODE_NOERROR]         = "no error",
        [RCODE_FORMERR]         = "format error (ill-formed query)",
        [RCODE_SERVFAIL]        = "server failure (couldn't process query due to error with server)",
        [RCODE_NXDOMAIN]        = "name error (name does not exist)",
        [RCODE_NOT_IMPLEMENTED] = "not implemented (the server doesn't support this kind of query)",
        [RCODE_REFUSED]         = "refused (refused due to policy reasons)"
};

static uint8_t *ut16_write(uint8_t *buf, uint16_t val);
static uint8_t *ut32_write(uint8_t *buf, uint32_t val);
static const uint8_t *ut16_read(uint16_t *val, const uint8_t *buf);
static const uint8_t *ut32_read(uint32_t *val, const uint8_t *buf);
static void rdata_format(char *buf, size_t n, enum rr_type type,
                         const uint8_t *rdata, size_t rdata_len);

enum rr_type string_to_rr_type(const char *string)
{
        for (size_t i = 0; i < TYPE_COUNT; i++) {
                const char *s = rr_type_strings[i];
                if (s == NULL) {
                        continue;
                }

                if (strcmp(string, s) == 0) {
                        return i;
                }
        }

        return -1;
}

const char *rr_type_to_string(enum rr_type type)
{
        if (type < 0 || type >= TYPE_COUNT) {
                return NULL;
        }

        return rr_type_strings[type];
}

const char *clas_to_string(enum clas clas)
{
        if (clas < 0 || clas >= CLAS_COUNT) {
                return NULL;
        }

        return clas_strings[clas];
}

uint8_t *serialize_dns_query(uint8_t *buf, const struct dns_query *dns_query)
{
        buf = serialize_dns_address(buf, dns_query->name);

        buf = ut16_write(buf, dns_query->type);
        buf = ut16_write(buf, dns_query->clas);
        return buf;
}

uint8_t *serialize_dns_answer(uint8_t *buf, const struct dns_answer *dns_answer)
{
        buf = serialize_dns_address(buf, dns_answer->name);

        buf = ut16_write(buf, dns_answer->type);
        buf = ut16_write(buf, dns_answer->clas);
        buf = ut32_write(buf, dns_answer->ttl);
        buf = ut16_write(buf, dns_answer->rdata_len);
        return buf;
}

uint8_t *serialize_dns_address(uint8_t *buf, const char *encoded)
{
        size_t name_len = strlen(encoded) + 2;
        memcpy(buf + 1, encoded, name_len);
        buf[0] = buf[name_len - 1] = '.';

        size_t anchor = 0;
        for (size_t i = 1; i <= name_len; i++) {
                if (i == name_len || buf[i] == '.') {
                        buf[anchor] = i - anchor - 1;
                        anchor = i;
                }
        }

        return buf + name_len;
}

void serialize_dns_message(uint8_t **buf, size_t *len, const struct dns_message *dns_message)
{
        size_t total_size = sizeof(struct dns_header);

        // sum of queries
        for (size_t i = 0; i < dns_message->header.num_queries; i++) {
                const struct dns_query *q = &dns_message->queries[i];
                total_size += strlen(q->name) + 2 + 4;
        }

        // sum of answers
        for (size_t i = 0; i < dns_message->header.num_answer_rr; i++) {
                const struct dns_answer *a = &dns_message->answers[i];
                total_size += strlen(a->name) + 2 + 10 + a->rdata_len;
        }

        *buf = malloc(total_size);
        *len = total_size;

        uint8_t *ptr = *buf;

        // header
        ptr = ut16_write(ptr, dns_message->header.id);
        ptr = ut16_write(ptr, dns_message->header.flags);
        ptr = ut16_write(ptr, dns_message->header.num_queries);
        ptr = ut16_write(ptr, dns_message->header.num_answer_rr);
        ptr = ut16_write(ptr, dns_message->header.num_authority_rr);
        ptr = ut16_write(ptr, dns_message->header.num_additional_rr);

        // queries
        for (size_t i = 0; i < dns_message->header.num_queries; i++) {
                const struct dns_query *query = &dns_message->queries[i];
                ptr = serialize_dns_query(ptr, query);
        }

        // answers
        for (size_t i = 0; i < dns_message->header.num_answer_rr; i++) {
                const struct dns_answer *answer = &dns_message->answers[i];
                ptr = serialize_dns_answer(ptr, answer);
        }
}

const uint8_t *deserialize_dns_query(struct dns_query *dns_query,
                const uint8_t *buf,
                const uint8_t *buf_full)
{
        char *name_decoded;
        buf = deserialize_dns_address(buf, buf_full, &name_decoded);
        dns_query->name     = name_decoded;

        buf = ut16_read(&dns_query->type, buf);
        buf = ut16_read(&dns_query->clas, buf);

        return buf;
}

const uint8_t *deserialize_dns_answer(struct dns_answer *dns_answer,
                const uint8_t *buf,
                const uint8_t *buf_full)
{
        char *name_decoded;
        buf = deserialize_dns_address(buf, buf_full, &name_decoded);
        dns_answer->name = name_decoded;

        buf = ut16_read(&dns_answer->type, buf);
        buf = ut16_read(&dns_answer->clas, buf);
        buf = ut32_read(&dns_answer->ttl, buf);
        buf = ut16_read(&dns_answer->rdata_len, buf);

        dns_answer->rdata = malloc(dns_answer->rdata_len);
        memcpy(dns_answer->rdata, buf, dns_answer->rdata_len);

        return buf + dns_answer->rdata_len;
}

const uint8_t *deserialize_dns_address(const uint8_t *buf,
                const uint8_t *buf_full,
                char **decoded)
{
        // restore buf in case it is set by compression indirection
        const uint8_t *buf_ret = NULL;

        uint8_t acc[DNS_NAME_MAX] = { 0 }; // max len of name per RFC 1035 2.3.4
        uint8_t *acc_ptr = acc;

        // decompress message by collecting all labels in acc
        while (buf[0] != '\0') {
                if (buf[0] & 0xc0) {
                        // first two bits set - compressed message
                        uint16_t offset = ((uint16_t)buf[0] << 8 | (uint16_t)buf[1]) & ~0xc000;

                        buf_ret = buf + 2;
                        buf = buf_full + offset;
                }

                memcpy(acc_ptr, buf, buf[0] + 1); // include size byte
                acc_ptr[0] = '.';
                acc_ptr += buf[0] + 1; // skip size byte
                buf += buf[0] + 1;
        }

        size_t len = strlen((const char*)acc);
        *decoded = malloc(len); // discard first label length but include null byte
        strncpy(*decoded, (const char*)acc + 1, len);

        if (buf_ret) {
                return buf_ret;
        } else {
                return buf + 1; // skip null byte
        }
}

void deserialize_dns_message(struct dns_message *dns_message, const uint8_t *buf)
{
        const uint8_t *ptr = buf;

        ptr = ut16_read(&dns_message->header.id, ptr);
        ptr = ut16_read(&dns_message->header.flags, ptr);
        ptr = ut16_read(&dns_message->header.num_queries, ptr);
        ptr = ut16_read(&dns_message->header.num_answer_rr, ptr);
        ptr = ut16_read(&dns_message->header.num_authority_rr, ptr);
        ptr = ut16_read(&dns_message->header.num_additional_rr, ptr);

        // queries
        dns_message->queries = malloc(sizeof(struct dns_query) * dns_message->header.num_queries);
        for (size_t i = 0; i < dns_message->header.num_queries; i++) {
                ptr = deserialize_dns_query(&dns_message->queries[i], ptr, buf);
        }

        // answers
        dns_message->answers = malloc(sizeof(struct dns_answer) * dns_message->header.num_answer_rr);
        for (size_t i = 0; i < dns_message->header.num_answer_rr; i++) {
                ptr = deserialize_dns_answer(&dns_message->answers[i], ptr, buf);
        }
}

void dns_message_format(char *buf, size_t n, const struct dns_message *message)
{
        static const char *flag_status[][2] = {
                { "message is answer", "message is response" },
                { "server is not an authority for this domain", "server is an authority for this domain" },
                { "message is not truncated", "message is truncated" },
                { "do not query recursively", "do query recursively" },
                { "server can't do recursion recursively", "server can do recursion recursively" },
        };

        int printed = snprintf(buf, n,
                "{\n"
                "   id: 0x%04x,\n"
                "   flags: 0x%04x {\n"
                "       response:            %s,\n"
                "       opcode:              %s,\n"
                "       authoritative:       %s,\n"
                "       truncated:           %s,\n"
                "       recursion desired:   %s,\n"
                "       recursion available: %s,\n"
                "       reply code:          %s\n"
                "   },\n"
                "   queries: %d,\n"
                "   answer RRs: %d,\n"
                "   authority RRS: %d,\n"
                "   additional RRs: %d,\n"
                "   queries: [\n",
                message->header.id,
                message->header.flags,
                flag_status[0][(message->header.flags & (MASK_QR     << SHIFT_QR    )) > 0],
                opcode_strings[(message->header.flags & (MASK_OPCODE << SHIFT_OPCODE)) > 0],
                flag_status[1][(message->header.flags & (MASK_AA     << SHIFT_AA    )) > 0],
                flag_status[2][(message->header.flags & (MASK_TC     << SHIFT_TC    )) > 0],
                flag_status[3][(message->header.flags & (MASK_RD     << SHIFT_RD    )) > 0],
                flag_status[4][(message->header.flags & (MASK_RA     << SHIFT_RA    )) > 0],
                rcode_strings[ (message->header.flags & (MASK_RCODE  << SHIFT_RCODE )) > 0],
                message->header.num_queries,
                message->header.num_answer_rr,
                message->header.num_authority_rr,
                message->header.num_additional_rr);


        if (printed > n) {
                fprintf(stderr, "buffer too small for message formatting\n");
                return;
        }

        buf += printed;
        n -= printed;

        for (size_t i = 0; i < message->header.num_queries; i++) {
                const struct dns_query *q = &message->queries[i];

                printed = snprintf(buf, n,
                        "      {\n"
                        "         name: %s,\n"
                        "         type: %s,\n"
                        "         class: %s\n"
                        "      }%s",
                        q->name, rr_type_to_string(q->type), clas_to_string(q->clas),
                        i < message->header.num_queries - 1 ? ",\n" : "\n");

                if (printed > n) {
                        fprintf(stderr, "buffer too small for message formatting\n");
                        return;
                }

                buf += printed;
                n -= printed;
        }

        printed = snprintf(buf, n,
                        "   ],\n"
                        "   answers: [\n");

        if (printed > n) {
                fprintf(stderr, "buffer too small for message formatting\n");
                return;
        }

        buf += printed;
        n -= printed;

        for (size_t i = 0; i < message->header.num_answer_rr; i++) {
                const struct dns_answer *a = &message->answers[i];

                char rdata[64] = { 0 };
                rdata_format(rdata, sizeof(rdata), a->type, a->rdata, a->rdata_len);

                printed = snprintf(buf, n - printed,
                                "      {\n"
                                "         name: %s,\n"
                                "         type: %s,\n"
                                "         class: %s,\n"
                                "         ttl: %d,\n"
                                "         rdata_len: %d,\n"
                                "         rdata: %s,\n"
                                "      }%s",
                                a->name, rr_type_to_string(a->type), clas_to_string(a->clas),
                                a->ttl, a->rdata_len, rdata,
                                i < message->header.num_queries - 1 ? ",\n" : "\n");

                if (printed > n) {
                        fprintf(stderr, "buffer too small for message formatting\n");
                        return;
                }

                buf += printed;
                n -= printed;
        }

        snprintf(buf, n, "   ]\n"
                         "}\n");
}

static uint8_t *ut16_write(uint8_t *buf, uint16_t val)
{
        uint16_t val_hton = htons(val);
        memcpy(buf, &val_hton, sizeof(val_hton));
        return buf + 2;
}

static uint8_t *ut32_write(uint8_t *buf, uint32_t val)
{
        uint32_t val_hton = htonl(val);
        memcpy(buf, &val_hton, sizeof(val_hton));
        return buf + 4;
}

static const uint8_t *ut16_read(uint16_t *val, const uint8_t *buf)
{
        uint16_t val_network;
        memcpy(&val_network, buf, sizeof(val_network));
        *val = ntohs(val_network);
        return buf + 2;
}

static const uint8_t *ut32_read(uint32_t *val, const uint8_t *buf)
{
        uint32_t val_network;
        memcpy(&val_network, buf, sizeof(val_network));
        *val = ntohl(val_network);
        return buf + 4;
}


static void rdata_format(char *buf, size_t n, enum rr_type type,
                         const uint8_t *rdata, size_t rdata_len)
{
        switch (type) {
                case TYPE_A:
                        if (rdata_len < 4) {
                                fprintf(stderr, "rdata too short for A record\n");
                        }

                        if (n < INET_ADDRSTRLEN) {
                                fprintf(stderr, "buf too small for A record\n");
                        }

                        inet_ntop(AF_INET, rdata, buf, n);
                        break;
                case TYPE_AAAA:
                        if (rdata_len < 16) {
                                fprintf(stderr, "rdata too short for AAAA record\n");
                        }

                        if (n < INET6_ADDRSTRLEN) {
                                fprintf(stderr, "buf too small for AAAA record\n");
                        }

                        inet_ntop(AF_INET6, rdata, buf, n);
                        break;
                default:
                        snprintf(buf, n, "(not implemented)");
        }
}
