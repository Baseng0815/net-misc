#include "dns.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

const char *rr_type_strings[] = {
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

uint8_t *ut16_write(uint8_t *buf, uint16_t val)
{
        uint16_t val_hton = htons(val);
        memcpy(buf, &val_hton, sizeof(val_hton));
        return &buf[2];
}

uint8_t *ut32_write(uint8_t *buf, uint32_t val)
{
        uint32_t val_hton = htons(val);
        memcpy(buf, &val_hton, sizeof(val_hton));
        return &buf[4];
}

uint8_t *serialize_dns_query(uint8_t *buf, const struct dns_query *dns_query)
{
        size_t name_len = strlen(dns_query->name) + 2; // first and last length octets
        memcpy(&buf[1], dns_query->name, name_len);
        buf[0] = buf[name_len - 1] = '.';

        size_t anchor = 0;
        for (size_t i = 1; i <= name_len; i++) {
                if (i == name_len || buf[i] == '.') {
                        buf[anchor] = i - anchor - 1;
                        anchor = i;
                }
        }

        buf = &buf[name_len];

        buf = ut16_write(buf, dns_query->type);
        buf = ut16_write(buf, dns_query->class);
        return buf;
}

uint8_t *serialize_dns_answer(uint8_t *buf, const struct dns_answer *dns_answer)
{
        size_t name_len = strlen(dns_answer->name) + 2;
        memcpy(&buf[1], dns_answer->name, name_len);
        buf[0] = buf[name_len - 1] = '.';

        size_t anchor = 0;
        for (size_t i = 1; i <= name_len; i++) {
                if (i == name_len || buf[i] == '.') {
                        buf[anchor] = i - anchor - 1;
                        anchor = i;
                }
        }

        buf = &buf[name_len];

        buf = ut16_write(buf, dns_answer->type);
        buf = ut16_write(buf, dns_answer->class);
        buf = ut32_write(buf, dns_answer->ttl);
        buf = ut16_write(buf, dns_answer->len_rdata);
        return buf;
}

uint8_t *serialize_dns_message(size_t *len, const struct dns_message *dns_message)
{
        size_t total_size = sizeof(struct dns_header);

        // sum of queries
        for (size_t i = 0; i < dns_message->header.num_questions; i++) {
                const struct dns_query *q = &dns_message->queries[i];
                total_size += strlen(q->name) + 2 + 4;
        }

        // sum of answers
        for (size_t i = 0; i < dns_message->header.num_answer_rr; i++) {
                const struct dns_answer *a = &dns_message->answers[i];
                total_size += strlen(a->name) + 2 + 10 + a->len_rdata;
        }

        uint8_t *buf = malloc(total_size);
        uint8_t *ptr = buf;

        // header
        ptr = ut16_write(ptr, dns_message->header.id);
        ptr = ut16_write(ptr, dns_message->header.flags);
        ptr = ut16_write(ptr, dns_message->header.num_questions);
        ptr = ut16_write(ptr, dns_message->header.num_answer_rr);
        ptr = ut16_write(ptr, dns_message->header.num_authority_rr);
        ptr = ut16_write(ptr, dns_message->header.num_additional_rr);

        // queries
        for (size_t i = 0; i < dns_message->header.num_questions; i++) {
                const struct dns_query *query = &dns_message->queries[i];
                ptr = serialize_dns_query(ptr, query);
        }

        // answers
        for (size_t i = 0; i < dns_message->header.num_answer_rr; i++) {
                const struct dns_answer *answer = &dns_message->answers[i];
                ptr = serialize_dns_answer(ptr, answer);
        }

        *len = total_size;
        return buf;
}
