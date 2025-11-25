#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include "dns_relay.h"
#include "dns_dgram_utils.h"

/*
    parse the domain name, type and class from question section of a dns datagram
    input:
        buf: the pointer point to the begin of the dns datagram
    output:
        name: the resolved domain name
        question: other fields except domain name in question section
    note:
        - support both sequences of labels and pointer
        - in this lab, consider that the dns request datagram contains ONLY one entry in question section for convenience.
*/
void parse_question_section(char *name, dns_question_t *question, const unsigned char *buf) {
    /* 
        TODO: implement this function 
    */
    const unsigned char *p = buf + DNS_HEADER_SIZE;
    int name_pos = 0;

    while(1) {
        unsigned char len = *p++;
        if (len == 0) {
            break;
        }

        for (int i = 0; i < len; i++) {
            name[name_pos++] = (char)(*p++);
        }    

        name[name_pos++] = '.';
    }

    if (name_pos > 0 && name[name_pos - 1] == '.') {
        name_pos--;
    }

    name[name_pos] = '\0';
    
    const dns_question_t *q = (const dns_question_t *)p;
    question->type = ntohs(q->type);
    question->cls = ntohs(q->cls); // 网络字节序转主机字节序

    return;
}

/**
    try to find answer to the domain name by reading the local host file
    input:
        name: the domain name try to answer
        question: other fields except domain name in question section
        file_path: the path to the local host file
    output:
        ip: the IP of multiple resource records in string format (eg. "192.168.1.1")
    return:
        0 if no record, positive if any record
    note: supports one IP mapping to multiple domain names per line
*/
int try_answer_local(char ip[MAX_ANSWER_COUNT][MAX_IP_BUFFER_SIZE], const char *name, const char *file_path) {
    /* 
        TODO: implement this function 
    */
    FILE *fp = fopen(file_path, "r");
    if (fp == NULL) {
        return 0;
    }
    int count = 0;
    char line[1024];
    
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0'; // 去掉换行符
        }

        if (line[0] == '#' || strlen(line) == 0) {
            continue;
        }

        

    }


    return 0;
}

/**
    it's more convenient to transform a dns request datagram to a dns response datagram than to construct a new dns response datagram
    input:
        buf: original dns request datagram
        len: original dns request datagram length
        ip: the IP of multiple resource records in string format (eg. "192.168.1.1")
        count: how many IP bind to this domain name
        question: other fields except domain name in question section
    output:
        buf: new dns response datagram
    return:
        length of the new dns response datagram
    note: 
        - do not need domain name, use pointer instead
        - need to support both IPv4 and IPv6
 */
int transform_to_response(unsigned char *buf, int len, const char ip[MAX_ANSWER_COUNT][MAX_IP_BUFFER_SIZE], int count, const dns_question_t *question) {
    /* 
        TODO: implement this function 
    */
    return len;
}