#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
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
    char line[1024]; // 字符串是只读的, 所以必须使用数组来存储读取的行
    
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0'; // 去掉换行符
        }

        if (line[0] == '#' || strlen(line) == 0) {
            continue;
        }
        
        char *token = strtok(line, "\t");  // 一段一段读取字符串      
        if (token == NULL) {
            continue; // 如果没有找到IP地址，跳过这一行
        }

        char cur_ip[MAX_IP_BUFFER_SIZE];
        strncpy(cur_ip, token, MAX_IP_BUFFER_SIZE - 1);
        cur_ip[MAX_IP_BUFFER_SIZE - 1] = '\0';

        while((token = strtok(NULL, "\t"))) {
            if (strcmp(token, name) == 0) {
                memcpy(ip[count], cur_ip, MAX_IP_BUFFER_SIZE);
                ip[count][MAX_IP_BUFFER_SIZE - 1] = '\0';
                count++;
            }
            break; // 每行只处理第一个域名
        }
    }
    fclose(fp);
    return count;
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
    (void)question;
    // 1. 修改 DNS Header
    dns_header_t *header = (dns_header_t *)buf;
    header->qr = 1;
    header->aa = 1; 
    header->ra = 1;
    header->rcode = 0; // 正确响应
    header->ancount = htons(count); // 转网络字节序
    int current_len = len;
    for (int i = 0; i < count; i++) {
        uint16_t name_ptr = htons(0xC00C);
        memcpy(buf + current_len, &name_ptr, 2);
        current_len += 2;

        struct in_addr addr4;
        struct in6_addr addr6;
        int type;
        int rdlen;

        if (inet_pton(AF_INET, ip[i], &addr4) == 1) {
            type = 1;
            rdlen = 4;
        } else if (inet_pton(AF_INET6, ip[i], &addr6) == 1) {
            type = 28;
            rdlen = 16;
        } else {
            continue; // 无效的IP地址，跳过
        }

        uint16_t type_net = htons(type);
        memcpy(buf + current_len, &type_net, 2);
        current_len += 2;

        uint16_t class_net = htons(1); // 写入 CLASS (IN = 1)
        memcpy(buf + current_len, &class_net, 2);   
        current_len += 2;

        uint32_t ttl_net = htonl(60); // 写入 TTL (例如 60 秒)
        memcpy(buf + current_len, &ttl_net, 4);
        current_len += 4;

        uint16_t rdlen_net = htons(rdlen); // 写入 RDLENGTH
        memcpy(buf + current_len, &rdlen_net, 2);
        current_len += 2;   

        if (type == 1) {
            memcpy(buf + current_len, &addr4, 4);
            current_len += 4;
        } else {
            memcpy(buf + current_len, &addr6, 16);
            current_len += 16;
        }

    }
    
    return len;
}