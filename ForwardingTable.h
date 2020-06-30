#ifndef IPFORWARDING_FORWARDINGTABLE_H
#define IPFORWARDING_FORWARDINGTABLE_H
#include <arpa/inet.h>

// 使用链表存储路由表
typedef struct tableEntry {
    struct in_addr    nid;     // 网络号
    struct in_addr    mask;    // 子网掩码
    int               port;    // 端口号
    struct tableEntry *next;
}tableEntry, *table;

void tableAppend(const char* nid, const char* mask, int port, table T);
table tableInit();
void tableDisplay(table T);
tableEntry tableLookup(table T, const struct in_addr &ip);

#endif //IPFORWARDING_FORWARDINGTABLE_H
