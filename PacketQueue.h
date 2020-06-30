#ifndef IPFORWARDING_PACKETQUEUE_H
#define IPFORWARDING_PACKETQUEUE_H
#include <sys/types.h>

// 使用链表存储输入输出队列
typedef struct packet {
    const u_char  *content;
    struct packet *next;
}packet, *packetQueue;

void queueAppend(const u_char *content, packetQueue Q);
packetQueue queueInit();
const u_char* queuePop(packetQueue &Q);

#endif //IPFORWARDING_PACKETQUEUE_H
