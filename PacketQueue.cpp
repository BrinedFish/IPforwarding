#include "PacketQueue.h"
#include <cstdlib>
using namespace std;

void queueAppend(const u_char *content, packetQueue Q) {
    packetQueue newPacket;
    newPacket = (packetQueue)malloc(sizeof(packet));
    newPacket->content = content;
    newPacket->next = nullptr;
    packetQueue p = Q;
    while (p->next != nullptr) {
        p = p->next;
    }
    p->next = newPacket;
}

packetQueue queueInit() {
    packetQueue head;
    head = (packetQueue)malloc(sizeof(packet));
    head->next = nullptr;
    return head;
}

const u_char* queuePop(packetQueue &Q) {
    packetQueue p = Q->next;
    if (Q->next == nullptr)
        return nullptr;
    else {
        if (Q->next->next != nullptr)
            Q->next = Q->next->next;
        else
            Q->next = nullptr;
        const u_char* content = p->content;
        free(p);
        return content;
    }
}
