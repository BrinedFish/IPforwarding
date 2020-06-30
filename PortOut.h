#ifndef IPFORWARDING_PORTOUT_H
#define IPFORWARDING_PORTOUT_H
#include "PacketQueue.h"

class PortOut {
private:
    int id;
    packetQueue queue;
    void packetOutput(); // 输出IP数据报
public:
    explicit PortOut(int id);
    void packetInsert(const u_char *packet); // 供路由器中心调用
    bool isEmpty();

    [[noreturn]] void operator()(); // 重载()操作符，用于分离线程
};

#endif //IPFORWARDING_PORTOUT_H
