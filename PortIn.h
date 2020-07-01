#ifndef IPFORWARDING_PORTIN_H
#define IPFORWARDING_PORTIN_H
#include "PacketQueue.h"
#include <string>

class PortIn {
private:
    int id;
    packetQueue queue;

    [[noreturn]] void packetCapture(const std::string &filter_cidr); // 从实际网络接口抓包并送到输入队列
public:
    explicit PortIn(int id);
    const u_char* packetInput(); // 供路由器中心调用
    bool isEmpty();
    void operator()(const std::string &filter_cidr); // 重载()操作符，用于分离线程
};

// 自定义pcap_loop的回调函数
void got_packet0(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void got_packet1(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //IPFORWARDING_PORTIN_H
