#ifndef IPFORWARDING_HEADERANALYSIS_H
#define IPFORWARDING_HEADERANALYSIS_H
#include <sys/types.h>
#include <arpa/inet.h>

// 每个原始数据包（以太网帧）的最大长度
#define SNAP_LEN 1518
// 以太网帧的头部长度为14字节
#define SIZE_ETHERNET 14
// IP数据报头部模式
struct typecastIP {
    u_char         v_hl;    // 4比特版本号 + 4比特首部长度
    u_char         tos;     // 8比特服务类型
    u_short        len;     // 16比特数据报长度
    u_short        id;      // 16比特标识
    u_short        off;     // 16比特片偏移
    u_char         ttl;     // 8比特TTL
    u_char         prot;    // 8比特上层协议
    u_short        cks;     // 16比特校验和
    struct in_addr src;     // 源地址
    struct in_addr dst;     // 目的地址
};

#endif //IPFORWARDING_HEADERANALYSIS_H
