#include "PortIn.h"
#include "HeaderAnalysis.h"
#include <iostream>
#include <pcap.h>
using namespace std;

// 全局静态变量用于暂存pcap抓取到的数据包指针
static const u_char* tempStorage0;
static const u_char* tempStorage1;

PortIn::PortIn(int id): id(id) {
    this->queue = queueInit();
}

const u_char *PortIn::packetInput() {
    return queuePop(this->queue);
}

void got_packet0(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    tempStorage0 = packet;
}

void got_packet1(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    tempStorage1 = packet;
}

[[noreturn]] void PortIn::packetCapture() {
    char *dev = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // 设置过滤器，这里抓取172.或10.的分组
    char filter_exp0[] = "dst net 172"; // Port 0抓取发往172.的分组
    char filter_exp1[] = "dst net 10"; // Port 1抓取发往10.的分组
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // 寻找默认网络接口
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        cerr << "Couldn't find default device: " << errbuf << endl;
        abort();
    }
    // 获取网络接口参数
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        cerr << "Couldn't get netmask for device " << dev << ": " << errbuf << endl;
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
        abort();
    }
    // 检查是否为以太网设备
    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << dev << " is not an Ethernet device" << endl;
        abort();
    }
    // 编译过滤器并开始抓包
    switch (id) {
        case 0:
            if (pcap_compile(handle, &fp, filter_exp0, 0, net) == -1) {
                cerr << "Couldn't parse filter " << filter_exp0 << ": " << pcap_geterr(handle) << endl;
                abort();
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                cerr << "Couldn't install filter " << filter_exp0 << ": " << pcap_geterr(handle) << endl;
                abort();
            }
            cout << "[Port 0] Port 0 is listening on " << dev << " for 172.0.0.0/8." << endl;
            while (true) {
                pcap_loop(handle, 1, got_packet0, nullptr);
                // 数据包指针向后移动以太网帧头部的长度，即从原始数据包（以太网帧）中取出IP数据报
                queueAppend(tempStorage0 + SIZE_ETHERNET, this->queue);
                cout << endl << "[Port 0] " << "A packet captured via " << dev << endl;
            }
            break;
        case 1:
            if (pcap_compile(handle, &fp, filter_exp1, 0, net) == -1) {
                cerr << "Couldn't parse filter " << filter_exp1 << ": " << pcap_geterr(handle) << endl;
                abort();
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                cerr << "Couldn't install filter " << filter_exp1 << ": " << pcap_geterr(handle) << endl;
                abort();
            }
            cout << "[Port 1] Port 1 is listening on " << dev << " for 10.0.0.0/8." << endl;
            while (true) {
                pcap_loop(handle, 1, got_packet1, nullptr);
                // 数据包指针向后移动以太网帧头部的长度，即从原始数据包（以太网帧）中取出IP数据报
                queueAppend(tempStorage1 + SIZE_ETHERNET, this->queue);
                cout << endl << "[Port 1] " << "A packet captured via " << dev << endl;
            }
            break;
    }

    // cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
}

bool PortIn::isEmpty() {
    return !this->queue->next;
}

void PortIn::operator()() {
    this->packetCapture();
}
