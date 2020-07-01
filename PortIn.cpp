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

[[noreturn]] void PortIn::packetCapture(const string &filter_cidr) {
    char *dev = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // 设置抓包过滤条件
    string filter_exp = "dst net " + filter_cidr;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // 寻找默认网络接口
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        cerr << "[Error] Couldn't find default device: " << errbuf << endl;
        exit(EXIT_FAILURE);
    }
    // 获取网络接口参数
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        cout << "[Warning] Couldn't get netmask for device " << dev << ": " << errbuf << endl;
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "[Error] Couldn't open device " << dev << ": " << errbuf << endl;
        exit(EXIT_FAILURE);
    }
    // 检查是否为以太网设备
    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << "[Error] " << dev << " is not an Ethernet device" << endl;
        exit(EXIT_FAILURE);
    }
    // 应用过滤条件
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        cerr << "[Error] Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "[Error] Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }
    // 开始抓包
    switch (id) {
        case 0:
            cout << "[Port 0] Port 0 is listening on " << dev << " for packets to "
                 << filter_cidr << "." << endl;
            while (true) {
                pcap_loop(handle, 1, got_packet0, nullptr);
                // 数据包指针向后移动以太网帧头部的长度，即从原始数据包（以太网帧）中取出IP数据报
                cout << endl << "[Port 0] " << "A packet captured via " << dev << endl;
                queueAppend(tempStorage0 + SIZE_ETHERNET, this->queue); // 加入输入队列
            }
            break;
        case 1:
            cout << "[Port 1] Port 1 is listening on " << dev << " for packets to "
                 << filter_cidr << "." << endl;
            while (true) {
                pcap_loop(handle, 1, got_packet1, nullptr);
                // 数据包指针向后移动以太网帧头部的长度，即从原始数据包（以太网帧）中取出IP数据报
                cout << endl << "[Port 1] " << "A packet captured via " << dev << endl;
                queueAppend(tempStorage1 + SIZE_ETHERNET, this->queue); // 加入输入队列
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

void PortIn::operator()(const string &filter_cidr) {
    this->packetCapture(filter_cidr);
}
