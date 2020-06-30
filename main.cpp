#include <iostream>
#include "ForwardingTable.h"
#include "PacketQueue.h"
#include "HeaderAnalysis.h"
#include "PortIn.h"
#include "PortOut.h"
#include <thread>
#include <zconf.h>

using namespace std;

table forwardingTable = tableInit();

int main() {
    // 载入路由表
    cout << endl << "[Initialization] Loading forwarding table..." << endl;
    tableAppend("192.168.1.0", "255.255.255.0", 0, forwardingTable);
    tableAppend("192.168.2.0", "255.255.255.0", 1, forwardingTable);
    tableAppend("172.16.0.0", "255.240.0.0", 2, forwardingTable);
    tableAppend("10.0.0.0", "255.0.0.0", 3, forwardingTable);
    tableDisplay(forwardingTable);
    cout << "[Initialization] Forwarding table loaded." << endl;

    // 打开输入输出端口
    PortIn port0(0);
    thread input0(port0);
    PortIn port1(1);
    thread input1(port1);
    PortOut port2(2);
    thread output0(port2);
    PortOut port3(3);
    thread output1(port3);
    input0.detach();
    cout << "[Initialization] Input port Port 0 activated." << endl;
    input1.detach();
    cout << "[Initialization] Input port Port 1 activated." << endl;
    output0.detach();
    cout << "[Initialization] Output port Port 2 activated." << endl;
    output1.detach();
    cout << "[Initialization] Output port Port 3 activated." << endl;
    cout << "[Initialization] Initialization complete." << endl;

    // 路由器中心
#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    while (true) {
        if (!port0.isEmpty()) {
            static const u_char *packet;
            static const struct typecastIP *datagram;
            packet = port0.packetInput(); // 从输入队列中取出一个数据包
            datagram = (struct typecastIP*)(packet); // 套用IP头部模式
            cout << "[Forwarding] A packet picked from Port 0." << endl;
            cout << "[Forwarding] Analyzing IP header..." << endl;

            // 查表转发
            cout << "[Forwarding] Looking up forwarding table..." << endl;
            switch (tableLookup(forwardingTable, datagram->dst).port) {
                case 2:
                    cout << "[Forwarding] This packet is going to Port 2." << endl;
                    port2.packetInsert(packet);
                    break;
                case 3:
                    cout << "[Forwarding] This packet is going to Port 3." << endl;
                    port3.packetInsert(packet);
                    break;
                default:
                    cout << "[Forwarding] This packet has nowhere to go." << endl;
            }
        }
        if (!port1.isEmpty()) {
            static const u_char *packet;
            static const struct typecastIP *datagram;
            packet = port1.packetInput(); // 从输入队列中取出一个数据包
            datagram = (struct typecastIP*)(packet); // 套用IP头部模式
            cout << "[Forwarding] A packet picked from Port 1." << endl;
            cout << "[Forwarding] Analyzing IP header..." << endl;

            // 查表转发
            cout << "[Forwarding] Looking up forwarding table..." << endl;
            switch (tableLookup(forwardingTable, datagram->dst).port) {
                case 2:
                    cout << "[Forwarding] This packet is going to Port 2." << endl;
                    port2.packetInsert(packet);
                    break;
                case 3:
                    cout << "[Forwarding] This packet is going to Port 3." << endl;
                    port3.packetInsert(packet);
                    break;
                default:
                    cout << "[Forwarding] This packet has nowhere to go." << endl;
            }
        }
        usleep(100);
    }
#pragma clang diagnostic pop

    return 0;
}
