#include <iostream>
#include <fstream>
#include "ForwardingTable.h"
#include "PacketQueue.h"
#include "HeaderAnalysis.h"
#include "PortIn.h"
#include "PortOut.h"
#include <thread>
#include <zconf.h>
#include <regex>

using namespace std;

table forwardingTable = tableInit();

int main() {
    // 载入路由表
    cout << "[Initialization] Loading forwarding table..." << endl;
    string ip, mask, port;
    ifstream infile("table.txt");
    if (!infile.is_open()) {
        cerr << "[Error] File not found." << endl;
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < 4; ++i) {
        infile >> ip >> mask >> port;
        if (stoi(port) != i) {
            cerr << "[Error] Wrong format." << endl;
            exit(EXIT_FAILURE);
        }
        tableAppend(ip.c_str(), mask.c_str(), i, forwardingTable);
    }
    infile.close();
    tableDisplay(forwardingTable);
    cout << "[Initialization] Forwarding table loaded." << endl;

    // 载入抓包过滤条件
    string filter_cidr0, filter_cidr1;
    regex validCIDR("([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\." \
                    "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\." \
                    "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\." \
                    "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/" \
                    "([0-9]|[1-2][0-9]|3[0-2])"); // 用正则表达式匹配IP/CIDR格式
    cout << "[Initialization] Please specify an IP/CIDR for Port 0 " \
            "to filter traffic to capture (default: 172.0.0.0/8): ";
    getline(cin, filter_cidr0);
    if (filter_cidr0.empty())
        filter_cidr0 = "172.0.0.0/8";
    while (!regex_match(filter_cidr0, validCIDR)) {
        cout << "[Error] Invalid CIDR format." << endl;
        cout << "[Initialization] Please specify an IP/CIDR for Port 0 " \
                "to filter traffic to capture (default: 172.0.0.0/8): ";
        getline(cin, filter_cidr0);
        if (filter_cidr0.empty())
            filter_cidr0 = "172.0.0.0/8";
    }
    cout << "[Initialization] Please specify an IP/CIDR for Port 1 " \
            "to filter traffic to capture (default: 10.0.0.0/8): ";
    getline(cin, filter_cidr1);
    if (filter_cidr1.empty())
        filter_cidr1 = "10.0.0.0/8";
    while (!regex_match(filter_cidr1, validCIDR)) {
        cout << "[Error] Invalid CIDR format." << endl;
        cout << "[Initialization] Please specify an IP/CIDR for Port 1 " \
                "to filter traffic to capture (default: 10.0.0.0/8): ";
        getline(cin, filter_cidr1);
        if (filter_cidr1.empty())
            filter_cidr1 = "10.0.0.0/8";
    }

    // 打开输入输出端口
    PortIn port0(0);
    thread input0(port0, filter_cidr0);
    input0.detach();
    cout << "[Initialization] Input port Port 0 activated." << endl;
    sleep(1);
    PortIn port1(1);
    thread input1(port1, filter_cidr1);
    input1.detach();
    cout << "[Initialization] Input port Port 1 activated." << endl;
    sleep(1);
    PortOut port2(2);
    thread output0(port2);
    output0.detach();
    cout << "[Initialization] Output port Port 2 activated." << endl;
    sleep(1);
    PortOut port3(3);
    thread output1(port3);
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
