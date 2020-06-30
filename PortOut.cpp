#include "PortOut.h"
#include "HeaderAnalysis.h"
#include "ForwardingTable.h"
#include <iostream>
#include <zconf.h>
using namespace std;

extern table forwardingTable;

PortOut::PortOut(int id):id(id) {
    this->queue = queueInit();
}

void PortOut::packetInsert(const u_char *packet) {
    queueAppend(packet, this->queue);
}

void PortOut::packetOutput() {
    static const u_char *packet;
    static const struct typecastIP *datagram;
    packet = queuePop(this->queue); //从队列中取出一个数据包
    datagram = (struct typecastIP*)(packet); // 套用IP头部模式

    cout << "[Port " << this->id << "] Printing packet detail..." << endl;
    cout << "     From: " << inet_ntoa(datagram->src) << endl;
    cout << "       To: " << inet_ntoa(datagram->dst) << endl;
    cout << "    NetID: " << inet_ntoa(tableLookup(forwardingTable, datagram->dst).nid) << endl;
    cout << "     Port: " << this->id << endl;
}

bool PortOut::isEmpty() {
    return !this->queue->next;
}

[[noreturn]] void PortOut::operator()() {
    while (true) {
        if (!this->isEmpty()) {
            this->packetOutput();
        }
        usleep(100);
    }
}
