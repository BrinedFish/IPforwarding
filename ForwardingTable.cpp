#include "ForwardingTable.h"
#include <iostream>
#include <iomanip>
using namespace std;

void tableAppend(const char* nid, const char* mask, int port, table T) {
    table newEntry;
    newEntry = (table)malloc(sizeof(tableEntry));
    inet_aton(nid, &newEntry->nid);
    inet_aton(mask, &newEntry->mask);
    newEntry->port = port;
    newEntry->next = nullptr;
    table p = T;
    while (p->next != nullptr) {
        p = p->next;
    }
    p->next = newEntry;
}

table tableInit() {
    table head;
    head = (table)malloc(sizeof(tableEntry));
    head->next = nullptr;
    return head;
}

void tableDisplay(table T) {
    table p = T->next;
    cout << "--------------------------------------------------" << endl;
    cout << left << setw(23) << "Network ID"
         << left << setw(23) << "Subnet Mask"
         << left << setw(23) << "Port"
         << endl;
    cout << "--------------------------------------------------" << endl;
    while (p != nullptr) {
        cout << left << setw(23) << inet_ntoa(p->nid)
             << left << setw(23) << inet_ntoa(p->mask)
             << left << setw(23) << p->port
             << endl;
        p = p->next;
    }
    cout << "--------------------------------------------------" << endl;
}

tableEntry tableLookup(table T, const struct in_addr &ip) {
    table p = T->next;
    tableEntry ret;
    ret.port = -1; //查不到时返回端口号为-1的表记录
    while (p && ((p->mask.s_addr & ip.s_addr) != p->nid.s_addr)) {
        // 将目的地址与各个端口的子网掩码进行按位与运算，然后与网络号比对
        p = p->next;
    }
    if (p)
        ret = *p;
    return ret;
}
