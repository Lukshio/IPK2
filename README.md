# IPK projekt 2 2022/2023
## Lukáš Ježek
#### xjezek19@stud.fit.vutbr.cz

## Dokumentace
### Požadavky
- C++ standard 20+
- make
- knihovna PCAP
#### Kompabilita se systémem windows
Kvůli použitým knihovnám `<arpa/inet.h> <netinet/in.h> <unistd.h>` aplikaci nelze použít na windows, teoreticky je možné je krom poslední zmíněné nahradit knihovnou `<winsock2.h>` v praxi však netestováno
### Kompilace a spuštění
Program využívá pouze jednoho souboru a to `main.cpp`, script se poté kompiluje pomocí `Makefile` příkazem `make`, tímto se vygeneruje binární spustitelný soubor `ipk-sniffer`, který se spouší spouští s povinnými přepínači: `sudo ./ipk-sniffer [-i interface | --interface interface] -p port [--tcp|-t] [--udp|-u] [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] -n num`.
Je nutné mít nainstalovanou knihovnu PCAP. Program je nutné spouštět s root právy (sudo). 

### Popis `main.cpp`
Program začíná vstupem do funkce `main(int argc, char *argv[])`, jako první se zvaliduje počet přijatých argumentů a jejich správnost, v případě protokolů se rovnou přidá příslušný protokol v závislosti na typu do proměnné `filter` nebo `no_port_filter`. Dále se ze začátku filtru umaže ` or ` pro správnost. Následuje nastavení filtru a hlavní smyčky odchytávání packetů `(pcap_loop(handle, num_packets, parsePacket, nullptr)`. Pro každý packet se volá funkce `parsePacket` ve které se naparsuje IP hlavička a ethernetová hlavička. Zavolá se funkce `printPacket`, která obstará správný výpis dat packetu na standardní výstup.
Používá pomocné funkce pro timestamp `getTimestamp()` . Pokud se jedná o UDP nebo TCP, zavolá se funkce pro výpis portů. Jako poslední se zavolá funkce `printPacketData` která vypíše dle zadaného formátu obsah packetu v hexadecimálním a ascii formátu. Bližsí funkcionalita je popsána v kódu.

### Příkazy
Příklady příkazů lze nalézt v dokumentaci zadání projektu: [link na zadání projektu](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Project%202/zeta).   
Případně se při zadání neplatného parametru vypíše příklad použití.

## Testování
Program jsem testoval za použití programu Wireshark, ve kterém jsem zachytával stejné packety a porovnával výstupy. Vybrané výsledky testování naleznete ve složce `tests`.

## Reference 
[1] [Zadání projektu](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Project%202/zeta)  
[2] [TCPReplay](https://tcpreplay.appneta.com)  
[3] [PCAP](https://www.tcpdump.org/manpages/pcap.3pcap.html)  
[4] [MLD wiki](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery)   
[5] [NDP wiki](https://cs.wikipedia.org/wiki/Neighbor_Discovery_Protocol)   
[6] [ICMPv6 wiki](https://cs.wikipedia.org/wiki/ICMPv6)