CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -std=c11 -D_DEFAULT_SOURCE
LDFLAGS  =
PTHREAD  = -lpthread

SRC      = src
UTILS_O  = $(SRC)/utils.o
SYN_O    = $(SRC)/syn_scanner.o
CONN_O   = $(SRC)/connect_scanner.o
SNIFF_O  = $(SRC)/packet_sniffer.o
ARP_O    = $(SRC)/arp_spoofer.o

PCAP_LIBS  := $(shell pkg-config --libs libpcap 2>/dev/null || echo "-lpcap")
PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null || echo "")

PCAP_AVAIL := $(shell echo "int main(){return 0;}" | $(CC) -x c - $(PCAP_LIBS) -o /dev/null 2>/dev/null && echo yes)

.PHONY: all clean syn-scanner connect-scanner sniffer arp-spoof

all: syn-scanner connect-scanner sniffer arp-spoof

$(SRC)/%.o: $(SRC)/%.c $(SRC)/%.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC)/packet_sniffer.o: $(SRC)/packet_sniffer.c $(SRC)/packet_sniffer.h
	$(CC) $(CFLAGS) $(PCAP_CFLAGS) $(if $(PCAP_AVAIL),-DHAVE_PCAP,) -c $< -o $@

$(SRC)/utils.o: $(SRC)/utils.c $(SRC)/utils.h
	$(CC) $(CFLAGS) -c $< -o $@

syn-scanner: $(UTILS_O) $(SYN_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

connect-scanner: $(UTILS_O) $(CONN_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(PTHREAD)

sniffer: $(UTILS_O) $(SNIFF_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(if $(PCAP_AVAIL),$(PCAP_LIBS),)

arp-spoof: $(UTILS_O) $(ARP_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(SRC)/*.o syn-scanner connect-scanner sniffer arp-spoof
