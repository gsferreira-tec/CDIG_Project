# ! bin/bash

# Create FIFO only if missing
if [[ ! -p /tmp/wifi_week6_livecap.pcap ]]; then
    mkfifo /tmp/wifi_week6_livecap.pcap
fi

# Start Wireshark on the FIFO
wireshark -k -i /tmp/wifi_week6_livecap.pcap -y IEEE802_11 &

# Start GNU Radio Companion
gnuradio-companion
