# ! bin/bash

# Create FIFO only if missing
if [[ ! -p /tmp/wifi_pluto_week6.pcap ]]; then
    mkfifo /tmp/wifi_pluto_week6.pcap
fi

# Start Wireshark on the FIFO
wireshark -k -i /tmp/wifi_pluto_week6.pcap -y IEEE802_11 &

# Start GNU Radio Companion
killall gnuradio-companion 2>/dev/null
gnuradio-companion
