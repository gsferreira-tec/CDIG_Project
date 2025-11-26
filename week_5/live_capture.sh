# ! bin/bash

# Create FIFO only if missing
if [[ ! -p /tmp/wifi_pluto_capture.pcap ]]; then
    mkfifo /tmp/wifi_pluto_capture.pcap
fi

# Start Wireshark on the FIFO
wireshark -k -i /tmp/wifi_pluto_capture.pcap -y IEEE802_11 &

# Start GNU Radio Companion
gnuradio-companion
