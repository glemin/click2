#!/bin/bash

interpacket_time = 1
test_scenarios = (1.txt 2.txt 3.txt 4.txt 5.txt 6.txt 7.txt)

for i in "${test_scenarios[@]}"
do
  until [ "$RX_BYTES" -eq "$TX_BYTES" ]; do
    echo $interpacket_time

    # resetting counter
    ifconfig enp2s0f0 down
    modprobe -r tg3
    modprobe tg3
    ifconfig enp2s0f0 up

    # send stream of packets
    timeout 2s trafgen --dev  enp2s0f0 --conf 1.txt -t "$interpacket_time"ms

    # wait 2 seconds for any residual frames to be received
    sleep 2s

    # compare # recieved frames with # sent frames, if equal throughput found
    RX_BYTES="$(ifconfig | grep -oP '(?<=RX bytes:)[0-9]*')"
    TX_BYTES="$(ifconfig | grep -oP '(?<=TX bytes:)[0-9]*')"
    interpacket_time=$(( $interpacket_time * 2))
  done
  intperpacket_time = 1
  # test completed
  # save value in file
  echo "De gevonden interpacket time is:  $(( $interpacket_time / 2))"
done
