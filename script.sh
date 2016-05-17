#!/bin/bash

> test.txt
for i in {1..30}
do
    echo "1"
    click conf/ipv6_net_success_version.click
    cat average.txt >> test.txt
done

