#!/bin/bash

> test.txt
for i in {1..30}
do
    echo "$i"
    click conf/ip_net_failure_version.click
    cat average.txt >> test.txt
done

