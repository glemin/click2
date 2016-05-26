// ipclassifier net test, ipv6 success version

InfiniteSource(LIMIT 100001, LENGTH 1)
-> UDPIP6Encap(fa80::0202:b3ff:fe1e:8329, 1200, f880::0202:b3ff:fe1e:0002, 1201) // first bit is '0'
-> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
-> ipclassifier :: IP6Classifier(net 0a80::0202:b3ff:fe1e:8329/20) // first bit is '1'
ipclassifier[0] -> Discard;
