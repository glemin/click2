// ipclassifier frag test (1 header), ipv6 failure version

InfiniteSource(LIMIT 100001, LENGTH 1)
-> UDPEncap(1200, 1201)
-> IP6Encap(SRC fa80::0202:b3ff:fe1e:8329, DST f880::0202:b3ff:fe1e:0002, PROTO 17)
-> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
-> ipclassifier :: IP6Classifier(ip6 frag)
ipclassifier[0] -> Discard;
