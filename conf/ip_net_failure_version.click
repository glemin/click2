// ipclassifier net test, ip failure version

InfiniteSource(LIMIT 100001, LENGTH 1)
-> UDPIPEncap(10.0.0.1, 1200, 10.0.0.2, 1201)
-> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
-> ipclassifier :: IPClassifier(net 20.0.0.0/8)
ipclassifier[0] -> Discard;
