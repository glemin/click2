// ipclassifier net test, ip failure version

InfiniteSource(LIMIT 100001, LENGTH 1)
-> UDPIPEncap(255.0.0.1, 1200, 10.0.0.2, 1201) // first bit is '1'
-> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
-> ipclassifier :: IPClassifier(net 0.0.0.0/20) // first bit is '0'
ipclassifier[0] -> Discard;
