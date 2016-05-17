// ipclassifier frag test (1 header), ip success version

InfiniteSource(LIMIT 100001, LENGTH 1)
-> UDPIPEncap(10.0.0.1, 1200, 10.0.0.2, 1201)
-> EtherEncap(0x0800, 00:0a:95:9d:68:16, 00:0a:95:9d:68:17)
// element that sets the fragment bit
-> ipclassifier :: IPClassifier(ip frag)
ipclassifier[0] -> Discard;
