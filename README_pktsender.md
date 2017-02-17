pktsender:
Generating traffic that is constructed according to a 5-tuple trace file.
Only support TCP and UDP packet generation.

Usage:
./build/MoonGen pktsender/pktsender.lua <devList> <traceFile> [-r rate] [-s pktsize]

Example of trace file is located in pktsender/traces/, the format is`<srcIP> <dstIP> <srcPort> <dstPort> <proto> <ignore> <ignore>`.
Note: all data in trace file are represented in host byte order.
