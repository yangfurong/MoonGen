--- This script implements a simple QoS test by generating two flows and measuring their latencies.
local mg		= require "moongen" 
local memory	= require "memory"
local device	= require "device"
local filter	= require "filter"
local stats		= require "stats"
local log		= require "log"
local ffi       = require "ffi"
local pipe      = require "pipe"
local barrier   = require "barrier"
require "utils"
local hton16, ntoh16, hton, ntoh = hton16, ntoh16, hton, ntoh

ffi.cdef[[
    struct tuple_t{
        uint32_t srcIP;
        uint32_t dstIP;
        uint16_t srcPort;
        uint16_t dstPort;
        uint8_t proto;
    };
    struct pktTraces_t{
        struct tuple_t *tuples;
        uint32_t n;
    };
]]

local RXQUEUE_NB = 1
local TXQUEUE_NB = 4

function configure(parser)
    parser:description("Read packet traces and replay these traffic. Packet traces are represented by a trace file.")
    parser:argument("devList", "Dpdk-dev list, seperated by comma. (e.g. 0,1)")
    parser:argument("traceFile", "Packet traces file.")
    parser:option("-s --pkt-size", "Packet Size in Bytes. (default 64B)"):default(64):convert(tonumber):target("pktSize")
    parser:option("-r --traffic-rate", "Traffic rate in Mbit/s. (default 10000Mbit/s)"):default(10000):convert(tonumber):target("rate")
end

local function parseDevList(devList)
    local devs = {}
    for s in string.gmatch(devList, "%d+") do
        table.insert(devs, device.config{port = tonumber(s), txQueues = TXQUEUE_NB, rxQueues = RXQUEUE_NB})
    end
    assert(#devs > 0)
    return devs
end

local function makeTuple(srcIP, dstIP, srcPort, dstPort, proto)
    return {
        srcIP = srcIP,
        dstIP = dstIP,
        srcPort = srcPort,
        dstPort = dstPort,
        proto = proto
    }
end

local function readPacketTraces(filename)
    local file = io.open(filename, "r")
    assert(file)
    local tuples = {}
    for line in file:lines() do
        local vars = {}
        for v in string.gmatch(line, "%d+") do
            table.insert(vars, tonumber(v))
        end
        -- only use tcp or udp packets
        if(vars[5] == 6 or vars[5] == 17) then
            table.insert(tuples, makeTuple(vars[1], vars[2], vars[3], vars[4], vars[5]))
        end
    end
    assert(#tuples > 0)
    log:info("read %d packet traces from file %s", #tuples, filename)
    -- convert to c-struct
    local pt = memory.alloc("struct pktTraces_t*", ffi.sizeof("struct pktTraces_t"))
    pt.n = #tuples
    pt.tuples = memory.alloc("struct tuple_t*", ffi.sizeof("struct tuple_t") * pt.n)
    for i = 1, #tuples do
        pt.tuples[i - 1].srcIP = tuples[i].srcIP
        pt.tuples[i - 1].dstIP = tuples[i].dstIP
        pt.tuples[i - 1].srcPort = tuples[i].srcPort
        pt.tuples[i - 1].dstPort = tuples[i].dstPort
        pt.tuples[i - 1].proto = tuples[i].proto
    end
    return pt
end

local function dispatchTraces(fastPipe, pt, slaves)
    for i = 1, slaves do
        fastPipe:send(pt)
    end
end

function master(args)
    local devs = parseDevList(args.devList)
	-- wait until the links are up
	device.waitForLinks()
    log:info("PortList: %s", args.devList)
	log:info("Sending %d MBit/s traffic per port", args.rate)
	-- setup rate limiters for CBR traffic
    for _, dev in ipairs(devs) do
        for i = 0, TXQUEUE_NB - 1 do
            dev:getTxQueue(i):setRate(args.rate)
        end
    end

    local pt = readPacketTraces(args.traceFile)
    local bar = barrier:new(#devs * TXQUEUE_NB)
    stats.startStatsTask(devs)
    if args.rate > 0 then
        --[[
        for i = 0, pt.n - 1 do
            log:info("%d %d %d %d %d", pt.tuples[i].srcIP, pt.tuples[i].dstIP, pt.tuples[i].srcPort, pt.tuples[i].dstPort, pt.tuples[i].proto)
        end
        --]]
        -- share packet traces between tasks
        local fastPipe = pipe:newFastPipe()
        dispatchTraces(fastPipe, pt, #devs * TXQUEUE_NB)
        -- launch tasks
        for _, dev in ipairs(devs) do
            for i = 0, TXQUEUE_NB - 1 do
    		    mg.startTask("loadSlave", dev:getTxQueue(i), args.pktSize, string.format("P%d_Q%d", _ - 1, i), fastPipe, bar)
            end
        end
	end
    ---- start rx tasks
    --for _, dev in ipairs(devs) do
    --    for i = 0, RXQUEUE_NB - 1 do
    --        mg.startTask("rxSlave", dev:getRxQueue(i), string.format("P%d_Q%d", _ - 1, i), bar)
    --    end
    --end
	-- wait until all tasks are finished
	mg.waitForTasks()
    memory.free(pt.tuples)
    memory.free(pt)
end

function loadSlave(queue, pktSize, taskName, fastPipe, bar)
    bar:wait()
    log:info("loadSlave[%s] running...", taskName)
	-- TODO: implement barriers
    -- trim CRC
    local pktSize = pktSize - 4 
    local pt = ffi.cast("struct pktTraces_t*", fastPipe:recv())
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = pktSize, -- this sets all length headers fields in all used protocols
			ethSrc = queue, -- get the src mac from the device
			-- payload will be initialized to 0x00 as new memory pools are initially empty
		}
	end)
	-- TODO: fix per-queue stats counters to use the statistics registers here
	-- a buf array is essentially a very thing wrapper around a rte_mbuf*[], i.e. an array of pointers to packet buffers
	local bufs = mem:bufArray()
    local traceIndex = 0
	while mg.running() do
		-- allocate buffers from the mem pool and store them in this array
		bufs:alloc(pktSize)
		for _, buf in ipairs(bufs) do
			-- modify some fields here
            local tuple = pt.tuples[traceIndex]
			if(tuple.proto == 6) then
                local pkt = buf:getTcpPacket()
                pkt.ip4:setSrc(tuple.srcIP)
                pkt.ip4:setDst(tuple.dstIP)
                pkt.ip4:setProtocol(tuple.proto)
                pkt.tcp:fill{tcpSrc = tuple.srcPort, tcpDst = tuple.dstPort}
                buf:offloadTcpChecksum()
            else
                local pkt = buf:getUdpPacket()
                pkt.ip4:setSrc(tuple.srcIP)
                pkt.ip4:setDst(tuple.dstIP)
                pkt.ip4:setProtocol(tuple.proto)
                pkt.udp:fill{udpSrc = tuple.srcPort, udpDst = tuple.dstPort, 
                udpLength = pkt.ip4:getLength() - pkt.ip4:getHeaderLength() * 4 - 8}
                buf:offloadUdpChecksum()
            end
            traceIndex = traceIndex + 1
            if(traceIndex >= pt.n) then
                traceIndex = 0
            end
		end
		-- send packets
		-- txCtr:updateWithSize(queue:send(bufs), pktSize)
        queue:send(bufs)
	end
end

--function rxSlave(queue, taskName, bar)
--    log:info("rxSlave[%s] running...", taskName)
--    local bufs = memory.bufArray()
--    bar:wait()
--    while mg.running(100) do
--        --local rx = queue:recv(bufs)
--        --bufs:freeAll()
--    end
--end
