package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"strings"
	"errors"
//	"sync/atomic"
//	"container/list"
//	"encoding/binary"
//	"encoding/hex"
//	"bufio"
	"runtime"
	"strconv"
	
	"./github.com/miekg/pcap"
	"./github.com/streadway/amqp"
	"./kakao.com/mrte"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

var (
	// Packet capture
	device  	= flag.String("interface", "", "Network interface to capture packet (example : eth0, lo")
	port    	= flag.Int("port", 3306, "Network port to capture packet (This is the listening port of MySQL server")
	threads    	= flag.Int("thread_count", 4, "Message queue publisher counter")
	max_queue 	= flag.Int("queue_size", 100, "Internal queue length of each publisher thread")
	
	snaplen 	= flag.Int("snapshot_len", 8192, "Snapshot length of packet capture")   // Default 8KB
	read_timeout= flag.Int("read_timeout", 100, "Read timeout of packet capture in milli-second") // Milli-second
	
	mysql_host  = flag.String("mysql_host", "", "Source MySQL server (hostname or ip-address)")
	mysql_user  = flag.String("mysql_user", "", "Soruce MySQL user account (example : kamrte)")
	mysql_password  = flag.String("mysql_password", "", "Source MySQL user password")
	
	// Message queue
	mq_host        = flag.String("rabbitmq_host", "", "Rabbit MQ server (hostname or ip-address)")
	mq_port        = flag.Int("rabbitmq_port", 5672, "Rabbit MQ server port (default 5672)")
	mq_user        = flag.String("rabbitmq_user", "", "Rabbit MQ server user account")
	mq_password    = flag.String("rabbitmq_password", "", "Rabbit MQ server user password")
	
	mq_exchange_name = flag.String("rabbitmq_exchange_name", "mrte", "Rabbit MQ exchange name (default 'mrte')")
	mq_routing_key = flag.String("rabbitmq_routing_key", "", "Rabbit MQ routing key (default '')")
	
	help    	= flag.Bool("help", false, "Print this message")
)

// Print status interval second
const STATUS_INTERVAL_SECOND = uint64(10)

// Internal queue for rabbit mq publisher
var queues []chan *mrte.MysqlRequest

/**
 * Global status variables
 */
var totalPacketCaptured   uint64
var validPacketCaptureds  []uint64
var mqErrorCounters       []uint64

var localIpAddress net.IP


/**
 * Packet
 *
 * + TCPDUMP man page : http://linux.die.net/man/8/tcpdump
 * + TCP Flags (http://en.wikipedia.org/wiki/Transmission_Control_Protocol)
 *       SYN - Initiates a connection
 *       ACK - Acknowledges received data
 *       FIN - Closes a connection
 *       RST - Aborts a connection in response to an error
 *       RST - Reset the connection
 *       NS  – ECN-nonce concealment protection (experimental: see RFC 3540).
 *       CWR – Congestion Window Reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
 *       ECE – ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
 *             If the SYN flag is set (1), that the TCP peer is ECN capable.
 *             If the SYN flag is clear (0), that a packet with Congestion Experienced flag in IP header set is received during normal transmission (added to header by RFC 3168).
 *       PSH - (Push), The sending application informs TCP that data should be sent immediately. (Do not waiting for full buffer)
 *             http://packetlife.net/blog/2011/mar/2/tcp-flags-psh-and-urg/
 *       URG - The URG flag is used to inform a receiving station that certain data within a segment is urgent and should be prioritized. If the URG flag is set, the receiving station evaluates the urgent pointer, a 16-bit field in the TCP header. This pointer indicates how much of the data in the segment, counting from the first byte, is urgent.
 *             http://packetlife.net/blog/2011/mar/2/tcp-flags-psh-and-urg/
 *
 *
 * + Snapshot-length (So, snapshot-length must be greater than 64 byte length
 *   - Size of Ethernet frame - 24 Bytes
 *   - Size of IPv4 Header (without any options) - 20 bytes
 *   - Size of TCP Header (without any options) - 20 Bytes
 *   - So total size of empty TCP datagram - 24 + 20 + 20 = 64 bytes
 *   
 *   - Size of UDP header - 8 bytes
 *   - So total size of empty UDP datagram - 24 + 20 + 8 = 52 bytes
 */
func main() {
	runtime.GOMAXPROCS(6)
	// This limitation make "out of memory"
	// MRTECollector need about 1GB maximum (But usually RES size is 15MB)
	// limitMemory(32*1024*1024/*Rlimit.Cur*/, 256*1024*1024/*Rlimit.Max*/)
	
	flag.Parse()
	if device==nil || *device=="" ||
		mysql_host==nil || *mysql_host=="" ||
		mysql_user==nil || *mysql_user=="" ||
		mysql_password==nil || *mysql_password=="" ||
		mq_host==nil || *mq_host=="" ||
		mq_user==nil || *mq_user=="" ||
		mq_password==nil || *mq_password=="" ||
		mq_exchange_name==nil || *mq_exchange_name=="" || mq_routing_key==nil ||  
		*help {	
		flag.Usage()
		os.Exit(0)
	}

	expr := fmt.Sprintf("tcp dst port %d", *port)
	mq_uri := fmt.Sprintf("amqp://%s:%s@%s:%d/", *mq_user, *mq_password, *mq_host, *mq_port)
	localIpAddress, dev_err := GetLocalIpAddress(*device)
	if dev_err!=nil {
		panic(dev_err)
	}
	
	// 
	//if *device == "" {
	//	devs, err := pcap.FindAllDevs()
	//	if err != nil {
	//		fmt.Fprintln(os.Stderr, "[FATAL] MRTECollector : Couldn't find any devices : ", err)
	//		return
	//	}
	//	if 0 == len(devs) {
	//		flag.Usage()
	//	}
	//	*device = devs[0].Name
	//}

	// Prepare rabbit mq connection
	mqConnection, mq_err := makeConnection(mq_uri, *mq_exchange_name, *mq_routing_key)
	if mq_err!=nil {
		panic(mq_err)
	}
	
	// Prepare rabbit mq publisher
	var realQueueSize = 100
	var realThreadCount int = 4
	if *threads>=2 && *threads<=10 {
		realThreadCount = *threads
	}
	if *max_queue>=100 && *max_queue<=5000 {
		realQueueSize = *max_queue
	}
	
	validPacketCaptureds = make([]uint64, realThreadCount)
	mqErrorCounters = make([]uint64, realThreadCount)
	for idx:=0; idx<realThreadCount; idx++ {
		workerIdx := idx
		queue := make(chan *mrte.MysqlRequest, realQueueSize)
		queues = append(queues, queue)
		
		// Run sub-thread(goroutine) for publishing message
		go mrte.PublishMessage(workerIdx, mqConnection, *mq_exchange_name, *mq_routing_key, localIpAddress, queue, &validPacketCaptureds[idx], &mqErrorCounters[idx])
	}

	// Prepare packet capturer
	h, err := pcap.OpenLive(*device, int32(*snaplen), true, int32(*read_timeout))
	if h == nil {
		fmt.Println(os.Stderr, "[FATAL] MRTECollector : Failed to open packet capture channel : ", err)
		return
	}
	defer h.Close()
	
	err = h.SetDirection("in")
	if err != nil {
		fmt.Println("[FATAL] MRTECollector : SetDirection failed, ", err)
		return
	}

	if expr != "" {
		fmt.Println("[INFO]  MRTECollector : Setting capture filter to '", expr, "'")
		ferr := h.SetFilter(expr)
		if ferr != nil {
			fmt.Println("[ERROR] MRTECollector : Failed to set packet capture filter : ", ferr)
		}
	}
	
	// Add signal handler for KILL | SIGUSR1 | SIGUSR2
	addSignalHandler(h, *mysql_host, int(*port), *mysql_user, *mysql_password)





	
	
	
	// Send init database information & run printing infinite processing info 
	go func(){
		time.Sleep(5 * 1000 * time.Millisecond)
		sendSessionDefaultDatabase(*mysql_host, int(*port), *mysql_user, *mysql_password)
		fmt.Println("[INFO]  Send init database information of all session (1). Wait ...")
		time.Sleep(5 * 1000 * time.Millisecond)
		sendSessionDefaultDatabase(*mysql_host, int(*port), *mysql_user, *mysql_password)
		fmt.Println("[INFO]  Send init database information of all session (2). Done")
		
		// Print processing informations
		loopCounter := 0
		packetDropped := uint64(0)
		packetIfDropped := uint64(0)
		
		// Previous term status variable
		cTotalPacketCaptured := uint64(0)
		pTotalPacketCaptured := uint64(0)
		pValidPacketCounter := uint64(0)
		pPacketDropped := uint64(0)
		pPacketIfDropped := uint64(0)
		pMqErrorCounter := uint64(0)

		for {
			if loopCounter % 20 == 0 {
				fmt.Println()
				fmt.Printf("DateTime                TotalPacket     ValidPacket    PacketDropped    PacketIfDropped      WaitingQueueCnt         MQError\n")
				loopCounter = 0
			}
			
			pcapStats, err := h.Getstats()
			if err==nil {
				packetDropped = uint64(pcapStats.PacketsDropped)
				packetIfDropped = uint64(pcapStats.PacketsIfDropped)
			}
			
			// Length of buffered waiting job of queue
			validPacketCounter := uint64(0)
			mqErrorCounter := uint64(0)
			waitingQueueCounter := uint64(0)
			for idx:=0; idx<realThreadCount; idx++ {
				waitingQueueCounter += uint64(len(queues[idx]))
				validPacketCounter += validPacketCaptureds[idx]
				mqErrorCounter += mqErrorCounters[idx]
			}
			
			dt := time.Now().String()
			cTotalPacketCaptured = totalPacketCaptured
			fmt.Printf("%s %15d %15d  %15d    %15d   %18d %15d\n", dt[0:19], 
                uint64((cTotalPacketCaptured - pTotalPacketCaptured) / STATUS_INTERVAL_SECOND),
                uint64((validPacketCounter - pValidPacketCounter) / STATUS_INTERVAL_SECOND),
                uint64((packetDropped - pPacketDropped) / STATUS_INTERVAL_SECOND),
                uint64((packetIfDropped - pPacketIfDropped) / STATUS_INTERVAL_SECOND),
                waitingQueueCounter,
                uint64((mqErrorCounter - pMqErrorCounter) / STATUS_INTERVAL_SECOND))
			time.Sleep(1000 * time.Millisecond * time.Duration(STATUS_INTERVAL_SECOND)) // each 10 seconds
			loopCounter++
			
			pTotalPacketCaptured = cTotalPacketCaptured
			pValidPacketCounter = validPacketCounter
			pPacketDropped = packetDropped
			pPacketIfDropped = packetIfDropped
			pMqErrorCounter = mqErrorCounter
		}
	}()
	
	
	// --------------------------------------------------------------------
	// Run packet capturer
	// --------------------------------------------------------------------
	var currentWorkerId int
	packets := make([][]*pcap.TcpPacket, realThreadCount)
	bufferSizes := make([]uint64, realThreadCount)
	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r==0 {
			// This is pcap library timeout, 
			// So do nothing BUT flush buffered packets
			for idx:=0; idx<realThreadCount; idx++ {
				if packets[idx]==nil || len(packets[idx])<=0 {
					continue; // Not data to flush
				}

				// Flush buffer to mq publisher
				if len(queues[idx]) > (realQueueSize-10) {
					panic("[FATAL] " + strconv.Itoa(idx) + "th internal queue is fulled, required greater internal queue length")
				}
				queues[idx] <- &mrte.MysqlRequest{
						BufferedData: nil, 
						Packets: packets[idx],
					}
				packets[idx] = nil
				bufferSizes[idx] = 0
			}
		}else{
			totalPacketCaptured++
		
			currentWorkerId = int(pkt.GetPortNo()) % realThreadCount // uint8(pkt.GetPortNo() % uint16(realThreadCount))
			if currentWorkerId<0 {
				currentWorkerId = 0
			}
			packets[currentWorkerId] = append(packets[currentWorkerId], pkt)
			bufferSizes[currentWorkerId] += uint64(pkt.Caplen)
			if len(packets[currentWorkerId])<50 && bufferSizes[currentWorkerId]<(32*1024) {
				// Need to more buffering
				continue
			}
			
			// Flush buffer to mq publisher
			if len(queues[currentWorkerId]) > (realQueueSize-10) {
				panic("[FATAL] " + strconv.Itoa(currentWorkerId) + "th internal queue is fulled, required greater internal queue length")
			}
			queues[currentWorkerId] <- &mrte.MysqlRequest{
					BufferedData: nil, 
					Packets: packets[currentWorkerId],
				}
			packets[currentWorkerId] = nil
			bufferSizes[currentWorkerId] = 0
		}

		// if shutdown==true {workPool.Shutdown("mq_publish")}
	}
	fmt.Fprintln(os.Stderr, "[INFO] MRTECollector : ", h.Geterror())
}

func limitMemory(cur uint64, max uint64) {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_AS, &rLimit)
	if err != nil {
		fmt.Println("[ERROR] Failed to get resource limit : ", err)
	}
	// ftm.Println(rLimit)
	
	rLimit.Max = max // 1024 * 1024 * 256		// 256MB
	rLimit.Cur = cur // 1024 * 1024 * 64		//  64MB
	err = syscall.Setrlimit(syscall.RLIMIT_AS, &rLimit)
	if err != nil {
		fmt.Println("[ERROR] Failed to set resource limit : ", err)
	}
	err = syscall.Getrlimit(syscall.RLIMIT_AS, &rLimit)
	if err != nil {
		fmt.Println("[ERROR] Failed to get resource limit(2) : ", err)
	}
	fmt.Println("[INFO]  Memory usage limited to : ", rLimit)
}


func addSignalHandler(h *pcap.Pcap, host string, port int, user string, password string) {
    signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for{
			sig := <-signalChannel
			if sig == syscall.SIGUSR1 {
				fmt.Println("[INFO] MRTECollector : Received SIGUSR1 signal : Retransmit default database info")
				sendSessionDefaultDatabase(host, port, user, password)
			}else if sig ==syscall.SIGUSR2 {
				fmt.Fprintln(os.Stderr, "[INFO] MRTECollector : Received SIGUSR2 signal : Nothing to do")
			}else{
				fmt.Fprintln(os.Stderr, "[INFO] MRTECollector : Received signal : ", sig)
				h.Close()
				os.Exit(0)
			}
		}
	}()
}

func makeConnection(url string, ex_name string, routing_key string) (*amqp.Connection, error){
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}
	
// This procedure will be handled by user manually
//	channel, err := conn.Channel()
//	if err != nil {
//		return nil, err
//	}
//	
//	if ex_init { 
//		// If rabbitmq_initialize_exchange is true, then remove and re-declare exchange
//		// If you want to run multiple MRTECollector on the same Rabbit MQ, then set rabbitmq_exchange_init=false.
//		rm_err := channel.ExchangeDelete(ex_name, false/* Remove if used or not */, false/*Wait until completely removed*/)
//		if rm_err!=nil { // if ExchangeDelete return error, channel will be closed automatically, so open new channel
//			channel, err = conn.Channel()
//			if err != nil {
//				return nil, err
//			}
//		}
//		
//		err = channel.ExchangeDeclare(
//			ex_name,      // name
//			ex_type,      // type
//			false,        // durable
//			true,         // auto-deleted
//			false,        // internal
//			true,         // noWait
//			nil,          // arguments
//		)
//		if err != nil {
//			return nil, err
//		}
//	}
	
	return conn, nil
}

func sendSessionDefaultDatabase(host string, port int, user string, password string){
	// sessions array has array of "[ip:port][database]" pair 
	sessions := mrte.GetSessionDefaultDatabase(host, port, user, password)
	
	var bufferedData []byte
	bufferedCounter := 0
	for idx:=0; (idx+1)<len(sessions); idx=idx+2 {
		host_port := sessions[idx]
		init_db := sessions[idx+1]
		init_db_bytes := ([]byte)(init_db)
		
		temp := strings.Split(string(host_port), ":")
		if len(temp)!=2 || len(init_db)==0 {
			continue;
		}
		
		byteIp := net.ParseIP(temp[0]).To4()
		if byteIp==nil {
			continue /* if not IPv4 */
		}
		port, _ := strconv.ParseUint(temp[1], 10, 16)
		bytePort := mrte.ConvertUint16ToBytesLE(uint16(port))
		
		// Make Mysql protocol so that transfer it to MYSQL_INIT_DB command through MQueue
		// bufferLength := 3/*payload_len*/+1/*sequence*/+1/*command*/+len(init_db_bytes)/*db_name length*/
		mysqlPayloadLen := mrte.ConvertUint24ToBytesBE(uint32(1/*command*/+len(init_db_bytes)/*db_name length*/))
		
		mysqlHeader := []byte{0 /* Sequence==0 */, 2 /* COM_INIT_DB */}
		
		payload := append(byteIp, bytePort...)
		payload = append(payload, mysqlPayloadLen...)
		payload = append(payload, mysqlHeader...)
		payload = append(payload, init_db_bytes...)
		
		bufferedData = append(bufferedData, mrte.ConvertUint32ToBytesLE(uint32(len(payload)))...)
		bufferedData = append(bufferedData, payload...)
		bufferedCounter++
		
		if bufferedCounter>50 {
			// Flush buffer to mq publisher
			queues[0] <- &mrte.MysqlRequest{
					BufferedData: bufferedData, 
					Packets: nil,
				} 
			
			bufferedCounter = 0
			bufferedData = nil
		}
	}
	
	if bufferedCounter>0 {
		// Flush buffer to mq publisher
		queues[0] <- &mrte.MysqlRequest{
					BufferedData: bufferedData, 
					Packets: nil,
				} 
			
		bufferedCounter = 0
		bufferedData = nil
	}
}

func GetLocalIpAddress(interface_name string) (net.IP, error){
	interfaces, _ := net.Interfaces()
	for _, inter := range interfaces {
		if inter.Name == interface_name {
			addrs, err := inter.Addrs()
			if err!=nil {
 				continue
			}

			for _, addr := range addrs{
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.To4() != nil {
						return ipnet.IP, nil
					}
				}
			}
		}
	}
	
	return nil, errors.New("Could not resolve ip address (v4) for " + interface_name)
}
