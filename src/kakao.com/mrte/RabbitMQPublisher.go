package mrte


import (
	"fmt"
	"net"
	"hash/adler32"
//	"time"
//	"sync/atomic"
//	"container/list"
//	"encoding/binary"
//	"encoding/hex"
	"../../github.com/miekg/pcap"
	"../../github.com/streadway/amqp"
)

const (
	CHECKSUM_LENGTH = 22 /*IP(4) + PORT(2) + MYSQL_HEADER(5) + a */
)

type MysqlRequest struct {
	BufferedData []byte
	Packets      []*pcap.TcpPacket
}

func PublishMessage(workerIdx int, mqConnection *amqp.Connection, exchange_name string, routing_key string, localIpAddress net.IP, queue chan *MysqlRequest, validPacketCaptured *uint64, mqErrorCounter *uint64) (){
	channel := getChannel(mqConnection)
	ipAddress := localIpAddress.To4()
	for{
		req := <-queue // read from a channel
		req.publish(channel, exchange_name, routing_key, ipAddress, validPacketCaptured, mqErrorCounter)
	}
}

/**
 * Rabbit MQ message structure
 *
 * 4-bytes     [4-bytes       4-bytes            2-bytes             variable-length     4-bytes ]...           
 * LOCAL_IP    [UNIT_LENGTH   PACKET_SOURCE_IP   PACKET_SOURCE_PORT  PACKET_DATA         CHECKSUM]...
 */
func (req *MysqlRequest) publish(channel *amqp.Channel, exchange_name string, routing_key string, ipAddress []byte, validPacketCaptured *uint64, mqErrorCounter *uint64) {
	var mysqlPayload []byte
	var bufferedMQData []byte
	
	if req.Packets!=nil && len(req.Packets)>0 {
		bufferedMQData = append(bufferedMQData, ipAddress...)
		for idx:=0; idx<len(req.Packets); idx++ {
			pkt := req.Packets[idx]
			pkt.Parse()
			if pkt.IsValidTcpPacket && pkt.Payload!=nil && len(pkt.Payload)>0 {
				// Packet payload size could be just 1 byte during TCP stream converted to IP datagram
				//   -- old code -- if pkt.Payload!=nil && len(pkt.Payload)>=5/* 3(len) + 1(sequence) + 1(command) */ {
				// So we have to send all captured packet to MRTE-Player
				*validPacketCaptured = (*validPacketCaptured) + 1
			
				mysqlPayload = nil
				mysqlPayload = append(mysqlPayload, pkt.SrcIp...)
				mysqlPayload = append(mysqlPayload, ConvertUint16ToBytesLE(pkt.TcpSrcPort)...)
				mysqlPayload = append(mysqlPayload, pkt.Payload...)
				
				// Add checksum
				checksum_len := len(mysqlPayload)
				if checksum_len > CHECKSUM_LENGTH {
					checksum_len = CHECKSUM_LENGTH
				}
				checksum := adler32.Checksum(mysqlPayload[0:checksum_len])
				mysqlPayload = append(mysqlPayload, ConvertUint32ToBytesLE(checksum)...)
			
				bufferedMQData = append(bufferedMQData, ConvertUint32ToBytesLE(uint32(len(mysqlPayload)))...)
				bufferedMQData = append(bufferedMQData, mysqlPayload...)
			}
		}
	}else{
		bufferedMQData = append(ipAddress, req.BufferedData...)
	}
	
	if bufferedMQData==nil || len(bufferedMQData)<=4 /* skip when only contains local host ip address */ {
		return
	}
	
	// fmt.Println(hex.Dump(msgBuffer))
	if err := channel.Publish(
		exchange_name,   // publish to an exchange
		routing_key, // routing to 0 or more queues
		false,      // mandatory
		false,      // immediate
		amqp.Publishing{
			Headers:         amqp.Table{},
			ContentType:     "text/plain",
			ContentEncoding: "",
			Body:            bufferedMQData,
			DeliveryMode:    amqp.Transient, // 1=non-persistent, 2=persistent
			Priority:        0,              // 0-9
		},
	); err != nil {
		*mqErrorCounter = (*mqErrorCounter) + 1
		fmt.Println("[ERROR] Failed to publish message to queue : %s", err)
	}
}


func getChannel(connection *amqp.Connection) (channel *amqp.Channel){
	channel, err := connection.Channel()
	if err!=nil {
		fmt.Println("[ERROR] Failed to get channel from mq connection")
		panic(err)
	}
	
	return channel
}