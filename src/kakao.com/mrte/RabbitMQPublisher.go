package mrte


import (
	"fmt"
//	"time"
//	"sync/atomic"
//	"container/list"
//	"encoding/binary"
//	"encoding/hex"
	"../../github.com/miekg/pcap"
	"../../github.com/streadway/amqp"
)

type MysqlRequest struct {
	BufferedData []byte
	Packets      []*pcap.TcpPacket
}

func PublishMessage(workerIdx int, mqConnection *amqp.Connection, exchange_name string, exchange_type string, routing_key string, queue chan *MysqlRequest, validPacketCaptured *uint64, mqErrorCounter *uint64) (){
	channel := getChannel(mqConnection)
	
	for{
		req := <-queue // read from a channel
		req.publish(channel, exchange_name, routing_key, validPacketCaptured, mqErrorCounter)
	}
}

func (req *MysqlRequest) publish(channel *amqp.Channel, exchange_name string, routing_key string, validPacketCaptured *uint64, mqErrorCounter *uint64) {
	var mysqlPayload []byte
	var bufferedMQData []byte
	
	if req.Packets!=nil && len(req.Packets)>0 {
		for idx:=0; idx<len(req.Packets); idx++ {
			pkt := req.Packets[idx]
			pkt.Parse()
			if pkt.IsValidTcpPacket && pkt.Payload!=nil && len(pkt.Payload)>0 {
				*validPacketCaptured = (*validPacketCaptured) + 1
				
				mysqlPayload = nil
				mysqlPayload = append(mysqlPayload, pkt.SrcIp...)
				mysqlPayload = append(mysqlPayload, ConvertUint16ToBytesLE(pkt.TcpSrcPort)...)
				mysqlPayload = append(mysqlPayload, pkt.Payload...)
				
				bufferedMQData = append(bufferedMQData, ConvertUint32ToBytesLE(uint32(len(mysqlPayload)))...)
				bufferedMQData = append(bufferedMQData, mysqlPayload...)
			}
		}
	}else{
		bufferedMQData = req.BufferedData
	}
	
	if bufferedMQData==nil || len(bufferedMQData)<=0 {
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