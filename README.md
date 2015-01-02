MRTE-Collector
==============

MRTE(MySQL Realtime Traffic Emulator) Collector

Architecture
------------
https://github.com/kakao/MRTE-Player/blob/master/doc/mrte.png

How to build
------------
1. Install go package (at least 1.3)
2. Build MRTECollector
  <pre>
   $cd ~MRTECollector/src
   $go build MRTECollector.go
  </pre>

How to run
----------
<pre>
./MRTECollector \
  --interface="eth0" \
  --port=3306 \
  --snapshot_len=8192 \
  --read_timeout=100 \
  --queue_size=100 \
  --thread_count=5 \
  --rabbitmq_host="127.0.0.1" \
  --rabbitmq_port=5672 \
  --rabbitmq_user="guest" \
  --rabbitmq_password="" \
  --mysql_host="127.0.0.1" \
  --mysql_user="mrte" \
  --mysql_password=""
</pre>


Understanding how to work
-------------------------
After starting MRTECollector with MRTECollector.sh, 
MRTECollector will print packet capture's filtering option (Actually this is static built option, so you can't change this).
And MRTECollector is initializing packet capture library(pcap library) and Rabbit MQ connection. 

If there's no problem, packet capturing is started right away.
And MRTECollector will connect to source MySQL server and collecting each connections' default database information and put this information to Rabbit MQ.
"Send init database information of all session(1)" and "(2)" message means doing this task. (reference "Understanding output" section)

MRTECollector will capture every income packet of specific tcp port of specific network interface (MRTECollector is not interested in out-bound packet of MySQL server).
And MRTECollector will strip tcp/ip header and get the source ip and port and packet payload.
After that MRTECollector just put three information to Rabbit MQ. That's all.


Understanding output
--------------------
MRTECollector will print internal processing status every 10 seconds.

<pre>
$ MRTECollector.sh
[INFO]  MRTECollector : Setting capture filter to ' tcp dst port 3306 '
[INFO]  Send init database information of all session (1). Wait ...
[INFO]  Send init database information of all session (2). Done

DateTime                TotalPacket     ValidPacket    PacketDropped    PacketIfDropped      WaitingQueueCnt         MQError
2015-01-02 21:13:06           40005           34154                0                  0                    0               0
2015-01-02 21:13:16           39941           34075                0                  0                    0               0
2015-01-02 21:13:26           39968           34121                0                  0                    0               0
2015-01-02 21:13:36           40009           34164                0                  0                    1               0
2015-01-02 21:13:46           39966           34145                0                  0                    0               0
2015-01-02 21:13:56           39976           34139                0                  0                    0               0
2015-01-02 21:14:06           39953           34146                0                  0                    0               0
2015-01-02 21:14:16           39943           34179                0                  0                    0               0
...
</pre>
<br>
<ul>
<li>TotalPacket 	: Total count of packet captured by pcap library 
<li>ValidPacket		: Valid packet means just simple tcp/ip packet which has user data(e.g. tcp/ip packet which have only ACK is not valid packet in MRTECollector)
<li>PacketDropped	: Packet dropped because of MRTECollector's abnormally
<li>PacketIfDropped	: Packet dropped by network interface
<li>WaitingQueueCnt	: Captured packet is sent to Rabbit MQ by multi-threaded publisher. And each publisher thread have their own internal queue. WaitingQueueCnt means these internal queue's pending item count.
<li>MQError			: Publishing to Rabbit MQ error count
</ul>


Limitations
-----------
<ol>
<li>MRTECollector can't capture server-side prepared statements.<br>
   A lot of people think they use real prepared statement in their MySQL server configurations.<br>
   But real server side prepared statements are used only if you set serverPreps option on your jdbc connection url.<br>
   If not, now you are using client side prepare statement (it's just a emulation of prepared statement).<br>
<li>MRTECollector have to be run on source MySQL server. <br>
   PCap library can't capture the packet of physical server outside.<br>
</ol>