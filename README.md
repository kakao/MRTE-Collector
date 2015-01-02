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
