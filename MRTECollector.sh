#!/bin/bash

./MRTECollector \
  --direction="in" \
  --interface="eth0" \
  --port=3306 \
  --snapshot_len=8192 \
  --read_timeout=100 \
  --queue_size=100 \
  --thread_count=5 \
  --max_mem_mb=64 \
  --rabbitmq_host="127.0.0.1" \
  --rabbitmq_port=5672 \
  --rabbitmq_user="guest" \
  --rabbitmq_password="" \
  --rabbitmq_exchange_name="mrte" \
  --rabbitmq_routing_key="" \
  --mysql_host="127.0.0.1" \
  --mysql_user="mrte" \
  --mysql_password=""
