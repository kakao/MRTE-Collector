Rabbit Message Queue Setting
============================

Visit "http://rabbit_mq_server:15672"

Exchange
--------
<ul>
<li>Name : &lt;ExchangeName&gt;</li>
<li>Type : &lt;direct | fanout&gt;</li>
<li>Durability : Transient</li>
<li>Auto delete : No</li>
<li>Internal : No</li>
<li>Alternate exchange : &lt;Empty&gt;</li>
<li>Arguments : nowait, true, Boolean</li>
</ul>


Queue
-----
<ul>
<li>Name : &lt;QueueName&gt;</li>
<li>Durability : Transient</li>
<li>Auto delete : No</li>
<li>Arguments : nowait, true, Boolean</li>
<li>나머지는 전부 &lt;Empty&gt;</li>


Queue-Binding (Choose queue from QUEUE-LIST)
--------------------------------------------
<ul>
<li>From exchange : &lt;ExchangeName&gt;</li>
<li>Routing key : &lt;RoutingKey&gt;</li>
<li>Arguments : nowait, true, Boolean</li>
</ul>
