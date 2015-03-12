Rabbit Message Queue Setting
============================

Visit "http://rabbit_mq_server:15672"

Exchange
--------
&lt;ul&gt;
&lt;li&gt;Name : &lt;ExchangeName&gt; (e.g. mrte) &lt;/li&gt;
&lt;li&gt;Type : &lt;direct | fanout&gt; (e.g. fanout) &lt;/li&gt;
&lt;li&gt;Durability : Transient (e.g. Transient) &lt;/li&gt;
&lt;li&gt;Auto delete : No&lt;/li&gt;
&lt;li&gt;Internal : No&lt;/li&gt;
&lt;li&gt;Alternate exchange : &lt;Empty&gt;&lt;/li&gt;
&lt;li&gt;Arguments : nowait, true, Boolean&lt;/li&gt;
&lt;/ul&gt;


Queue
-----
&lt;ul&gt;
&lt;li&gt;Name : &lt;QueueName&gt; (e.g. queue1, queue2) &lt;/li&gt;
&lt;li&gt;Durability : Transient&lt;/li&gt;
&lt;li&gt;Auto delete : No&lt;/li&gt;
&lt;li&gt;Arguments : nowait, true, Boolean&lt;/li&gt;
&lt;li&gt;나머지는 전부 &lt;Empty&gt;&lt;/li&gt;


Queue-Binding (Choose queue from QUEUE-LIST)
--------------------------------------------
&lt;ul&gt;
&lt;li&gt;From exchange : &lt;ExchangeName&gt; (e.g. mrte) &lt;/li&gt;
&lt;li&gt;Routing key : &lt;RoutingKey&gt; (e.g. "" ) &lt;/li&gt;
&lt;li&gt;Arguments : nowait, true, Boolean&lt;/li&gt;
&lt;/ul&gt;
