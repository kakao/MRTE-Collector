Packet capture functionality of MRTECollector is come from miekg/pcap library (https://github.com/miekg/pcap/).

For fast processing and limited resource usage,
I need to change and skip some processing of miekg's original packet parsing.
So you can not simply replace miekg's original source code to MRTECollector.

And only necessary source files are included here.
You can find original version ~/MRTECollector/ref/pcap or https://github.com/miekg/pcap


--To Miek-------------------------------------------------------------------------------
Hi Miek.

Really thanks for your miekg/pcap library.
I need your library but I want make my own packet parser (Actually more minimalized parser).
But your library not support this. So I changed pcap library for my own purpose.

What I am asking is that do your have any license for your miekg/pcap library and 
could I chnage your pcap library(also source code file name) and open it on github ?

I am going to your name and github path of miekg/pcap library for original source code developer.

Regards,
Matt.

--From Miek-----------------------------------------------------------------------------
You could just fork it, but I'll *need* to leave to original LICENSE file in
there.

----------------------------------------------------------------------------------------