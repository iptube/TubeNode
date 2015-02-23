# TubeNode
Netfilter bits to play with SPUD

./configure and make sould do the trick

First set up your PI as a Masquerading NAT router

Then insert the rules like this:
sudo iptables-restore < iptables.rules 

and then run:
src/tubenode

All SPUD packets should be sent to the tubenode process