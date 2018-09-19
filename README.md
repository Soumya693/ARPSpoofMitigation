Pre-requisites:
1. mininet 
2. dsniff
3. ryu

------------Ryu installation----------------------------
pip install ryu
 or 
% git clone git://github.com/osrg/ryu.git
% cd ryu; pip install . 

------------To install dsniff in linux--------------------------
 "sudo apt-get install dsniff"


-----mininet installations and Topology creation----------------
Open a linux terminal.

install mininet:
"sudo apt-get install mininet"

----------------To run the arpspoof module----------------
Start the ryu controller module with this command: 
" ryu-manager arpspoofing.py

----------------Create a topology-----------------------------
Run the following commands:

" sudo mn --topo single,3 --mac --controller remote --switch ovsk,protocols=OpenFlow13"
"h1 ping h2"
"xterm h1 h2 h3"



Run the commands in Xterm console:
 for Node h1 and h2: arp -a   # to check the arp cache
-------------Launching attack using dsniff arpspoof command---------
Run the command in Node h3 console:
sudo arpspoof -i <h3 interface> -t <IP of h1> -r <IPof h2>

----------to verify the arp cache of node h1 and h2----------
Node h1 and h2: arp -a




