# knifenet
The Swiss knife of networking
Programmed in <b>python 2.7.12</b>

The idea was to create a useful tool for basic network functions, without additional files or additional libraries to download.

# Functions
<ul>
  <li>Manual or automatic port scan</li>
  <li>Search for hosts on a network</li>
  <li>Creation and listening to backdoors</li>
  <li>admin directory searcher</li>
  <li>Extract links from a website</li>
  <li>TCP chat</li>
  <li>Traffic sniff on the local host</li>
</ul>
Soon this tool will be updated, adding new features and fixing existing ones

# Help
<code>knifenet.py --help</code>
# Use
<code>knifenet.py [topic] [host/port/interface/gateway/URL/file]</code>
Examples:
<code>knifenet.py -a -H 192.168.1.15</code>
<code>knifenet.py --backdoor -H 192.168.1.15 -p 8888</code>
<code>knifenet.py -e -t -u http://www.example.com/</code>
