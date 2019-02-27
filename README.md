# knifenet
The Swiss knife of networking<br>
<i>Programmed in <b>python 2.7.12</b></i>

The idea was to create a useful tool for basic network functions, without additional files or additional libraries to download.

# Functions
<ul>
  <li>Manual or automatic port scan</li>
  <li>Search for hosts on a network</li>
  <li>Creation and listening to backdoors</li>
  <li>Admin directory searcher</li>
  <li>Extract links from a website</li>
  <li>TCP chat</li>
  <li>Traffic sniff on the local host</li>
</ul>
Soon this tool will be updated, adding new features and fixing existing ones

# Help
<code>knifenet.py --help</code>
# Use
<code>knifenet.py [topic] [host/port/interface/gateway/URL/file]</code><br><br>
Examples:<br>
<code>knifenet.py -a -H 192.168.1.15</code><br>
<code>knifenet.py --backdoor -H 192.168.1.15 -p 8888</code><br>
<code>knifenet.py -e -t -u http://www.example.com/</code>
