**Read Me**

This is the repo for a eBPF based packet filter tool that allows basic anaylsis and filtering of packets based on IP.
Within the repo are various tools, but the main tool is located under the master branch (not main), in xdp_prog.py. 
Based on which option is selected in xdp_prog.py, the program will load one of the c files (and XDP eBPF filter) 
onto the specified interface and perform some operation to incoming packets on that interface. 

This tool is still in development, but it is being used in research on ways to make the Linux Kernel LPM Trie more 
efficient. 
