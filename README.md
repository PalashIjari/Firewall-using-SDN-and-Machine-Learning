# Firewall-using-SDN-and-Machine-Learning
Intelligent Time Based Firewall
The problem statement being to Block the malicious IP addresses from a secured  network based on similarity of the IP’s from the previous data  and also to reroute the packets through a different path if the IP’s  found to be are a potential threat in the future. I used Mininet to create a topology of 2 companies and a service provider and later Used Ryu as a Controller to write Flows in the SDN controller which used Openflow as a protocol. My system checks each incoming IP’s , converts them into a unique 32bit integer using the python IP library, compares them with the dataset of malicious IP’s addresses using K-Nearest Neighbor Algorithm and predicts whether the IP address are a Potential Threat. Based on whether the IP’s are a Threat , the system initializes commands to act as a Firewall and the whole system can be automated using Time. 



