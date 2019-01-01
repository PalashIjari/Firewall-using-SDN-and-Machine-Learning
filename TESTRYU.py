from ryurest import RyuSwitch
import KNN as CHECK
import datetime
import threading
import unicodedata


def checking():

	DT = datetime.datetime.now() # extracting the date time of the system
        f=open("malware.txt","r")
        add=f.readline()
        f.close()
        address=add.rstrip()
        testIP=unicode(address)  #converting the IP address to unique 32 bit integer


	Malware=CHECK.CheckIP(testIP)
	#print(Malware)  Check whether the IP is malicious
      
	switch1= RyuSwitch()
	#print("Succesful")   

     

	DPID_list =  switch1.get_switches() #getting all the switches connected
    
	switch1.DPID=DPID_list[1]

	flows=switch1.get_flows()

	#print (DPID_list[1])

	duration= flows[str(switch1.DPID)][0]['duration_sec']
	table_id=flows[str(switch1.DPID)][0]['table_id']
	#print("\n Specific Value for FLOW in DUMP TABLE:table_id")
	#print(table_id)
    # the Below flow rule is an experimentation and is not used further
	flow_rule={
	"dpid":switch1.DPID,
	"idle_timeout":30,"hard_timeout":30,"priority": 65000,
	"table_id":2,"match":{"in_port ":1,},
	"actions":[]


	}

	#print("here")
	
	if (Malware==2):
		switch1.DPID=DPID_list[0]
		Malware= -1
		#The flow below is used to block the IP address if it turns to be malicious
        ##########################################################
	flow_rule1={

	"dpid":switch1.DPID,
	"cookie":42,
	"priority":45000,

	"match":{

	"nw_src":address,   #change the IP address here
	"dl_type":2048
	},
	"actions":
	[]


	}
        ##########################################################

	#print("the time is")
	#print(DT.second)
 
    # You can adjust the timing restrcitions here and then add the flow to any switch you like
	if(DT.second >= 30 and Malware==-1 ):
		print("THE FIREWALL IS ACTIVE")
 		switch1.add_flow(flow_rule1)


    if(DT.second<30):
		print("THE FIREWALL IS INACTIVE")
		switch1.delete_flow(flow_rule1)

	flows=switch1.get_flows()
	#print(flows)

	#print("Enteries After deleting")
	del_rule={

	"match":{"in_port":1}

	}





	#switch1.delete_flow(flow_rule1)

	#print(switch1.get_flows())


	threading.Timer(5,checking).start()#code to run the program continuosly




checking()
