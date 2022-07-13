
PCAP_DIR 	= 	pcap
LOG_DIR 	= 	log
P4SRC_DIR	=	p4src	 

ifndef P4SRC_FILE
P4SRC_FILE = p4src/int_md.p4
endif

all: run

# start network
run:
	sudo python3 network.py --p4 ${P4SRC_FILE}

stop:
	sudo mn -c

clean: stop
	rm -f *.pcap
	rm -rf $(PCAP_DIR) $(LOG_DIR) $(RULE_DIR)/rule*
