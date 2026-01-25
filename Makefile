############################################################################
##
##     This file is part of the University of Michigan (U-M) EECS 489.
##
##     U-M EECS 489 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     U-M EECS 489 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with U-M EECS 489. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

default: client-server

####################################################################
############### Set up Mininet and Controller ######################
####################################################################

SCRIPTS = ../scripts

export MN_STRATUM_IMG = opennetworking/mn-stratum:latest
export ONOS_IMAGE = onosproject/onos:latest

export name ?=

MAKEFLAGS += --no-print-directory

.PHONY: mininet controller cli netcfg host tests

help: 
	@echo "Example usage:"
	@echo "  sudo make mininet           Start Mininet"
	@echo "  sudo make mininet-prereqs   Install Mininet Prereqs/Dependencies"
	@echo "  sudo make controller        Start ONOS Controller"
	@echo "  sudo make cli               Access Controller CLI (password: rocks)"
	@echo "  sudo make netcfg            Connect Controller to Mininet"
	@echo "  sudo make host name=h1      Access Mininet Host"
	@echo "  sudo make client-server     Compile Server/Client Binaries"
	@echo "  sudo make tests             Run Tests"
	@echo "  sudo make clean             Clean All"

mininet:
	$(SCRIPTS)/mn-stratum --topo linear,2

mininet-prereqs:
	docker exec -it mn-stratum bash -c \
		"sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list ; \
		 sed -i '$d' /etc/apt/sources.list ; \
		 chmod 1777 /tmp ; \
		 apt-get update ; \
		 apt-get -y --allow-unauthenticated install iptables python-scapy"

	$(SCRIPTS)/utils/mn-stratum/exec-script h1 \
		"iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
	$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"

controller:
	ONOS_APPS=gui,proxyarp,drivers.bmv2,lldpprovider,hostprovider,fwd \
	$(SCRIPTS)/onos

cli:
	$(SCRIPTS)/onos-cli

netcfg:
	$(SCRIPTS)/onos-netcfg cfg/netcfg.json

# Usage: make host name=h1
host:
	$(SCRIPTS)/utils/mn-stratum/exec $(name)


####################################################################
###################### Compile C programs ##########################
####################################################################

GCC = gcc:4.9
SRCS = srcs

client-server: client server

client:
	docker run --rm -v ./:/workdir -w /workdir $(GCC) \
		gcc -o $(SRCS)/client $(SRCS)/client.c

server:
	docker run --rm -v ./:/workdir -w /workdir $(GCC) \
		gcc -o $(SRCS)/server $(SRCS)/server.c

####################################################################
###3###################### Run tests ###############################
####################################################################

tests:
	make -f Tests.mak all-tests


clean:
	rm -f $(SRCS)/server $(SRCS)/client
	rm -rf .workspace
