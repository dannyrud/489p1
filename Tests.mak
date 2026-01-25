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

export PORT ?= 11111

SCRIPTS = ../scripts

SRCS_DIR = ./srcs
SCS = $(SRCS_DIR)/server # Student C server
SCC = $(SRCS_DIR)/client # Student C client
SPC = $(SRCS_DIR)/client-3wh.py # Student 3WH Python client

WORKSPACE_DIR = .workspace
NUM_CORRECT = 0

MAKEFLAGS += --no-print-directory

.PHONY: tests tests-3wh all-tests

tests: 
	$(eval result = $(shell make -f Tests.mak test-short-message))
	@echo "Short Message: $(result)"

	$(eval result = $(shell make -f Tests.mak test-rand-alpha-message))
	@echo "Random Alphanumeric Message: $(result)"

	$(eval result = $(shell make -f Tests.mak test-rand-binary-message))
	@echo "Random Binary Message: $(result)"
	
	$(eval result = $(shell make -f Tests.mak test-server-infinite-loop))
	@echo "Server Infinite Loop: $(result)"
	
tests-3wh: 
	$(eval result = $(shell make -f Tests.mak test-3wh-short-message))
	@echo "Short Message (3WH): $(result)"
	
	$(eval result = $(shell make -f Tests.mak test-3wh-rand-alpha-message))
	@echo "Random Alphanumeric Message (3WH): $(result)"
	
	$(eval result = $(shell make -f Tests.mak test-3wh-rand-binary-message))
	@echo "Random Binary Message (3WH): $(result)"
	
	$(eval result = $(shell make -f Tests.mak test-3wh-server-infinite-loop))
	@echo "Server Infinite Loop (3WH): $(result)"
	
all-tests: tests tests-3wh


execute:
	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"$(SCS) $(PORT) > $(WORKSPACE_DIR)/test_output.text"
	@sleep 0.2
	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"$(SCC) 10.0.0.1 $(PORT) < $(WORKSPACE_DIR)/test_message.txt > /dev/null"
	@sleep 0.2

	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"pkill -f $(SCS)"
	@sleep 0.2

execute-3wh:
	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"$(SCS) $(PORT) > $(WORKSPACE_DIR)/test_output.text"
	@sleep 0.2
	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"$(SPC) 10.0.0.1 $(PORT) < $(WORKSPACE_DIR)/test_message.txt > /dev/null"
	@sleep 0.2

	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"pkill -f $(SCS)"
	@sleep 0.2

compare:
	@if diff -q $(WORKSPACE_DIR)/test_message.txt $(WORKSPACE_DIR)/test_output.text > /dev/null; then \
		echo "PASSED!"; \
	else \
		echo "FAILED!"; \
	fi

clear:
	@rm -f $(WORKSPACE_DIR)/test_message.txt
	@rm -f $(WORKSPACE_DIR)/test_output.text


#################################################################
# Test 1: Short Message 
#################################################################

short-message:
	@mkdir -p $(WORKSPACE_DIR)
	@echo "Go Boilermakers!\n" > $(WORKSPACE_DIR)/test_message.txt
	
test-short-message: short-message execute compare clear

test-3wh-short-message: short-message execute-3wh compare clear


#################################################################
# Test 2: Random Alphanumeric Message
#################################################################

rand-alpha-message:
	@mkdir -p $(WORKSPACE_DIR)
	@head -c100000 /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' > $(WORKSPACE_DIR)/test_message.txt
	
test-rand-alpha-message: rand-alpha-message execute compare clear

test-3wh-rand-alpha-message: rand-alpha-message execute-3wh compare clear


#################################################################
# Test 3: Random Binary Message
#################################################################

rand-binary-message:
	@mkdir -p $(WORKSPACE_DIR)
	@head -c100000 /dev/urandom > $(WORKSPACE_DIR)/test_message.txt
	
test-rand-binary-message: rand-binary-message execute compare clear

test-3wh-rand-binary-message: rand-binary-message execute-3wh compare clear


###########################################################################
# Test 4: Server Inifinite Loop (multiple sequential clients to same server)
###########################################################################

server-infinite-loop:
	@mkdir -p $(WORKSPACE_DIR)
	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"$(SCS) $(PORT) > $(WORKSPACE_DIR)/test_output.text"
	@sleep 0.2

	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"echo 'Line 1' | $(SCC) 10.0.0.1 $(PORT) >/dev/null"
	@sleep 0.1
	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"echo 'Line 2' | $(SCC) 10.0.0.1 $(PORT) >/dev/null"
	@sleep 0.1
	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"echo 'Line 3' | $(SCC) 10.0.0.1 $(PORT) >/dev/null"
	@sleep 0.1

	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"pkill -f $(SCS)"
	@sleep 0.2

	@echo "Line 1\nLine 2\nLine 3" > $(WORKSPACE_DIR)/test_message.txt

test-server-infinite-loop: server-infinite-loop compare clear

server-infinite-loop-3wh:
	@mkdir -p $(WORKSPACE_DIR)
	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"$(SCS) $(PORT) > $(WORKSPACE_DIR)/test_output.text"
	@sleep 0.2

	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"echo 'Line 1' | $(SPC) 10.0.0.1 $(PORT) >/dev/null"
	@sleep 0.1
	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"echo 'Line 2' | $(SPC) 10.0.0.1 $(PORT) >/dev/null"
	@sleep 0.1
	@$(SCRIPTS)/utils/mn-stratum/exec-script h2 \
		"echo 'Line 3' | $(SPC) 10.0.0.1 $(PORT) >/dev/null"
	@sleep 0.1

	@$(SCRIPTS)/utils/mn-stratum/exec-d-script h1 \
		"pkill -f $(SCS)"
	@sleep 0.2

	@echo "Line 1\nLine 2\nLine 3" > $(WORKSPACE_DIR)/test_message.txt

test-3wh-server-infinite-loop: server-infinite-loop-3wh compare clear
