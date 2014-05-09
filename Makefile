TOP_DIR = ../..
include $(TOP_DIR)/tools/Makefile.common

TARGET ?= /kb/deployment
DEPLOY_RUNTIME ?= /kb/runtime

all: bin 

bin: $(BIN_DIR)/kb-login $(BIN_DIR)/kb-logout

JSON = deps/json-parser
BSTRLIB = deps/bstrlib
INIPARSER = deps/iniparser

INCS = -I$(JSON) -I$(BSTRLIB) -I$(INIPARSER)/src

CFLAGS = -g -Wall $(DEFS) $(INCS)

LIBS = -lcurl  -lm

OBJS = 	src/kb-common.o \
	$(INIPARSER)/src/iniparser.o \
	$(INIPARSER)/src/dictionary.o \
	$(JSON)/json.o \
	$(BSTRLIB)/bstrlib.o \
	$(BSTRLIB)/bstraux.o

$(BIN_DIR)/kb-login: src/kb-login.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BIN_DIR)/kb-logout: src/kb-logout.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

deploy: 
deploy-all: 
deploy-client: 

deploy-docs:

deploy-dir:
	if [ ! -d $(SERVICE_DIR) ] ; then mkdir $(SERVICE_DIR) ; fi
	if [ ! -d $(SERVICE_DIR)/webroot ] ; then mkdir $(SERVICE_DIR)/webroot ; fi
	if [ ! -d $(SERVICE_DIR)/bin ] ; then mkdir $(SERVICE_DIR)/bin ; fi


include $(TOP_DIR)/tools/Makefile.common.rules
