JARS=$(shell ls jars/*.jar)
JCP=$(shell ls jars/*.jar | tr '\n' :)

## Sorry, the following is hard-coded for the PAM module; if it breaks, the session server will work, just not use PAM
JAVA_HOME:=$(shell ./jhome)
JCPPFLAGS=-I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(JAVA_HOME)/../include -I$(JAVA_HOME)/../include/linux
JLIBS=-L$(JAVA_HOME)/jre/lib/amd64/server -L$(JAVA_HOME)/lib/amd64/server -ljvm
CFLAGS=-g -fPIC -O2

SessionKeyServer.jar: build/com/att/research/RCloud/SessionKeyServer.class
	(cd build && for jar in $(JARS); do jar fx ../$$jar; done)
	rm -rf build/META-INF
	(cd build && jar fc ../$@ *)

build/com/att/research/RCloud/SessionKeyServer.class: SessionKeyServer.java PAM.java
	@-rm -rf build; mkdir build
	javac $(JFLAGS) -d build -cp $(JCP) SessionKeyServer.java PAM.java

libPAM.so: pam.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JCPPFLAGS) -shared -o $@ pam.c -lpam $(LIBS) $(JLIBS)

pam: libPAM.so

run: SessionKeyServer.jar
	java -cp SessionKeyServer.jar com.att.research.RCloud.SessionKeyServer

clean:
	rm -rf build *~ libPAM.so SessionKeyServer.jar

.PHONY: pam
