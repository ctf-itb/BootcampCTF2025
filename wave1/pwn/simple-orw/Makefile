FLAG := $(shell cat src/flag.txt)
OUTPUT := dist/dist.zip

.PHONY: all
all: src/chall $(OUTPUT) challenge.yml

src/chall: src/chall.c
	cd src
	gcc -Wl,-z,relro,-z,now -pie -fstack-protector -o chall chall.c

$(OUTPUT): src/chall src/chall.c src/Dockerfile src/docker-compose.yml
	cd src
	zip dist.zip chall chall.c Dockerfile docker-compose.yml
	cd ..
	mkdir -p $(shell dirname "$(OUTPUT)")
	mv src/dist.zip $(OUTPUT)

define CHALLENGE
name: "simple orw"
category: binary exploitation
description: |-
    Seriously, what harm could this little ORW program possibly cause?
    
    Author: **msfir**
value: 1000
type: dynamic
extra:
    initial: 1000
    decay: 30
    minimum: 100
connection_info: nc 163.47.10.146 8910
flags:
    - $(FLAG)
files:
    - $(OUTPUT)
state: hidden
version: "0.1"
endef

export CHALLENGE

.ONESHELL:
challenge.yml: src/flag.txt
	echo "$$CHALLENGE" > challenge.yml

.PHONY: clean
clean:
	rm -rf $(OUTPUT) src/chall challenge.yml

.PHONY: rebuild
rebuild: clean all
