DIRS=$(shell go list -f {{.Dir}} ./...)

.PHONY: build

all: clean depend lint build

clean:
	rm enroll-mac
	rm enroll-linux

depend:
	@go get ./...

lint:
	@for d in $(DIRS) ; do \
		if [ "`goimports -l $$d/*.go | tee /dev/stderr`" ]; then \
			echo "^ - Repo contains improperly formatted go files" && echo && exit 1; \
		fi \
	done
	@if [ "`golint ./... | tee /dev/stderr`" ]; then \
		echo "^ - Lint errors!" && echo && exit 1; \
	fi


build:
	go build -o enroll-mac

deploy:
	GOOS=linux GOARCH=amd64 go build -o enroll-linux
	scp ./enroll-linux root@gophertrain.com:~/enroll

