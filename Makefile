CONTAINER=go_fpe
generatenative:
	go build -buildmode=c-shared -o /amex/hiped/go/lib-fpe.so

generatelinux:
	docker build . -t ${CONTAINER}
	docker run -it --rm --name ${CONTAINER} ${CONTAINER}

linuxextract:
	docker cp ${CONTAINER}:/amex/hiped/go bin/

test:
	go test -v github.com/cloudtrust/fpe/ff1

benchmark:
	go test -v -bench=. -run=NONE github.com/cloudtrust/fpe/ff1
