generatenative:
	go build -buildmode=c-shared -o /amex/hiped/go/lib-fpe.so

test:
	go test -v github.com/cloudtrust/fpe/ff1

benchmark:
	go test -v -bench=. -run=NONE github.com/cloudtrust/fpe/ff1
