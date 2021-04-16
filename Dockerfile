FROM ubuntu

RUN apt update && apt install -y wget gcc make && wget https://golang.org/dl/go1.16.3.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.3.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /root/go/src/github.com/cloudtrust/fpe
COPY . .
RUN make generatenative

