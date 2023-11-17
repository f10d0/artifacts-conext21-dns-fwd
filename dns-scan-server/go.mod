module dns_over_tcp

go 1.21.4

require (
	github.com/gopacket/gopacket v1.1.1
	golang.org/x/net v0.18.0
)

require (
	github.com/breml/bpfutils v0.0.0-20170519214641-cfcd7145376f // indirect
	github.com/google/gopacket v1.1.19 // indirect
	golang.org/x/sys v0.14.0 // indirect
)

replace github.com/google.gopacket v1.1.19 => github.com/gopacket/gopacket v1.1.11
