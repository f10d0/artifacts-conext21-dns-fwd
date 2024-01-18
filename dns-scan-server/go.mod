module dns_over_tcp

go 1.21.4

require github.com/google/gopacket v1.1.19

replace github.com/google.gopacket => github.com/gopacket/gopacket v1.2.0

require (
	github.com/breml/bpfutils v0.0.0-20170519214641-cfcd7145376f
	github.com/ilyakaznacheev/cleanenv v1.5.0
	golang.org/x/net v0.18.0
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	golang.org/x/sys v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
)
