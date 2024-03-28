module github.com/abakum/sites

go 1.21.4

require (
	github.com/xlab/closer v1.1.0
	golang.org/x/sys v0.10.0
)

require github.com/Trisia/gosysproxy v1.0.0

require github.com/abakum/embed-encrypt v0.0.0-20240326205818-6f9fdc0c51b7 // indirect

replace github.com/abakum/embed-encrypt => ../embed-encrypt