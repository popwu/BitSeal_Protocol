module gocode

go 1.22

toolchain go1.24.4

require github.com/bitcoin-sv/go-sdk v0.0.0

require golang.org/x/crypto v0.31.0 // indirect

// 使用本地路径替代远程依赖，避免下载
replace github.com/bitcoin-sv/go-sdk => ./go-sdk
