package main

import (
	"educationHTTP-restAPI/internal/app/apiserver"
	"flag"
	"github.com/BurntSushi/toml"
	"log"
	"time"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath, "config-path", "configs/apiserver.toml", "path to config file")
}

func main() {
	flag.Parse()

	config := apiserver.NewConfig()
	_, err := toml.DecodeFile(configPath, config)
	if err != nil {
		log.Fatal(err)
	}

	s, err := apiserver.Start(config)
	if err != nil {
		log.Fatal(err)
	}

	stopChan := make(chan struct{})
	go s.StartRefreshTokenCleanup(24*time.Hour, stopChan)
}
