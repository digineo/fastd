package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/digineo/fastd/fastd"
)

type config struct {
	RemoteAddr string `json:"remote_addr"`
	RemoteKey  string `json:"remote_key"`
	Secret     string `json:"secret"`
	MTU        int    `json:"mtu"`

	ConnTimeout string `json:"connect_timeout"`
	timeout     time.Duration
}

func readConfig(fname string) (*config, error) {
	f, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *config) Validate() error {
	if c.RemoteAddr == "" {
		return fmt.Errorf("config.remote_addr is empty")
	}
	if c.RemoteKey == "" {
		return fmt.Errorf("config.remote_key is empty")
	}
	if c.Secret == "" {
		return fmt.Errorf("config.secret is empty")
	}
	if c.ConnTimeout == "" {
		c.timeout = 5 * time.Second
	} else {
		var e error
		if c.timeout, e = time.ParseDuration(c.ConnTimeout); e != nil {
			return fmt.Errorf("config.connection_timeout is invalid: %v", e)
		}
	}
	if c.MTU <= fastd.MinMTU || c.MTU > 1500 {
		return fmt.Errorf("config.mtu must be in (%d..1500), got %d", fastd.MinMTU, c.MTU)
	}
	return nil
}
