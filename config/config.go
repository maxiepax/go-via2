package config

import (
	"flag"

	"github.com/koding/multiconfig"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Debug   		bool
	Port    		int 	`default:"8443"`
	File    		string
	Network 		Network
	DisableDhcp 	bool
}

type Network struct {
	Interfaces []string
}

var conf *Config

func Get() *Config {
	return conf
}

func Set(c *Config) {
	conf = c
}

func Load() *Config {
	d := multiconfig.New()

	c := new(Config)

	err := d.Load(c)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"err": err,
		}).Fatalf("failed to load config")
	}

	if c.File != "" {
		d = multiconfig.NewWithPath(c.File)

		err = d.Load(c)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"err": err,
			}).Fatalf("failed to load config")
		}
	}

	err = d.Validate(c)
	if err != nil {
		flag.Usage()
		logrus.WithFields(logrus.Fields{
			"err": err,
		}).Fatalf("failed to load config")
	}

	conf = c

	return c
}