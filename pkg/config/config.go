/*
Copyright © 2021 Red Hat, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"log"
	"net/url"
	"os"

	"github.com/spf13/viper"
)

// Package config loads configuration details so they can be accessed
// by other packages

var Appname = "compliance-audit-router"
var defaultMessageTemplate = "{{.Username}} and {{.Manager}}\n\n" +
	"This action requires justification." +
	"Please provide the justification in the comments section below."

var AppConfig Config

type Config struct {
	Verbose         bool
	ListenPort      int
	MessageTemplate string

	LDAPConfig   LDAPConfig
	SplunkConfig SplunkConfig
	JiraConfig   JiraConfig
}

type LDAPConfig struct {
	Host               string
	InsecureSkipVerify bool
	Username           string
	Password           string
	SearchBase         string
	Scope              string
	Attributes         []string
}

type SplunkConfig struct {
	Host          string
	Token         string
	AllowInsecure bool
}

type JiraConfig struct {
	Host          string
	AllowInsecure bool
	Token         string
	Query         string
}

func init() {

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	viper.AddConfigPath(home + "/.config/" + Appname) // Look for config in $HOME/.config/compliance-audit-router
	viper.SetConfigType("yaml")
	viper.SetConfigName(Appname)

	viper.SetEnvPrefix("CAR")
	viper.AutomaticEnv() // read in environment variables that match

	err = viper.ReadInConfig() // Find and read the config file
	if err != nil {            // Handle errors reading the config file
		panic(err)
	}

	log.Printf("Using config file: %s", viper.ConfigFileUsed())

	viper.SetDefault("MessageTemplate", defaultMessageTemplate)
	viper.SetDefault("Verbose", true)
	viper.SetDefault("ListenPort", 8080)

	err = viper.Unmarshal(&AppConfig)
	if err != nil {
		panic(err)
	}

	for _, x := range []*string{
		&AppConfig.LDAPConfig.Host,
		&AppConfig.JiraConfig.Host,
		&AppConfig.SplunkConfig.Host,
		&AppConfig.SplunkConfig.Token,
	} {
		_, err := url.Parse(*x)
		if err != nil {
			panic(err)
		}

	}
}
