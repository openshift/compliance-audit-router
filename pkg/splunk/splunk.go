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

package splunk

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/openshift/compliance-audit-router/pkg/config"
	"github.com/openshift/compliance-audit-router/pkg/helpers"
)

// Webhook is the JSON structure for a Splunk webhook
type Webhook struct {
	Sid         string       `json:"sid"`
	SearchName  string       `json:"search_name"`
	App         string       `json:"app"`
	Owner       string       `json:"owner"`
	ResultsLink string       `json:"results_link"`
	Result      SearchResult `json:"result"`
}

// Alert describes a Splunk alert
type Alert struct {
	SearchID      string
	SearchResults SearchResults
}

// searchResult represents an actual SPLUNK search result
type SearchResult struct {
	Index      string `json:"index"`
	Source     string `json:"source"`
	SourceType string `json:"sourcetype"`
	User       string `json:"user"`
	Action     string `json:"action"`
	Raw        string `json:"_raw"`
}

// searchResults represents the results of a Splunk API */results call
type SearchResults struct {
	InitOffset  int                 `json:"init_offset"`
	Messages    []map[string]string `json:"messages"`
	Preview     bool                `json:"preview"`
	Results     []SearchResult      `json:"results"`
	Highlighted map[string]string   `json:"highlighted"`
	//Fields    []map[string]string `json:"fields"`
}

// NOTE: The webhook itself contains the search result. So this may not be necessary

// RetrieveSearchFromAlert parses the received webhook, and looks up the data for the alert in Splunk,
// and returns the information in an Alert struct
func RetrieveSearchFromAlert(sid string) (Alert, error) {
	var alert = Alert{}
	var searchResults = SearchResults{}

	alert.SearchID = sid

	transport := &http.Transport{}
	// Allow insecure connections for development
	if config.AppConfig.SplunkConfig.AllowInsecure {
		log.Printf("Allowing insecure connections to Splunk")
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	// Create a new HTTP client; don't modify the default client
	splunkHttpClient := &http.Client{Transport: transport}
	req, err := http.NewRequest(
		http.MethodGet,
		getSplunkURL(config.AppConfig.SplunkConfig.Host, sid),
		http.NoBody,
	)
	if err != nil {
		return alert, err
	}

	bearerToken := "Bearer" + config.AppConfig.SplunkConfig.Token
	req.Header.Add("Authorization", bearerToken)

	resp, err := splunkHttpClient.Do(req)
	if err != nil {
		return alert, err
	}

	// Process the response
	err = helpers.DecodeJSONResponseBody(resp, &searchResults)
	if err != nil {
		return alert, err
	}

	alert.SearchResults = searchResults

	log.Printf("Received alert from Splunk: %s", alert.SearchID)
	for _, result := range alert.SearchResults.Results {
		log.Println(result.Raw)
	}

	// TODO: Can we make the un-marshalling of the XML response agnostic to any specific service?  Interfaces?
	//var search Results

	os.Exit(1)
	return alert, err
}

// getSplunkURL returns the URL for a Splunk search by sid
func getSplunkURL(host, sid string) string {
	return fmt.Sprintf(
		"%s/services/search/jobs/%s/results?output_mode=json&count=0", host, sid,
	)
}
