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

package listeners

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/openshift/compliance-audit-router/pkg/config"
	"github.com/openshift/compliance-audit-router/pkg/helpers"
	"github.com/openshift/compliance-audit-router/pkg/jira"
	"github.com/openshift/compliance-audit-router/pkg/ldap"
	"github.com/openshift/compliance-audit-router/pkg/metrics"
	"github.com/openshift/compliance-audit-router/pkg/splunk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// genericErrorMsg is a text string returned to the client
// when an error occurs that we don't want to accidentally expose
// data from. All error messages should be logged to the application log.
const genericErrorMsg = "The request could not be completed. Please contact the system administrator."

type Listener struct {
	Path        string
	Methods     []string
	HandlerFunc http.HandlerFunc
}

type processInfo struct {
	uuid    string
	process string
}

func (p processInfo) LabelInput() map[string]string {
	return map[string]string{"uuid": p.uuid, "process": p.process}
}

type statusInfo struct {
	code int
	msg  []string
}

var (
	status500 = statusInfo{code: http.StatusInternalServerError}
	status200 = statusInfo{code: http.StatusOK}
)

var Listeners = []Listener{
	{
		Path:        "/readyz",
		Methods:     []string{http.MethodGet},
		HandlerFunc: RespondOKHandler,
	},
	{
		Path:        "/healthz",
		Methods:     []string{http.MethodGet},
		HandlerFunc: RespondOKHandler,
	},
	{
		Path:        "/api/v1/alert",
		Methods:     []string{http.MethodPost},
		HandlerFunc: ProcessAlertHandler,
	},
	{
		Path:        "/api/v1/jira_webhook",
		Methods:     []string{http.MethodPost},
		HandlerFunc: ProcessJiraWebhook,
	},
}

// InitRoutes initializes routes from the defined Listeners
func InitRoutes(router *chi.Mux) {
	for _, listener := range Listeners {
		for _, method := range listener.Methods {
			router.Method(method, listener.Path, listener.HandlerFunc)
		}
	}
	// Add the Prometheus metrics endpoint
	router.Method(http.MethodGet, "/metrics", promhttp.Handler())
}

// RespondOKHandler replies with a 200 OK and "OK" text to any request, for health checks
func RespondOKHandler(w http.ResponseWriter, _ *http.Request) {
	setResponse(w, status200, processInfo{process: "RespondOKHandler"})
}

// ProcessAlertHandler is the main logic processing alerts received from Splunk
func ProcessAlertHandler(w http.ResponseWriter, r *http.Request) {
	if config.AppConfig.Verbose {
		log.Printf("listeners.ProcessAlertHandler(): received http request: %+v", r)
	}

	// Assign a UUID to the event and set process info for metrics/logging
	var p processInfo = processInfo{
		uuid:    uuid.New().String(),
		process: "ProcessAlertHandler",
	}

	// Prefix log messages with uuid plus a space for easier tracing
	log.SetPrefix(p.uuid + " ")
	defer log.SetPrefix("")

	// Process the Received Webhook
	metrics.MetricSplunkWebhookReceived.With(p.LabelInput()).Inc()

	var webhook splunk.Webhook

	decodeJSONerr := helpers.DecodeJSONRequestBody(w, r, &webhook)
	if decodeJSONerr != nil {
		var mr *helpers.MalformedRequest
		if errors.As(decodeJSONerr, &mr) {
			ple := p.LabelInput()
			ple["error_type"] = "malformed_request"
			metrics.MetricSplunkWebhookProcessFailures.With(ple).Inc()
			log.Printf("received malformed request: %s\n", mr.Msg)
			// This is a client error, so we return the status code and message
			setResponse(w, statusInfo{code: mr.Status, msg: []string{mr.Msg}}, p)
		} else {
			ple := p.LabelInput()
			ple["error_type"] = "unknown"
			metrics.MetricSplunkWebhookProcessFailures.With(ple).Inc()
			log.Printf("failed decoding JSON request body: %s\n", decodeJSONerr.Error())
			setResponse(w, status500, p)
		}
		return
	}

	if config.AppConfig.Verbose {
		log.Printf("listeners.ProcessAlertHandler(): JSON data decoded to &splunk.Webhook : %+v", webhook)
	}

	// Create a Jira client
	// This may be used to create issues on failures, too
	jiraClient, jiraClientErr := jira.DefaultClient()
	if jiraClientErr != nil {
		log.Printf("failed creating Jira client: %s\n", jiraClientErr.Error())
		metrics.MetricJiraClientCreateFailures.With(p.LabelInput()).Inc()
		setResponse(w, status500, p)
		return
	}

	// Retrieve search results from webhook
	log.Println("retrieving alert from Splunk:", webhook.Sid)
	metrics.MetricSplunkAlertSIDReceived.With(p.LabelInput()).Inc()

	var searchResults splunk.Alert
	searchResults, searchErr := splunk.Server(config.AppConfig.SplunkConfig).RetrieveSearchFromAlert(webhook.Sid)

	if searchErr != nil {
		log.Printf("error retrieving search results from Splunk: %s", searchErr.Error())
		ple := p.LabelInput()
		ple["error_type"] = "retrieval_error"
		metrics.MetricSplunkSearchResultQueryFailures.With(ple).Inc()

		alertJson, jsonErr := json.MarshalIndent(webhook, "", "  ")
		if jsonErr != nil {
			log.Printf("error marshalling webhook data to JSON: %s", jsonErr.Error())
		}

		ticketDetails := fmt.Sprintf(
			"A Compliance Alert was received from Splunk, but the alert details could not be retrieved. "+
				"Please review:\n"+
				"Splunk Webhook Search ID: %s\n"+
				"Splunk Webhook Data: %s\n"+
				"\nError: %s\n", webhook.Sid, alertJson, searchErr.Error(),
		)

		// Add a note to the ticket details if the webhook data might be incomplete
		if jsonErr != nil {
			ticketDetails += fmt.Sprintf(
				"\nNOTE: The Splunk webhook data could not be marshalled to JSON.\n"+
					"This may indicate that the webhook data is incomplete."+
					"The error was: %s\n", jsonErr.Error())
		}

		createErr := jira.CreateTicket(jiraClient.User, jiraClient.Issue, "", "", ticketDetails)
		if createErr != nil {
			log.Printf("failed creating Jira ticket: %s", createErr.Error())
			metrics.MetricJiraIssueCreateFailures.With(p.LabelInput()).Inc()
			setResponse(w, status500, p)
			return
		}
		// Increment the metric for Jira issues created to track errors
		metrics.MetricJiraErrorIssuesCreated.With(p.LabelInput()).Inc()

		// Return a 500 for any error case
		setResponse(w, status500, p)

		return
	}

	// Process each result in the alert search results
	for _, complianceEvent := range searchResults.Details() {
		log.Println(complianceEvent)
		metrics.MetricComplianceEventsFound.With(p.LabelInput()).Inc()

		var user string = complianceEvent.User
		var manager string = ""

		// If LDAP is enabled, look up the user and manager
		// This may be deprecated in the future
		if config.AppConfig.LDAPConfig.Enabled {
			var ldapErr error
			user, manager, ldapErr = ldap.LookupUser(complianceEvent.User)
			if ldapErr != nil {
				log.Printf("failed ldap lookup: %s\n", ldapErr.Error())
				metrics.MetricLDAPLookupFailures.With(p.LabelInput()).Inc()

				ticketDetails := fmt.Sprintf(
					"A Compliance Alert was received from Splunk, but the user details could not be retrieved from LDAP."+
						"Please review and assign accordingly:\n"+
						"Compliance Data: %+v\n"+
						"\nError: %s\n", complianceEvent, ldapErr.Error(),
				)

				createErr := jira.CreateTicket(jiraClient.User, jiraClient.Issue, "", "", ticketDetails)
				if createErr != nil {
					log.Printf("failed creating Jira ticket: %s", createErr.Error())
					metrics.MetricJiraIssueCreateFailures.With(p.LabelInput()).Inc()
					setResponse(w, status500, p)
					return
				}
				// Increment the metric for Jira issues created to track errors
				metrics.MetricJiraErrorIssuesCreated.With(p.LabelInput()).Inc()

				// Return a 500 for any error case
				setResponse(w, status500, p)
				return
			}
		}

		// Create a Jira issue for the compliance event
		jiraCreateErr := jira.CreateTicket(jiraClient.User, jiraClient.Issue, user, manager, complianceEvent.Body())
		if jiraCreateErr != nil {
			log.Printf("failed creating Jira ticket: %s", jiraCreateErr.Error())
			metrics.MetricJiraIssueCreateFailures.With(p.LabelInput()).Inc()
			setResponse(w, status500, p)
			return
		}
	}

	// Everything worked!
	metrics.MetricComplianceEventsProcessed.With(p.LabelInput()).Inc()
	setResponse(w, status200, p)
}

func ProcessJiraWebhook(w http.ResponseWriter, r *http.Request) {
	p := processInfo{
		uuid:    uuid.New().String(),
		process: "ProcessJiraWebhook",
	}
	pl := p.LabelInput()

	webhook := jira.Webhook{}
	err := helpers.DecodeJSONRequestBody(w, r, &webhook)
	if err != nil {
		var mr *helpers.MalformedRequest
		var si statusInfo
		if errors.As(err, &mr) {
			ple := p.LabelInput()
			ple["error_type"] = "malformed_request"
			log.Printf("received malformed request: %s\n", mr.Msg)
			metrics.MetricJiraWebhookProcessFailures.With(ple).Inc()
			// This is a client error, so we return the status code and message
			si.code = mr.Status
			si.msg = []string{mr.Msg}
		} else {
			ple := p.LabelInput()
			ple["error_type"] = "unknown"
			log.Printf("failed decoding JSON request body: %s\n", err.Error())
			metrics.MetricJiraWebhookProcessFailures.With(ple).Inc()
			si.code = http.StatusInternalServerError
			si.msg = []string{genericErrorMsg}
		}
		setResponse(w, si, p)
		return
	}

	client, err := jira.DefaultClient()
	if err != nil {
		log.Print(err)
		metrics.MetricJiraClientCreateFailures.With(pl).Inc()
		setResponse(w, status500, p)
	}

	err = jira.HandleUpdate(client.Issue, webhook)
	if err != nil {
		log.Print(err)
		metrics.MetricJiraIssueUpdateFailures.With(pl).Inc()
		setResponse(w, status500, p)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func setResponse(w http.ResponseWriter, status statusInfo, info processInfo) {
	var body string
	var headers map[string]string = make(map[string]string)

	// Add Status Code to the metrics labels
	metricsLabels := info.LabelInput()
	metricsLabels["code"] = http.StatusText(status.code)

	switch status.code {
	case http.StatusOK:
		body = "ok"
	case http.StatusInternalServerError:
		// Set a generic error message for InternalServerErrors to avoid accidentally exposing data
		body = genericErrorMsg
	default:
		if status.msg != nil {
			body = strings.Join(status.msg, ", ")
		} else {
			body = genericErrorMsg
		}
	}

	headers["Content-Type"] = "text/plain; charset=utf-8"
	w.WriteHeader(status.code)
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	_, _ = w.Write([]byte(body))

	metrics.MetricHTTPResponses.With(metricsLabels).Inc()
}
