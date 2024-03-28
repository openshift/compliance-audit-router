package splunk

import (
	"strings"
	"time"
)

// AlertDetails is a structured Splunk alert details
type AlertDetails struct {
	AlertName           string
	User                string
	Group               string
	Timestamp           time.Time
	ClusterIDs          []string
	ClusterText         string
	ElevatedSummary     []string
	ElevatedSummaryText string
	Reasons             []string
	ReasonsText         string
}

// AlertDetails.Valid checks whether an alert has all the necessary fields for a compliance ticket
func (a AlertDetails) Valid() bool {
	return a.AlertName != "" && a.User != "" && a.Group != "" && len(a.ClusterIDs) > 0
}

func (a AlertDetails) Name() string {
	return a.AlertName
}

func (a AlertDetails) Body() string {
	var s strings.Builder

	s.WriteString(a.User + " - " + a.Name())
	s.WriteString("\n\n")
	s.WriteString(a.ClusterText)
	s.WriteString("\n\n")
	s.WriteString(a.ElevatedSummaryText)
	s.WriteString("\n\n")
	s.WriteString(a.ReasonsText)

	return s.String()
}

// NewAlertDetails creates a new AlertDetails from a SearchResult
func NewAlertDetails(result SearchResult) AlertDetails {
	return AlertDetails{
		AlertName:           result.string("alertname"),
		User:                result.string("username"),
		Group:               result.string("group"),
		Timestamp:           result.time("timestamp"),
		ClusterIDs:          result.slice("clusterid"),
		ClusterText:         result.string("cluster_text"),
		ElevatedSummary:     result.slice("elevated_summary"),
		ElevatedSummaryText: result.string("elevated_summary_text"),
		Reasons:             result.slice("reason"),
		ReasonsText:         result.string("reason_text"),
	}
}

// Alert.Details returns a slice of AlertDetails from the alert search results
func (w Alert) Details() []AlertDetails {
	alerts := []AlertDetails{}
	for _, result := range w.SearchResults.Results {
		alert := NewAlertDetails(result)
		if alert.Valid() {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}
