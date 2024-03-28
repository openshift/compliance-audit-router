package splunk

import (
	"fmt"
	"log"
	"time"
)

const SplunkTimeFormat = "2006-01-02T15:04:05.GMT"

func (a SearchResult) string(field string) string {
	if i, ok := a[field]; !ok {
		log.Printf("No such field: %s", field)
		return ""
	} else {
		return fmt.Sprint(i)
	}
}

func (a SearchResult) slice(field string) []string {
	if i, ok := a[field]; !ok {
		return []string{}
	} else {
		var values []string
		switch v := i.(type) {
		case string:
			values = append(values, v)
		case []string:
			values = append(values, v...)
		case []interface{}:
			for _, e := range v {
				values = append(values, e.(string))
			}
		default:
			log.Printf("Unknown type for field %s: %T", field, v)
		}
		return values
	}
}

func (a SearchResult) time(field string) time.Time {
	if s := a.string(field); s != "" {
		if t, err := time.Parse(SplunkTimeFormat, s); err == nil {
			return t
		} else {
			log.Printf("Error parsing timestamp: %v", err)
		}
	}
	return time.Time{}
}
