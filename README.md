# compliance-audit-router

A tool to receive compliance alert webhooks from an external source (eg. Splunk), look up the responsible engineer's information (eg. from LDAP), and create a compliance report ticket (eg. Jira) assigned to the engineer for follow-up.

## Configuration

Configuration is managed in the `~/.config/compliance-audit-router/compliance-audit-router.yaml` file.

Alternatively, configuration options may be set using environment variables according to the [Viper environmental variable setup](https://github.com/spf13/viper#working-with-environment-variables), with the prefix `CAR_` (eg. `CAR_LISTENPORT=8080`).

An example `compliance-audit-router.yaml` file:

```yaml
---
verbose: false
listenport: 8080

ldapconfig:
  host: ldaps://ldap.example.org
  searchbase: dc=example,dc=org
  scope: sub
  attributes:
    - manager
    - alternateID

splunkconfig:
  host: https://splunk.example.org:8089
  token: <token>
  allowinsecure: false

jiraconfig:
  host: https://jira.example.org:443
  username: <username>
  token: <token>
  query: <JQL to identify compliance cards>

messagetemplate: |
  {{.Username}},

  This action required business justification from the engineer who used this access, and management approval.

  If this action is unexpected or unexplained, please contact the Security team immediately for further investigation.
```
