# Setting up a development environment

The compliance-audit-router interacts with three external services (at the moment): Splunk, LDAP and Jira. This document describes how to setup a local development environment to simulate or interact with these services.

## Splunk

The Splunk environment integration consists of two pieces:  receipt of a webook, and retrieving a search result from the webook.

Initial development was done with a CURL to the CAR running locally to simulate the webhook, and a contaier running an HTTP server that responsed with a mock Splunk search result.

As of this writing, Splunk doesn't offer a free development environment in the same way Atlassian does, so testing sending of a webhook still need sto be done with a manual CURL to your local CAR instance.  However, all of the search retrieval operations are read-only, so it's not totally unreasonable to use a real Splunk instances for development.

For SplunkCloud, someone with Admin privileges needs to setup a user account and request a bearer token from Splunk. Note that for SplunkCloud, API access has to be requested from Splunk, to allow a set of IP addresses.

1. Login to SplunkCloud, and select "Settings -> User"
2. Create a user using "Splunk" authentication, and assign the desired roles. These should likely just be read-only access to the Search app results and indexes.
3. Go to "Settings -> Tokens" and create a token for the new user.

You can test your API token by curling the search endpoint:

```shell
curl -H "Authorization: Bearer your_api_token" \
   -X GET \
   https://your.instance.url:8089/services/search/v2
```

### Setup Splunk config for CAR

This is currently unused for development.  The Splunk config should look something like this in production:

```yaml
splunkconfig:
  host: https://your_splunk_server:port
  token: your_splunk_token
  allowinsecure: false
```

### From Webhook to Search Results

Concepts:

1. Splunk alerts are just Splunk Searches that run on some schedule.  The alert fires of the search turns up a set of results.
2. The Splunk webhook will send the ID of a specific search + job for the alert that fires.
3. The results of the search can be retrieved from the Splunk API with the search id ("search_id" in Splunk-API speak).  The search id will look something like `scheduler_abcdefg0123456789__search__RMDabcdefg0123456789_at_1674590400_80909`

Retrieval of the search id from the webhook is trivial.

Retrieval of the results of the search can be done by via the API: `https://your_splunk_server:port/services/search/v2/jobs/{search_id}/results`.  The results will return, among other data, an array of `results[]`, containing a representation of the hits for that particular search.  Each of the results in the array represent a specific audit alert to be triaged by the Compliance Audit Router - eg. each element in the array should turn into a specific ticket for audit purposes.

Note: The format/contents of the elements in the search results array depend on the format of the search output, and are not guaranteed to be identical across different searches, so for multiple types of alerts, the output for each must be standardized.

An example curl retrieving search results in JSON format looks something like this:

```shell
curl -H "Authorization: Bearer $(jq -r .token .splunk_api )" \
     -X GET \
     -d output_mode=json \
     https://your_splunk_server:port/services/search/v2/jobs/scheduler_foobarbaz__search__RMDfoobarbaz_at_1674590400_80909/results
```

## LDAP

All of the interaction with LDAP performed by CAR are read-only operations, and very low volume, so it is probably reasonable to use the production LDAP instance for the lookups.  For Red Hat team members, this just requires you to be on the corporate VPN.

This integration is so minor that it should be possible to just mock the responses for development at some point.  As of right now, it is designed to retrieve the manager information for the user who has triggered the compliance alert.

### Setup LDAP config for CAR

Add your LDAP server connection information and search parameters to your `~/.config/compliance-audit-router/compliance-audit-router.yaml` file:

```yaml
ldapconfig:
  host: ldaps://your_ldap_server
  searchbase: dc=example,dc=com
  scope: sub
  attributes:
    - manager
```

## Jira

Atlassian offers free developer instances for testing integration with Jira and other services. [Sign up for a free development instance](http://go.atlassian.com/about-cloud-dev-instance) to test API usage.

Once your test instances has been created, log in to the instance, and navigate to [https://id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) to create an API token.

You can validate your API token with the following:

```shell
curl -D- \
   -u your_email@example.org:your_api_token \
   -X GET \
   -H "Content-Type: application/json" \
   https://your.instance.url/rest/api/3/project
```

You should receive a 200 response with an empty project result, as nothing exists in your Jira instance yet.

### Create an Project in your instance

First retrieve your account id (note the `emailAddress` filter in the JQ command below):

```shell
curl -s \
   -u your_email@example.org:your_api_token \
   -X GET \
   -H "Content-Type: application/json" \
   https://your.instance.url/rest/api/3/users/search |jq -r '.[]|select(.emailAddress == "your_email@example.org") | .accountId'
```

Then use the accountID to create a dummy project (called OHSS in this example):

```shell
curl -u your_email@example.org:your_api_token \ 
   -X POST \
   -H "Content-Type: application/json" \
   https://your.instance.url/rest/api/3/project -d '{"key": "OHSS", "name": "OHSS (TEST)", "projectTypeKey": "software", "projectTemplateKey": "com.pyxis.greenhopper.jira:gh-kanban-template", "description": "Development OHSS Board for CAR", "leadAccountId": "your_user_account_id"}'
   ```

   This will leave you with a project that you can then tweak to configure to match your production instance.

### Setup Jira config for CAR

Add your test instance credentials to your `~/compliance-audit-router/compliance-audit-router.yaml` file:

```yaml
---
jiraconfig:
  host: https://your.instance.url
  username: your_email@example.org
  token: your_api_token
```
