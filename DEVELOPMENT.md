<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Setting up a development environment](#setting-up-a-development-environment)
  - [Splunk](#splunk)
    - [Setup Splunk config for CAR](#setup-splunk-config-for-car)
    - [From Webhook to Search Results](#from-webhook-to-search-results)
  - [LDAP](#ldap)
    - [Setup LDAP config for CAR](#setup-ldap-config-for-car)
  - [Jira](#jira)
    - [Create a Project in your instance](#create-a-project-in-your-instance)
    - [Enabling Permissions for your project](#enabling-permissions-for-your-project)
    - [Setup Jira config for CAR](#setup-jira-config-for-car)
  - [Container Development](#container-development)
    - [Building the image](#building-the-image)
    - [Testing the container image](#testing-the-container-image)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Setting up a development environment

The compliance-audit-router interacts with three external services (at the moment): Splunk, LDAP and Jira. This document describes how to setup a local development environment to simulate or interact with these services.

## Splunk

The Splunk environment integration consists of two pieces:  receipt of a webhook, and retrieving a search result from the webhook.

Initial development was done with a CURL to the CAR running locally to simulate the webhook, and a container running an HTTP server that responds with a mock Splunk search result.

As of this writing, Splunk doesn't offer a free development environment in the same way Atlassian does, so testing sending of a webhook still needs to be done with a manual CURL to your local CAR instance.  However, all of the search retrieval operations are read-only, so it's not totally unreasonable to use a real Splunk instances for development.

For SplunkCloud, someone with Admin privileges needs to setup a user account and request a bearer token from Splunk. Note that for SplunkCloud, API access has to be requested from Splunk, to allow a set of IP addresses.

1. Login to SplunkCloud, and select "Settings -> User"
2. Create a user using "Splunk" authentication, and assign the desired roles. These should likely just be read-only access to the Search app results and indexes.
3. Go to "Settings -> Tokens" and create a token for the new user.

You will also need to add your IP/Subnet to the allow list in "Settings -> Server Settings -> IP Allow List Management" under "Search head API access". After adding an IP to the allowlist, it will take some time to propagate.

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

1. Splunk alerts are just Splunk Searches that run on some schedule.  The alert fires if the search turns up a set of results.
2. The Splunk webhook will send the ID of a specific search + job for the alert that fires. [See 'Example Alert Payload' below](#example-alert-payload) 
3. The results of the search can be retrieved from the Splunk API with the search id ("search_id" in Splunk-API speak).  The search id will look something like `scheduler_abcdefg0123456789__search__RMDabcdefg0123456789_at_1674590400_80909`.
4. The search id can be retrieved from the Alert Payload from the `sid` field in the payload.  

Retrieval of the results of the search can be done by via the API: `https://your_splunk_server:port/services/search/v2/jobs/{search_id}/results`.  The results will return, among other data, an array of `results[]`, containing a representation of the hits for that particular search.  Each of the results in the array represent a specific audit alert to be triaged by the Compliance Audit Router - eg. each element in the array should turn into a specific ticket for audit purposes.

Note: The format/contents of the elements in the search results array depend on the format of the search output, and are not guaranteed to be identical across different searches, so for multiple types of alerts, the output for each must be standardized.

An example curl retrieving search results in JSON format looks something like this:

```shell
curl -H "Authorization: Bearer $(jq -r .token .splunk_api )" \
     -X GET \
     -d output_mode=json \
     https://your_splunk_server:port/services/search/v2/jobs/scheduler_foobarbaz__search__RMDfoobarbaz_at_1674590400_80909/results
```

See [https://docs.splunk.com/Documentation/SplunkCloud/9.0.2305/RESTREF/RESTsearch#search.2Fv2.2Fjobs.2F.7Bsearch_id.7D.2Fresults](https://docs.splunk.com/Documentation/SplunkCloud/9.0.2305/RESTREF/RESTsearch#search.2Fv2.2Fjobs.2F.7Bsearch_id.7D.2Fresults) for more information about the Splunk Search results API endpoint.

<a name="example-alert-payload"></a>
**_Example Alert Payload_**

An Alert webhook payload will look similar to this:

```json
{
	"result": {
		"sourcetype" : "_json",
		"count" : "8"
	},
	"sid" : "scheduler_foobarbaz__search__RMDfoobarbaz_at_1674590400_80909/results",
	"results_link" : "https://your_splunk_server:port/services/search/v2/jobs/scheduler_foobarbaz__search__RMDfoobarbaz_at_1674590400_80909",
	"search_name" : null,
	"owner" : "admin",
	"app" : "search"
}
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

### Create a Project in your instance

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

### Enabling Permissions for your project
Before you can create and manage new issues in your test project, you will need to add yourself to the Administrators role for your cloud account. To do this, use the following steps:

1. While logged in to your JIRA cloud web console, click the menu button in the top-left and switch to the "Administration" service.
1. Select "Directory" from the top tabs.
1. Select "Groups" from the left sidebar.
1. Find the group `jira-admins-YOUR_ACCOUNT_NAME` and click "Show Details" for the group.
1. Click "Add Group Members" and add your account as a User to the group.

### Setup Jira config for CAR

Add your test instance credentials and other required fields to your `~/compliance-audit-router/compliance-audit-router.yaml` file:

- host - the url for your JIRA instance
- username - your JIRA username
- token - your API token or personal access token
- key - the project key for which issues will be created
- issuetype - the type to assign to created issues
- dev - whether CAR is being run in a development environment.
  - Note: this setting will assume that you are using a Jira Cloud instance with Basic Auth
- transitions - map of what state to transition a ticket to after a specific user comments on the ticket. The ticket will only be transitioned if that user is also the ticket's current assignee. Note that "initial" is the initial state a ticket will be placed in after it is created.
```yaml
---
jiraconfig:
  host: https://your.instance.url
  username: your_email@example.org
  token: your_api_token
  key: OHSS
  issuetype: Task
  dev: true
  transitions:
    initial: In Progress
    sre: Pending Approval
    manager: Done
```

## Container Development

### Building the image

The CI setup for this project is designed for use with the OpenShift Dedicated internal App-SRE and SRE Platform teams' CI tools, but can be run locally as well.  A `build-image` make target is provided in the Makefile and will build the binary and a local image, and tag the image as `compliance-audit-router:latest`.

The image build will exit with a failure if your local git checkout is not clean (you have uncommitted changes).  Committing these changes, or setting `ALLOW_DIRTY_CHECKOUT=TRUE` will allow the build to proceed.

### Testing the container image

A `compose.yaml` file is provided for use with [Podman Desktop with a compose engine](https://podman-desktop.io/docs/compose), standalone [Podman Compose](https://github.com/containers/podman-compose), or [Docker Compose](https://docs.docker.com/compose/).

To get a running instance of compliance-audit-router locally, you just need to create the compose service, copy a configuration file to the root of the container, and start the service.

```
# Create the compose service
podman compose create

# Copy a configuration file to /compliance-audit-router.yaml in the container
podman compose copy <path to your config file> compliance-audit-router-compliance-audit-router-1:/compliance-audit-router.yaml

# Start the service
podman compose up --detach
```

The container running compliance-audit-router will now be visible in the output of `podman ps` or within the Podman Desktop application window.  The compliance-audit-router itself will be listening on [http://localhost:8080](http://localhost:8080) of your host machine.
