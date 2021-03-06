# Agent Check: pihole

## Official release
Official release can be found on integrations-extras: https://github.com/DataDog/integrations-extras/tree/master/pihole

## Overview

This check monitors [pihole][1] through the Datadog Agent.



![](https://p-qKFgO2.t2.n0.cdn.getcloudapp.com/items/GGukK0lR/Image%202020-05-06%20at%2010.15.08%20PM.png?v=52c007c545c0e3341bd58916c057505f)



## Setup

Follow the instructions below to install and configure this check for an Agent running on a host. For containerized environments, see the [Autodiscovery Integration Templates][2] for guidance on applying these instructions.

### Installation

To install the pihole check on your host:

1. Install the [developer toolkit](https://docs.datadoghq.com/developers/integrations/new_check_howto/#developer-toolkit) on any machine.
2. Run `ddev release build pihole` to build the package.
3. [Download the Datadog Agent](https://app.datadoghq.com/account/settings#agent).
4. Upload the build artifact to any host with an Agent andrun `datadog-agent integration install -w path/to/pihole/dist/<ARTIFACT_NAME>.whl`.

### Configuration

1. Edit the `pihole.d/conf.yaml` file, in the `conf.d/` folder at the root of your Agent's configuration directory to start collecting your pihole performance data. See the [sample pihole.d/conf.yaml][3] for all available configuration options.

2. [Restart the Agent][4].

### Validation

[Run the Agent's status subcommand][5] and look for `pihole` under the Checks section.


## Available metrics
* Queries forwarded
* Domains being blocked
* Ads percentage today
* Ads blocked today
* DNS queries today
* Total clients
* Unique clients
* Queries cached
* Unique Domains
* Top Queries
* Top Ads
* Top clients
* Forward destinations
* Query type
* Reply type
* DNS queries by host


### Metrics

See [metadata.csv][6] for a list of metrics provided by this check.

![](https://p-qKFgO2.t2.n0.cdn.getcloudapp.com/items/OAub8x2X/Image%202020-05-06%20at%2010.16.46%20PM.png?v=37506212f56c09d84525962af60279f4)

### Service Checks

pi-hole.can.connect

### Events

pihole does not include any events.

## Troubleshooting

Need help? Contact [Datadog support][7].

[1]: **LINK_TO_INTEGRATION_SITE**
[2]: https://docs.datadoghq.com/agent/autodiscovery/integrations
[3]: https://github.com/DataDog/integrations-core/blob/master/pihole/datadog_checks/pihole/data/conf.yaml.example
[4]: https://docs.datadoghq.com/agent/guide/agent-commands/#start-stop-and-restart-the-agent
[5]: https://docs.datadoghq.com/agent/guide/agent-commands/#agent-status-and-information
[6]: https://github.com/DataDog/integrations-core/blob/master/pihole/metadata.csv
[7]: https://docs.datadoghq.com/help
