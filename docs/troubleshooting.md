# Troubleshooting

## CIS Logs and Events

Check for events in CIS deployed kube-system namespace for any ContainerCreation issues.

`kubectl get events -n kube system`

### To access CIS logs for troubleshoot

`kubectl logs deploy/<name-of-cis-deployment> -n kube-system -f`

Log related CIS deployment arguments to help with debugging.

`log-level`:  can be set to INFO, DEBUG, CRITICAL, WARNING, ERROR

`cccl-log-level`: can be set to INFO, for detailed logs with cccl

`log-as3-response`: set to true, it logs the AS3 API response.It can be used to look at error returned from AS3.

### BIGIP logs

To check logs for restjavad and restnoded daemon

`/var/log/restjavad.0.log`

`/var/log/restnoded/restnoded.log`

## High CPU Usage with bigip

Increase memory allocated to restjavd in case of continuous restart of the restjavad daemon due to high CPU usage

`tmsh modify sys db restjavad.useextramb value true`

`tmsh modify sys db provision.extramb value 2048`

`bigstart restart restjavad`

### Options to consider for mitigating high cpu usage on bigip

* as3-post-delay - Continuously posting new declaration to BIG-IP without much delay may lead to 503 response from BIG-IP as AS3 is busy in performing earlier requests.This may lead to high cpu usage with retries.Consider delaying
  the post call to BIG-IP with given number of seconds through CIS config parameter --as3-post-delay.Once the delay time ends CIS picks up the latest declaration produced and posts to BIGIP, this will reduce the number of post requests.
  
* verify-interval - It is used to verify if the BIG-IP configuration matches the state of the orchestration system.CIS verifies every 30s(default interval) if the LTM and NET config matches the config on BIGIP.Consider increasing the verify-interval value to reduce the number of calls to BIGIP.



