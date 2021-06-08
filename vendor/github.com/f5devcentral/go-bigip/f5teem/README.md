# f5teem
Go Module providing an interface for F5's TEEM infrastructure to provide usage analytics to F5.

# Usage (Anonymous API)

```go

package main

import (
	//"github.com/RavinderReddyF5/f5-teem"
	"github.com/f5devcentral/go-bigip/f5teem"
	"log"
)

func main() {
	assetInfo := f5teem.AssetInfo{
		"Terraform-Provider-BIGIP-Ecosystem",
		"1.2.0",
		"",
	}
	teemDevice := f5teem.AnonymousClient(assetInfo, "")
	d := map[string]interface{}{
		"Device":          1,
		"Tenant":          1,
		"License":         1,
		"DNS":             1,
		"NTP":             1,
		"Provision":       1,
		"VLAN":            2,
		"SelfIp":          2,
		"platform":        "BIG-IP",
		"platformVersion": "15.1.0.5",
	}
	err := teemDevice.Report(d, "Terraform BIGIP-ravinder-latest", "1")
	if err != nil {
		log.Printf("Error:%v", err)
	}
}
```
# Example Telemetry Record
```
{
    "digitalAssetName": "f5-example-product",
    "digitalAssetVersion": "1.0.0",
    "digitalAssetId": "<asset UUID>",
    "documentType": "Installation Usage",
    "documentVersion": "1",
    "observationStartTime": "",
    "observationEndTime": "",
    "epochTime": "",
    "telemetryId": "",
    "telemetryRecords": [
        {
        "Device":          1,
        "Tenant":          1,
        "License":         1,
        "DNS":             1,
        "NTP":             1,
        "Provision":       1,
        "VLAN":            2,
        "SelfIp":          2,
        "platform":        "BIG-IP",
        "platformVersion": "15.1.0.5",
	   }]
}
```
# Use TEEM staging environment
  Set environment variable
  ```
  export TEEM_API_ENVIRONMENT='staging'
  ```
# Additional Notes
This library is similar to the node-based f5-teem library (https://www.npmjs.com/package/@f5devcentral/f5-teem),
python library(https://pypi.org/project/f5-teem/)
