# AS3 API refernce

## To get AS3 version.

   `https://<mgmt_ip>:8443/mgmt/shared/appsvcs/info`
    
   eg: curl -k https://localhost:8443/mgmt/shared/appsvcs/info
 
## To get tenants AS3 Declaration.
   
   `https://<mgmt_ip>/mgmt/shared/appsvcs/declare/<tenant_name>`
   
   eg: curl -ku username:password https://<mgmt_ip>/mgmt/shared/appsvcs/declare/<tenant_name>

## To flush a tenant's content.
   
   POST AS3 empty declaration `https://<mgmt_ip>/mgmt/shared/appsvcs/declare/<tenant-name>`
   
   eg: curl -ku username:password -X POST -H "Content-Type: application/json" -d '{"class": "AS3","action": "deploy","persist": true,"declaration": {"class": "ADC","schemaVersion": "3.28.0","<bigip-partition>": {"class": "Tenant","Shared": {"class": "Application","template": "shared"}}}}' https://<mgmt-ip>/mgmt/shared/appsvcs/declare/<tenant_name>

## To delete a tenant
   
   Send DELETE to `https://<mgmt_ip>/mgmt/shared/appsvcs/declare/<tenant_name>`
   
   eg: curl -ku username:password -X DELETE https://<mgmt_ip>/mgmt/shared/appsvcs/declare/<tenat_name>