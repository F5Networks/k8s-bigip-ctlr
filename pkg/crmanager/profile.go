package crmanager

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
	"reflect"
)

// Creates a default SNI profile (if needed) and a new profile from a Secret
func (crMgr *CRManager) createSecretSslProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
) (error, bool) {
	if _, ok := secret.Data["tls.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}
	if _, ok := secret.Data["tls.key"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.key' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}

	// Create Default for SNI profile
	skey := SecretKey{
		Name:         fmt.Sprintf("default-clientssl-%s", rsCfg.GetName()),
		ResourceName: rsCfg.GetName(),
	}
	sni := ProfileRef{
		Name:      skey.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   CustomProfileClient,
	}
	if _, ok := crMgr.customProfiles.Profs[skey]; !ok {
		// This is just a basic profile, so we don't need all the fields
		cp := NewCustomProfile(sni, "", "", "", true, "", "")
		crMgr.customProfiles.Profs[skey] = cp
	}
	rsCfg.Virtual.AddOrUpdateProfile(sni)

	// Now add the resource profile
	profRef := ProfileRef{
		Name:      secret.ObjectMeta.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   CustomProfileClient,
		Namespace: secret.ObjectMeta.Namespace,
	}
	cp := NewCustomProfile(
		profRef,
		string(secret.Data["tls.crt"]),
		string(secret.Data["tls.key"]),
		"",    // serverName
		false, // sni
		"",    // peerCertMode
		"",    // caFile
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	crMgr.customProfiles.Lock()
	defer crMgr.customProfiles.Unlock()
	if prof, ok := crMgr.customProfiles.Profs[skey]; ok {
		if !reflect.DeepEqual(prof, cp) {
			crMgr.customProfiles.Profs[skey] = cp
			return nil, true
		} else {
			return nil, false
		}
	}
	crMgr.customProfiles.Profs[skey] = cp
	return nil, false
}
