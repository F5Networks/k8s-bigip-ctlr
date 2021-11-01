package crmanager

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
)

// Creates a new ClientSSL profile from a Secret
func (crMgr *CRManager) createSecretClientSSLProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
	context string,
) (error, bool) {

	if _, ok := secret.Data["VirtualServerWithTLSProfile.key"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'VirtualServerWithTLSProfile.key' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}

	if _, ok := secret.Data["VirtualServerWithTLSProfile.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'VirtualServerWithTLSProfile.crt' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}

	// Create Default for SNI profile
	skey := SecretKey{
		Name:         fmt.Sprintf("default-%s-%s", context, rsCfg.GetName()),
		ResourceName: rsCfg.GetName(),
	}
	sni := ProfileRef{
		Name:      skey.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   context,
	}
	if _, ok := rsCfg.customProfiles.Profs[skey]; !ok {
		// This is just a VirtualServer profile, so we don't need all the fields
		cp := NewCustomProfile(sni, "", "", "", true, "", "")
		rsCfg.customProfiles.Profs[skey] = cp
	}

	// TODO
	//rsCfg.Virtual.AddOrUpdateProfile(sni)

	// Now add the resource profile
	profRef := ProfileRef{
		Name:      secret.ObjectMeta.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   context,
		Namespace: secret.ObjectMeta.Namespace,
	}
	cp := NewCustomProfile(
		profRef,
		string(secret.Data["VirtualServerWithTLSProfile.crt"]),
		string(secret.Data["VirtualServerWithTLSProfile.key"]),
		"",    // serverName
		false, // sni
		"",    // peerCertMode
		"",    // caFile
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	if prof, ok := rsCfg.customProfiles.Profs[skey]; ok {
		if prof != cp {
			rsCfg.customProfiles.Profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
			return nil, true
		} else {
			return nil, false
		}
	}
	rsCfg.customProfiles.Profs[skey] = cp
	rsCfg.Virtual.AddOrUpdateProfile(profRef)
	return nil, false
}

// Creates a new ServerSSL profile from a Secret
func (crMgr *CRManager) createSecretServerSSLProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
	context string,
) (error, bool) {

	// VirtualServerWithTLSProfile.key is not mandatory for ServerSSL Profile
	if _, ok := secret.Data["VirtualServerWithTLSProfile.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'VirtualServerWithTLSProfile.crt' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}

	// Create Default for SNI profile
	skey := SecretKey{
		Name:         fmt.Sprintf("default-%s-%s", context, rsCfg.GetName()),
		ResourceName: rsCfg.GetName(),
	}
	sni := ProfileRef{
		Name:      skey.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   context,
	}
	if _, ok := rsCfg.customProfiles.Profs[skey]; !ok {
		// This is just a VirtualServer profile, so we don't need all the fields
		cp := NewCustomProfile(sni, "", "", "", true, "", "")
		rsCfg.customProfiles.Profs[skey] = cp
	}
	// TODO
	//rsCfg.Virtual.AddOrUpdateProfile(sni)

	// Now add the resource profile
	profRef := ProfileRef{
		Name:      secret.ObjectMeta.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   context,
		Namespace: secret.ObjectMeta.Namespace,
	}
	cp := NewCustomProfile(
		profRef,
		string(secret.Data["VirtualServerWithTLSProfile.crt"]),
		"",
		"",    // serverName
		false, // sni
		"",    // peerCertMode
		"",    // caFile
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	if prof, ok := rsCfg.customProfiles.Profs[skey]; ok {
		if prof != cp {
			rsCfg.customProfiles.Profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
			return nil, true
		} else {
			return nil, false
		}
	}
	rsCfg.customProfiles.Profs[skey] = cp
	rsCfg.Virtual.AddOrUpdateProfile(profRef)
	return nil, false
}
