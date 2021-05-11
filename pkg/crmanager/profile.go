package crmanager

import (
	"fmt"
	"reflect"

	v1 "k8s.io/api/core/v1"
)

// Creates a new ClientSSL profile from a Secret
func (crMgr *CRManager) createSecretClientSSLProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
	context string,
) (error, bool) {

	if _, ok := secret.Data["tls.key"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.key' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}

	if _, ok := secret.Data["tls.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
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
		// This is just a basic profile, so we don't need all the fields
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
	if prof, ok := rsCfg.customProfiles.Profs[skey]; ok {
		if !reflect.DeepEqual(prof, cp) {
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

	// tls.key is not mandatory for ServerSSL Profile
	if _, ok := secret.Data["tls.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
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
		// This is just a basic profile, so we don't need all the fields
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
		string(secret.Data["tls.crt"]),
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
		if !reflect.DeepEqual(prof, cp) {
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
