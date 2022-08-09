package controller

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
)

// Creates a new ClientSSL profile from a Secret
func (ctlr *Controller) createSecretClientSSLProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
	tlsCipher TLSCipher,
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

	return ctlr.createClientSSLProfile(rsCfg, string(secret.Data["tls.key"]), string(secret.Data["tls.crt"]), secret.ObjectMeta.Name, secret.ObjectMeta.Namespace, tlsCipher, context)
}

// Creates a new ClientSSL profile from a Secret
func (ctlr *Controller) createClientSSLProfile(
	rsCfg *ResourceConfig,
	key string,
	cert string,
	name string,
	namespace string,
	tlsCipher TLSCipher,
	context string,
) (error, bool) {

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
	if _, ok := rsCfg.customProfiles[skey]; !ok {
		// This is just a basic profile, so we don't need all the fields
		cp := NewCustomProfile(sni, "", "", "", true, "", "", "", tlsCipher)
		rsCfg.customProfiles[skey] = cp
	}

	// TODO
	//rsCfg.Virtual.AddOrUpdateProfile(sni)

	// Now add the resource profile
	profRef := ProfileRef{
		Name:      name,
		Partition: rsCfg.Virtual.Partition,
		Context:   context,
		Namespace: namespace,
	}
	cp := NewCustomProfile(
		profRef,
		cert,
		key,
		"",    // serverName
		false, // sni
		"",    // peerCertMode
		"",    // caFile
		"",    // chainCA,
		tlsCipher,
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	if prof, ok := rsCfg.customProfiles[skey]; ok {
		if prof != cp {
			rsCfg.customProfiles[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
			return nil, true
		} else {
			return nil, false
		}
	}
	rsCfg.customProfiles[skey] = cp
	rsCfg.Virtual.AddOrUpdateProfile(profRef)
	return nil, false
}

// Creates a new ServerSSL profile from a Secret
func (ctlr *Controller) createSecretServerSSLProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
	tlsCipher TLSCipher,
	context string,
) (error, bool) {

	// tls.key is not mandatory for ServerSSL Profile
	if _, ok := secret.Data["tls.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}
	return ctlr.createServerSSLProfile(rsCfg, string(secret.Data["tls.crt"]), "", secret.ObjectMeta.Name, secret.ObjectMeta.Namespace, tlsCipher, context)
}

// Creates a new ServerSSL profile from a Secret
func (ctlr *Controller) createServerSSLProfile(
	rsCfg *ResourceConfig,
	cert string,
	certchain string,
	name string,
	namespace string,
	tlsCipher TLSCipher,
	context string,
) (error, bool) {

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
	if _, ok := rsCfg.customProfiles[skey]; !ok {
		// This is just a basic profile, so we don't need all the fields
		cp := NewCustomProfile(sni, "", "", "", true, "", "", "", tlsCipher)
		rsCfg.customProfiles[skey] = cp
	}
	// TODO
	//rsCfg.Virtual.AddOrUpdateProfile(sni)

	// Now add the resource profile
	profRef := ProfileRef{
		Name:      name,
		Partition: rsCfg.Virtual.Partition,
		Context:   context,
		Namespace: namespace,
	}
	cp := NewCustomProfile(
		profRef,
		cert,
		"",
		"",        // serverName
		false,     // sni
		"",        // peerCertMode
		"",        // caFile
		certchain, // certchain,
		tlsCipher,
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	if prof, ok := rsCfg.customProfiles[skey]; ok {
		if prof != cp {
			rsCfg.customProfiles[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
			return nil, true
		} else {
			return nil, false
		}
	}
	rsCfg.customProfiles[skey] = cp
	rsCfg.Virtual.AddOrUpdateProfile(profRef)
	return nil, false
}
