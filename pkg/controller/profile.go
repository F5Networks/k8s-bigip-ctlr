package controller

import (
	"fmt"
	"reflect"

	v1 "k8s.io/api/core/v1"
)

// Creates a new ClientSSL profile from a Secret
func (ctlr *Controller) createSecretClientSSLProfile(
	rsCfg *ResourceConfig,
	secrets []*v1.Secret,
	tlsCipher TLSCipher,
	context string,
	renegotiationEnabled *bool,
) (error, bool) {

	var certificates []certificate
	for _, secret := range secrets {
		cert := certificate{}
		if _, ok := secret.Data["tls.key"]; !ok {
			err := fmt.Errorf("Invalid Secret '%v': 'tls.key' field not specified.",
				secret.ObjectMeta.Name)
			return err, false
		} else {
			cert.Key = string(secret.Data["tls.key"])
		}
		if _, ok := secret.Data["tls.crt"]; !ok {
			err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
				secret.ObjectMeta.Name)
			return err, false
		} else {
			cert.Cert = string(secret.Data["tls.crt"])
		}
		certificates = append(certificates, cert)
	}

	return ctlr.createClientSSLProfile(rsCfg, certificates, secrets[0].ObjectMeta.Name, secrets[0].ObjectMeta.Namespace, tlsCipher, context, renegotiationEnabled)
}

// Creates a new ClientSSL profile from a Secret
func (ctlr *Controller) createClientSSLProfile(
	rsCfg *ResourceConfig,
	certificates []certificate,
	name string,
	namespace string,
	tlsCipher TLSCipher,
	context string,
	renegotiationEnabled *bool,
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
		cp := NewCustomProfile(sni, []certificate{}, "", true, "", "", "", tlsCipher, renegotiationEnabled)
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
		certificates,
		"",    // serverName
		false, // sni
		"",    // peerCertMode
		"",    // caFile
		"",    // chainCA,
		tlsCipher,
		renegotiationEnabled,
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	if prof, ok := rsCfg.customProfiles[skey]; ok {
		if !reflect.DeepEqual(prof, cp) {
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
	secrets []*v1.Secret,
	tlsCipher TLSCipher,
	context string,
	renegotiationEnabled *bool,
) (error, bool) {

	var certificates []certificate
	for _, secret := range secrets {
		cert := certificate{}
		// tls.key is not mandatory for ServerSSL Profile
		if _, ok := secret.Data["tls.crt"]; !ok {
			err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
				secret.ObjectMeta.Name)
			return err, false
		} else {
			cert.Cert = string(secret.Data["tls.crt"])
		}
		certificates = append(certificates, cert)
	}
	return ctlr.createServerSSLProfile(rsCfg, certificates, "", secrets[0].ObjectMeta.Name, secrets[0].ObjectMeta.Namespace, tlsCipher, context, renegotiationEnabled)
}

// Creates a new ServerSSL profile from a Secret
func (ctlr *Controller) createServerSSLProfile(
	rsCfg *ResourceConfig,
	certificates []certificate,
	certchain string,
	name string,
	namespace string,
	tlsCipher TLSCipher,
	context string,
	renegotiationEnabled *bool,
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
		cp := NewCustomProfile(sni, []certificate{}, "", true, "", "", "", tlsCipher, renegotiationEnabled)
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
		certificates,
		"",        // serverName
		false,     // sni
		"",        // peerCertMode
		"",        // caFile
		certchain, // certchain,
		tlsCipher,
		renegotiationEnabled,
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	if prof, ok := rsCfg.customProfiles[skey]; ok {
		if !reflect.DeepEqual(prof, cp) {
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
