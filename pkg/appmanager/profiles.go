/*-
 * Copyright (c) 2017, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"

	routeapi "github.com/openshift/origin/pkg/route/api"
)

func (appMgr *Manager) setClientSslProfile(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
	route *routeapi.Route,
) {
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()

	// First handle the Default for SNI profile
	if appMgr.routeConfig.ClientSSL != "" {
		// User has provided a name
		prof := convertStringToProfileRef(
			appMgr.routeConfig.ClientSSL, customProfileClient, sKey.Namespace)
		rsCfg.Virtual.AddOrUpdateProfile(prof)
	} else {
		// No provided name, so we create a default
		skey := secretKey{
			Name:         "default-route-clientssl",
			ResourceName: rsCfg.GetName(),
		}
		if _, ok := appMgr.customProfiles.profs[skey]; !ok {
			profile := ProfileRef{
				Name:      "default-route-clientssl",
				Partition: rsCfg.Virtual.Partition,
				Context:   customProfileClient,
			}
			// This is just a basic profile, so we don't need all the fields
			cp := NewCustomProfile(profile, "", "", "", true, "", "")
			appMgr.customProfiles.profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profile)
		}
	}
	// Now handle the profile from the Route.
	// If annotation is set, use that profile instead of Route profile.
	if prof, ok := route.ObjectMeta.Annotations[f5ClientSslProfileAnnotation]; ok {
		if nil != route.Spec.TLS {
			log.Debugf("Both clientssl annotation and cert/key provided for Route: %s, "+
				"using annotation.", route.ObjectMeta.Name)
			// Delete existing Route profile if it exists
			profRef := makeRouteClientSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
			rsCfg.Virtual.RemoveProfile(profRef)
		}
		profRef := convertStringToProfileRef(prof, customProfileClient, sKey.Namespace)
		if add := rsCfg.Virtual.AddOrUpdateProfile(profRef); add {
			// Store this annotated profile in the metadata for future reference
			// if it gets deleted.
			rKey := routeKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   customProfileClient,
			}
			rsCfg.MetaData.RouteProfs[rKey] = prof
			stats.vsUpdated += 1
		}
	} else {
		profRef := ProfileRef{
			Partition: "Common",
			Name:      "clientssl",
			Context:   customProfileClient,
			Namespace: sKey.Namespace,
		}
		// We process the profile from the Route
		if "" != route.Spec.TLS.Certificate && "" != route.Spec.TLS.Key {
			profile := makeRouteClientSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)

			cp := NewCustomProfile(
				profile,
				route.Spec.TLS.Certificate,
				route.Spec.TLS.Key,
				route.Spec.Host,
				false,
				"", // peerCertMode
				"", // caFile
			)

			skey := secretKey{
				Name:         cp.Name,
				ResourceName: rsCfg.GetName(),
			}
			if prof, ok := appMgr.customProfiles.profs[skey]; ok {
				if !reflect.DeepEqual(prof, cp) {
					stats.cpUpdated += 1
				}
			}
			appMgr.customProfiles.profs[skey] = cp
			profRef.Partition = cp.Partition
			profRef.Name = cp.Name
		}
		if add := rsCfg.Virtual.AddOrUpdateProfile(profRef); add {
			// Remove annotation profile if it exists
			rKey := routeKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   customProfileClient,
			}
			if profName, ok := rsCfg.MetaData.RouteProfs[rKey]; ok {
				delete(rsCfg.MetaData.RouteProfs, rKey)
				profRef := convertStringToProfileRef(
					profName, customProfileClient, sKey.Namespace)
				rsCfg.Virtual.RemoveProfile(profRef)
			}
			stats.vsUpdated += 1
		}
	}
}

func (appMgr *Manager) setServerSslProfile(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
	route *routeapi.Route,
) string {
	// Check to see if the server ssl profile should validate its peer
	peerCert := peerCertIgnored
	if getBooleanAnnotation(
		route.ObjectMeta.Annotations, f5ServerSslSecureAnnotation, false) {
		peerCert = peerCertRequired
	}

	// Handle the Default for SNI profile
	appMgr.handleServerSNIDefaultProfile(rsCfg, peerCert)

	if prof, ok := route.ObjectMeta.Annotations[f5ServerSslProfileAnnotation]; ok {
		serverSsl, updated := appMgr.handleServerSslProfileAnnotation(
			sKey, rsCfg, route, prof)
		if updated {
			stats.vsUpdated += 1
		}
		return serverSsl
	}

	if "" != route.Spec.TLS.DestinationCACertificate {
		return appMgr.handleDestCACert(sKey, rsCfg, route, peerCert, stats)
	}

	// Use default profile
	serverSsl := ""
	profile, added := appMgr.loadDefaultCert()
	if nil != profile {
		rsCfg.Virtual.AddOrUpdateProfile(*profile)
		serverSsl = joinBigipPath(profile.Partition, profile.Name)
	}
	if added {
		stats.cpUpdated += 1
	}
	return serverSsl
}

func (appMgr *Manager) handleServerSNIDefaultProfile(
	rsCfg *ResourceConfig,
	peerCert string,
) {
	if appMgr.routeConfig.ServerSSL != "" {
		// User has provided a name
		profile := ProfileRef{
			Name:      appMgr.routeConfig.ServerSSL,
			Partition: rsCfg.Virtual.Partition,
			Context:   customProfileServer,
		}
		rsCfg.Virtual.AddOrUpdateProfile(profile)
	} else {
		// No provided name, so we create a default
		skey := secretKey{
			Name:         "default-route-serverssl",
			ResourceName: rsCfg.GetName(),
		}
		appMgr.customProfiles.Lock()
		defer appMgr.customProfiles.Unlock()
		if _, ok := appMgr.customProfiles.profs[skey]; !ok {
			profile := ProfileRef{
				Name:      "default-route-serverssl",
				Partition: rsCfg.Virtual.Partition,
				Context:   customProfileServer,
			}
			// This is just a basic profile, so we don't need all the fields
			cp := NewCustomProfile(profile, "", "", "", true, peerCert,
				makeCertificateFileName(defaultSslServerCAName))
			appMgr.customProfiles.profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profile)
		}
	}
}

func (appMgr *Manager) handleServerSslProfileAnnotation(
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
	route *routeapi.Route,
	prof string,
) (string, bool) {
	if nil != route.Spec.TLS {
		log.Infof("Both serverssl annotation and CA cert provided for Route: %s, "+
			"using annotation.", route.ObjectMeta.Name)
		profRef := makeRouteServerSSLProfileRef(
			rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
		rsCfg.Virtual.RemoveProfile(profRef)
	}
	partition, name := splitBigipPath(prof, false)
	if partition == "" {
		// BIG-IP considers profiles without partitions as being in Common.
		log.Warningf("No partition provided in profile name: %v, assuming Common partition.", prof)
		partition = "Common"
	}
	profile := ProfileRef{
		Name:      name,
		Partition: partition,
		Context:   customProfileServer,
		Namespace: sKey.Namespace,
	}
	updated := false
	if updated = rsCfg.Virtual.AddOrUpdateProfile(profile); updated {
		// Store this annotated profile in the metadata for future reference
		// if it gets deleted.
		rKey := routeKey{
			Name:      route.ObjectMeta.Name,
			Namespace: route.ObjectMeta.Namespace,
			Context:   customProfileServer,
		}
		rsCfg.MetaData.RouteProfs[rKey] = prof
		updated = true
	}
	return joinBigipPath(profile.Partition, profile.Name), updated
}

func (appMgr *Manager) handleDestCACert(
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
	route *routeapi.Route,
	peerCert string,
	stats *vsSyncStats,
) string {
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()

	// Create new SSL server profile with the provided CA Certificate.
	caProfRef := makeRouteServerSSLProfileRef(
		rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
	caProfRef.Name += "-ca"
	caProf := NewCustomProfile(
		caProfRef,
		route.Spec.TLS.DestinationCACertificate,
		"", // no key
		route.Spec.Host,
		false,
		peerCert,
		"self",
	)
	caKey := secretKey{Name: caProfRef.Name}
	caExistingProf, ok := appMgr.customProfiles.profs[caKey]
	if !ok || !reflect.DeepEqual(caProf, caExistingProf) {
		appMgr.customProfiles.profs[caKey] = caProf
		stats.cpUpdated += 1
	}

	svrProfRef := makeRouteServerSSLProfileRef(
		rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
	svrProf := NewCustomProfile(
		svrProfRef,
		route.Spec.TLS.DestinationCACertificate,
		"", // no key
		route.Spec.Host,
		false,
		peerCert,
		makeCertificateFileName(caProfRef.Name),
	)

	skey := secretKey{
		Name:         svrProf.Name,
		ResourceName: rsCfg.GetName(),
	}
	svrExistingProf, ok := appMgr.customProfiles.profs[skey]
	if !ok || !reflect.DeepEqual(svrProf, svrExistingProf) {
		appMgr.customProfiles.profs[skey] = svrProf
		stats.cpUpdated += 1
	}
	if updated := rsCfg.Virtual.AddOrUpdateProfile(svrProfRef); updated {
		// Remove annotation profile if it exists
		rKey := routeKey{
			Name:      route.ObjectMeta.Name,
			Namespace: route.ObjectMeta.Namespace,
			Context:   customProfileServer,
		}
		if prof, ok := rsCfg.MetaData.RouteProfs[rKey]; ok {
			delete(rsCfg.MetaData.RouteProfs, rKey)
			partition, name := splitBigipPath(prof, false)
			rsCfg.Virtual.RemoveProfile(ProfileRef{
				Name:      name,
				Partition: partition,
				Context:   customProfileServer,
			})
		}
		stats.vsUpdated += 1
	}
	return joinBigipPath(svrProfRef.Partition, svrProfRef.Name)
}

// Creates a default SNI profile (if needed) and a new profile from a Secret
func (appMgr *Manager) createSecretSslProfile(
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
	skey := secretKey{
		Name:         fmt.Sprintf("default-clientssl-%s", rsCfg.GetName()),
		ResourceName: rsCfg.GetName(),
	}
	if _, ok := appMgr.customProfiles.profs[skey]; !ok {
		profile := ProfileRef{
			Name:      skey.Name,
			Partition: rsCfg.Virtual.Partition,
			Context:   customProfileClient,
		}
		// This is just a basic profile, so we don't need all the fields
		cp := NewCustomProfile(profile, "", "", "", true, "", "")
		appMgr.customProfiles.profs[skey] = cp
		rsCfg.Virtual.AddOrUpdateProfile(profile)
	}

	// Now add the Ingress profile
	profRef := ProfileRef{
		Name:      secret.ObjectMeta.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   customProfileClient,
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
	skey = secretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	if prof, ok := appMgr.customProfiles.profs[skey]; ok {
		if !reflect.DeepEqual(prof, cp) {
			appMgr.customProfiles.profs[skey] = cp
			return nil, true
		} else {
			return nil, false
		}
	}
	appMgr.customProfiles.profs[skey] = cp
	return nil, false
}

func (appMgr *Manager) deleteUnusedProfiles(
	appInf *appInformer,
	namespace string,
	stats *vsSyncStats,
) {
	// Loop through and delete any profileRefs for Ingress cfgs that are
	// no longer referenced, or have been deleted
	for _, cfg := range appMgr.resources.GetAllResources() {
		if cfg.MetaData.ResourceType != "ingress" {
			continue
		}
		if nil == cfg.Virtual.VirtualAddress ||
			cfg.Virtual.VirtualAddress.BindAddr == "" {
			// Nothing to do for pool-only mode
			continue
		}

		var toRemove []ProfileRef
		ingresses, _ := appInf.ingInformer.GetIndexer().ByIndex(
			"namespace", namespace)
		for _, prof := range cfg.Virtual.Profiles {
			// Don't process profiles that came from an Ingress in a different namespace.
			// We don't want to delete them, since they won't reference an Ingress this time.
			if prof.Namespace != namespace {
				continue
			}
			// Don't process our default profiles (they'll be deleted when the VS is deleted)
			if prof.Name == "http" ||
				prof.Name == "tcp" ||
				prof.Name == fmt.Sprintf("default-clientssl-%s", cfg.GetName()) ||
				prof.Name == "default-route-clientssl" ||
				prof.Name == "default-route-serverssl" {
				continue
			}
			referenced := false
			for _, obj := range ingresses {
				ing := obj.(*v1beta1.Ingress)
				if 0 == len(ing.Spec.TLS) {
					// Nothing to do if no TLS section
					continue
				}
				for _, tls := range ing.Spec.TLS {
					var profName string
					// Trim leading "/" from secret name (if it exists)
					secretName := strings.TrimSpace(strings.TrimPrefix(tls.SecretName, "/"))
					// If another slash remains, then we know a partition is in the name
					if strings.ContainsAny(secretName, "/") {
						profName = fmt.Sprintf("%s/%s", prof.Partition, prof.Name)
					} else {
						profName = prof.Name
					}
					if profName == secretName {
						referenced = true
						// Ingress may reference a secret that no longer exists
						if appMgr.useSecrets {
							_, err := appMgr.kubeClient.Core().
								Secrets(ing.ObjectMeta.Namespace).
								Get(tls.SecretName, metav1.GetOptions{})
							if nil != err && !strings.ContainsAny(secretName, "/") {
								// No secret with this name, and name does not
								// contain "/", meaning it isn't a valid BIG-IP profile
								toRemove = append(toRemove, prof)
							}
						}
					}
				}
				if referenced {
					break
				}
			}
			if !referenced {
				toRemove = append(toRemove, prof)
			}
		}
		for _, prof := range toRemove {
			cfg.Virtual.RemoveProfile(prof)
			stats.cpUpdated += 1
		}
	}

	var found bool
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()

	// Build a map of CA files and maintain a reference count.
	caRefs := make(map[string]int)
	for key, profile := range appMgr.customProfiles.profs {
		if !profile.SNIDefault && profile.CAFile == "self" {
			caKey := makeCertificateFileName(key.Name)
			caRefs[caKey] = 0
		}
	}

	// Now look to delete any created customProfiles
	for key, profile := range appMgr.customProfiles.profs {
		if profile.CAFile == "self" {
			// Don't touch CA profile
			continue
		}
		found = false
		for _, cfg := range appMgr.resources.GetAllResources() {
			if key.ResourceName == cfg.GetName() &&
				cfg.Virtual.ReferencesProfile(profile) {
				found = true
			}
		}
		if !found {
			// Profile is not used
			delete(appMgr.customProfiles.profs, key)
			stats.cpUpdated += 1
		} else if profile.CAFile != "" {
			// Add ref for this profile
			caRefs[profile.CAFile]++
		}
	}
	// Remove CA files that are no longer referenced
	for caKey, refs := range caRefs {
		if refs == 0 {
			delKey := secretKey{Name: extractCertificateName(caKey)}
			delete(appMgr.customProfiles.profs, delKey)
			stats.cpUpdated += 1
		}
	}
}

func (appMgr *Manager) loadDefaultCert() (*ProfileRef, bool) {
	// OpenShift will put the default server SSL cert on each pod. We create a
	// server SSL profile for it and associate it to any reencrypt routes that
	// have not explicitly set a certificate.
	profileName := defaultSslServerCAName
	profile := ProfileRef{
		Name:      profileName,
		Partition: DEFAULT_PARTITION,
		Context:   customProfileServer,
	}
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	skey := secretKey{Name: profileName}
	_, found := appMgr.customProfiles.profs[skey]
	if !found {
		path := "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
		data, err := ioutil.ReadFile(path)
		if nil != err {
			log.Errorf("Unable to load default cluster certificate '%v': %v",
				path, err)
			return nil, false
		}
		appMgr.customProfiles.profs[skey] =
			NewCustomProfile(
				profile,
				string(data),
				"",   // no key
				"",   // no serverName
				true, //
				peerCertDefault,
				"self", // 'self' indicates this file is the CA file
			)
	}
	return &profile, !found
}
