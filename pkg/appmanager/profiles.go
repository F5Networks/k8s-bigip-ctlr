/*-
 * Copyright (c) 2017,2018, F5 Networks, Inc.
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
	"encoding/json"
	"fmt"
	"io/ioutil"
	netv1 "k8s.io/api/networking/v1"
	"strings"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"

	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
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
		profRef := ConvertStringToProfileRef(
			appMgr.routeConfig.ClientSSL, CustomProfileClient, sKey.Namespace)
		rsCfg.Virtual.AddOrUpdateProfile(profRef)
		rKey := RouteKey{
			Name:      route.ObjectMeta.Name,
			Namespace: route.ObjectMeta.Namespace,
			Context:   CustomProfileClient,
		}
		rsCfg.MetaData.RouteProfs[rKey] = appMgr.routeConfig.ClientSSL
	} else {
		// No provided name, so we create a default
		skey := SecretKey{
			Name:         "default-route-clientssl",
			ResourceName: rsCfg.GetName(),
		}
		if _, ok := appMgr.customProfiles.Profs[skey]; !ok {
			profile := ProfileRef{
				Name:      "default-route-clientssl",
				Partition: rsCfg.Virtual.Partition,
				Context:   CustomProfileClient,
			}
			// This is just a basic profile, so we don't need all the fields
			cp := NewCustomProfile(profile, "", "", "", true, "", "", "")
			appMgr.customProfiles.Profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profile)
		}
	}
	// Now handle the profile from the Route.
	// If annotation is set, use that profile instead of Route profile.
	if prof, ok := route.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]; ok {
		var profRef ProfileRef
		if nil != route.Spec.TLS && ("" != route.Spec.TLS.Certificate && "" != route.Spec.TLS.Key) {
			// Delete existing Route profile if it exists
			profRef = MakeRouteClientSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
			rsCfg.Virtual.RemoveProfile(profRef)
		}
		profRef = ConvertStringToProfileRef(prof, CustomProfileClient, sKey.Namespace)
		if add := rsCfg.Virtual.AddOrUpdateProfile(profRef); add {
			// Store this annotated profile in the metadata for future reference
			// if it gets deleted.
			rKey := RouteKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   CustomProfileClient,
			}
			rsCfg.MetaData.RouteProfs[rKey] = prof
			stats.vsUpdated += 1
		}
	} else {
		profRef := ProfileRef{
			Partition: "Common",
			Name:      "clientssl",
			Context:   CustomProfileClient,
			Namespace: sKey.Namespace,
		}
		// We process the profile from the Route
		if "" != route.Spec.TLS.Certificate && "" != route.Spec.TLS.Key {
			profile := MakeRouteClientSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
			var cp CustomProfile
			if "" != route.Spec.TLS.CACertificate {
				cp = NewCustomProfile(
					profile,
					route.Spec.TLS.Certificate,
					route.Spec.TLS.Key,
					route.Spec.Host,
					false,
					"",                           // peerCertMode
					"",                           // caFile
					route.Spec.TLS.CACertificate, //chainCA
				)
			} else {
				cp = NewCustomProfile(
					profile,
					route.Spec.TLS.Certificate,
					route.Spec.TLS.Key,
					route.Spec.Host,
					false,
					"", // peerCertMode
					"", // caFile
					"",
				)
			}

			skey := SecretKey{
				Name:         cp.Name,
				ResourceName: rsCfg.GetName(),
			}
			if prof, ok := appMgr.customProfiles.Profs[skey]; ok {
				if prof != cp {
					stats.cpUpdated += 1
				}
			}
			appMgr.customProfiles.Profs[skey] = cp
			profRef.Partition = cp.Partition
			profRef.Name = cp.Name
		} else {
			log.Warningf("[CORE] No profile information supplied for Route '%v'", route.ObjectMeta.Name)
			return
		}
		if add := rsCfg.Virtual.AddOrUpdateProfile(profRef); add {
			// Remove annotation profile if it exists
			rKey := RouteKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   CustomProfileClient,
			}
			if profName, ok := rsCfg.MetaData.RouteProfs[rKey]; ok {
				delete(rsCfg.MetaData.RouteProfs, rKey)
				profRef := ConvertStringToProfileRef(
					profName, CustomProfileClient, sKey.Namespace)
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
	peerCert := PeerCertIgnored
	if getBooleanAnnotation(
		route.ObjectMeta.Annotations, F5ServerSslSecureAnnotation, false) {
		peerCert = PeerCertRequired
	}

	// Handle the Default for SNI profile
	appMgr.handleServerSNIDefaultProfile(rsCfg, peerCert, sKey)

	if prof, ok := route.ObjectMeta.Annotations[F5ServerSslProfileAnnotation]; ok {
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
		serverSsl = JoinBigipPath(profile.Partition, profile.Name)
	}
	if added {
		stats.cpUpdated += 1
	}
	return serverSsl
}

func (appMgr *Manager) handleServerSNIDefaultProfile(
	rsCfg *ResourceConfig,
	peerCert string,
	sKey serviceQueueKey,
) {
	if appMgr.routeConfig.ServerSSL != "" {
		// User has provided a name
		prof := ConvertStringToProfileRef(
			appMgr.routeConfig.ServerSSL, CustomProfileServer, sKey.Namespace)
		rsCfg.Virtual.AddOrUpdateProfile(prof)
	} else {
		// No provided name, so we create a default
		skey := SecretKey{
			Name:         "default-route-serverssl",
			ResourceName: rsCfg.GetName(),
		}
		appMgr.customProfiles.Lock()
		defer appMgr.customProfiles.Unlock()
		if _, ok := appMgr.customProfiles.Profs[skey]; !ok {
			profile := ProfileRef{
				Name:      "default-route-serverssl",
				Partition: rsCfg.Virtual.Partition,
				Context:   CustomProfileServer,
			}
			// This is just a basic profile, so we don't need all the fields
			cp := NewCustomProfile(profile, "", "", "", true, peerCert,
				MakeCertificateFileName(rsCfg.Virtual.Partition, DefaultSslServerCAName), "")
			appMgr.customProfiles.Profs[skey] = cp
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
	if nil != route.Spec.TLS && ("" != route.Spec.TLS.Certificate && "" != route.Spec.TLS.Key) {
		log.Infof("[CORE] Both serverssl annotation and CA cert provided for Route: %s, "+
			"using annotation.", route.ObjectMeta.Name)
		profRef := MakeRouteServerSSLProfileRef(
			rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
		rsCfg.Virtual.RemoveProfile(profRef)
	}
	partition, name := SplitBigipPath(prof, false)
	if partition == "" {
		// BIG-IP considers profiles without partitions as being in Common.
		log.Warningf("[CORE] No partition provided in profile name: %v, assuming Common partition.", prof)
		partition = "Common"
	}
	profile := ProfileRef{
		Name:      name,
		Partition: partition,
		Context:   CustomProfileServer,
		Namespace: sKey.Namespace,
	}
	updated := false
	if updated = rsCfg.Virtual.AddOrUpdateProfile(profile); updated {
		// Store this annotated profile in the metadata for future reference
		// if it gets deleted.
		rKey := RouteKey{
			Name:      route.ObjectMeta.Name,
			Namespace: route.ObjectMeta.Namespace,
			Context:   CustomProfileServer,
		}
		rsCfg.MetaData.RouteProfs[rKey] = prof
		updated = true
	}
	return JoinBigipPath(profile.Partition, profile.Name), updated
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

	// Create new SSL server profile with the provided CA Certificate (if required).
	var caFile string
	if peerCert == PeerCertRequired {
		caProfRef := MakeRouteServerSSLProfileRef(
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
			"",
		)
		caKey := SecretKey{Name: caProfRef.Name}
		caExistingProf, ok := appMgr.customProfiles.Profs[caKey]
		if !ok || caProf != caExistingProf {
			appMgr.customProfiles.Profs[caKey] = caProf
			stats.cpUpdated += 1
		}
		caFile = MakeCertificateFileName(rsCfg.Virtual.Partition, caProfRef.Name)
	}

	svrProfRef := MakeRouteServerSSLProfileRef(
		rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
	svrProf := NewCustomProfile(
		svrProfRef,
		route.Spec.TLS.DestinationCACertificate,
		"", // no key
		route.Spec.Host,
		false,
		peerCert,
		caFile,
		"",
	)

	skey := SecretKey{
		Name:         svrProf.Name,
		ResourceName: rsCfg.GetName(),
	}
	svrExistingProf, ok := appMgr.customProfiles.Profs[skey]
	if !ok || svrProf != svrExistingProf {
		appMgr.customProfiles.Profs[skey] = svrProf
		stats.cpUpdated += 1
	}
	if updated := rsCfg.Virtual.AddOrUpdateProfile(svrProfRef); updated {
		// Remove annotation profile if it exists
		rKey := RouteKey{
			Name:      route.ObjectMeta.Name,
			Namespace: route.ObjectMeta.Namespace,
			Context:   CustomProfileServer,
		}
		if prof, ok := rsCfg.MetaData.RouteProfs[rKey]; ok {
			delete(rsCfg.MetaData.RouteProfs, rKey)
			partition, name := SplitBigipPath(prof, false)
			rsCfg.Virtual.RemoveProfile(ProfileRef{
				Name:      name,
				Partition: partition,
				Context:   CustomProfileServer,
			})
		}
		stats.vsUpdated += 1
	}
	return JoinBigipPath(svrProfRef.Partition, svrProfRef.Name)
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
	skey := SecretKey{
		Name:         fmt.Sprintf("default-clientssl-%s", rsCfg.GetName()),
		ResourceName: rsCfg.GetName(),
	}
	sni := ProfileRef{
		Name:      skey.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   CustomProfileClient,
	}
	if _, ok := appMgr.customProfiles.Profs[skey]; !ok {
		// This is just a basic profile, so we don't need all the fields
		cp := NewCustomProfile(sni, "", "", "", true, "", "", "")
		appMgr.customProfiles.Profs[skey] = cp
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
		"",
	)
	skey = SecretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	if prof, ok := appMgr.customProfiles.Profs[skey]; ok {
		if prof != cp {
			appMgr.customProfiles.Profs[skey] = cp
			return nil, true
		} else {
			return nil, false
		}
	}
	appMgr.customProfiles.Profs[skey] = cp
	return nil, false
}

func (appMgr *Manager) deleteUnusedProfiles(
	appInf *appInformer,
	namespace string,
	stats *vsSyncStats,
) {
	var reencryptRouteCount int
	// delete any custom profiles that are no longer referenced
	// Get the list of routes and check if there are any reencrypt
	// routes. If there are no reencrypt routes delete
	// default-route-serverssl profile as it is not used by any
	// virtual server.
	if appInf.routeInformer != nil {
		routes := appInf.routeInformer.GetIndexer().List()
		for _, obj := range routes {
			route := obj.(*routeapi.Route)
			if route.Spec.TLS != nil &&
				route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
				reencryptRouteCount++
			}
		}
	}
	// Loop through and delete any profileRefs for cfgs that are
	// no longer referenced, or have been deleted
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for _, cfg := range appMgr.resources.RsMap {
		if cfg.MetaData.ResourceType == "iapp" {
			continue
		}
		if nil == cfg.Virtual.VirtualAddress ||
			cfg.Virtual.VirtualAddress.BindAddr == "" {
			// Nothing to do for pool-only mode
			continue
		}

		var toRemove []ProfileRef
		for _, prof := range cfg.Virtual.Profiles {

			// If reencryptRouteCount >= 1, don't remove default-route-serverssl
			if reencryptRouteCount >= 1 && prof.Name == "default-route-serverssl" {
				reencryptRouteCount = 0
				continue
			}
			// Don't process profiles that came from a resource in a different namespace.
			// We don't want to delete them, since they won't reference a resource this time.
			if prof.Namespace != namespace && prof.Name != "default-route-serverssl" {
				continue
			}
			// Don't process our default profiles (they'll be deleted when the VS is deleted)
			if prof.Name == "http" || prof.Name == "tcp" ||
				prof.Name == fmt.Sprintf("default-clientssl-%s", cfg.GetName()) ||
				prof.Name == "openshift_route_cluster_default-ca" {
				continue
			}
			// If route clientssl has been given via cli, don't remove it
			if appMgr.routeConfig.ClientSSL != "" {
				_, rtClient := SplitBigipPath(appMgr.routeConfig.ClientSSL, false)
				if prof.Name == rtClient {
					continue
				}
			} else if prof.Name == "default-route-clientssl" {
				continue
			}
			// If route serverssl has been given via cli, don't remove it
			if appMgr.routeConfig.ServerSSL != "" {
				_, rtServer := SplitBigipPath(appMgr.routeConfig.ServerSSL, false)
				if prof.Name == rtServer {
					continue
				}
			}

			referenced := false
			// If a profile in our Virtual is not referenced in any resource, or is a Secret
			// that has been deleted, then we remove that profile from the virtual
			if cfg.MetaData.ResourceType == "configmap" {
				cfgmaps, _ := appInf.cfgMapInformer.GetIndexer().ByIndex(
					"namespace", namespace)
				for _, obj := range cfgmaps {
					cm := obj.(*v1.ConfigMap)
					var cfgMap ConfigMap
					if data, ok := cm.Data["data"]; ok {
						err := json.Unmarshal([]byte(data), &cfgMap)
						if err != nil {
							continue
						}
						var profNames []string
						if nil != cfgMap.VirtualServer.Frontend.SslProfile {
							ssl := cfgMap.VirtualServer.Frontend.SslProfile
							if len(ssl.F5ProfileName) > 0 {
								profNames = append(profNames, ssl.F5ProfileName)
							} else {
								for _, profName := range ssl.F5ProfileNames {
									profNames = append(profNames, profName)
								}
							}
							for _, p := range profNames {
								appMgr.checkProfile(
									prof,
									&toRemove,
									cm.ObjectMeta.Namespace,
									p,
									&referenced,
								)
							}
						}
					}
				}
			} else if cfg.MetaData.ResourceType == "ingress" {
				ingresses, _ := appInf.ingInformer.GetIndexer().ByIndex(
					"namespace", namespace)
				for _, obj := range ingresses {
					//TODO remove the switch case and checkV1beta1Ingress function
					switch obj.(type) {
					case *v1beta1.Ingress:
						ing := obj.(*v1beta1.Ingress)
						if 0 == len(ing.Spec.TLS) {
							// Nothing to do if no TLS section
							continue
						}
						for _, tls := range ing.Spec.TLS {
							appMgr.checkProfile(
								prof,
								&toRemove,
								ing.ObjectMeta.Namespace,
								tls.SecretName,
								&referenced,
							)
						}
						if serverProfile, ok :=
							ing.ObjectMeta.Annotations[F5ServerSslProfileAnnotation]; ok == true {
							appMgr.checkProfile(
								prof,
								&toRemove,
								ing.ObjectMeta.Namespace,
								serverProfile,
								&referenced,
							)
						}
					default:
						ing := obj.(*netv1.Ingress)
						if 0 == len(ing.Spec.TLS) && len(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]) == 0 {
							// Nothing to do if no TLS section
							continue
						}
						if len(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]) > 0 {
							if profiles, err := appMgr.getProfilesFromAnnotations(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation], ing); err != nil {
								msg := "Unable to parse bigip clientssl profile JSON array " + ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation] + " : " + err.Error()
								log.Errorf("[CORE] %s", msg)
							} else {
								for _, profile := range profiles {
									referenced = true
									appMgr.checkProfile(
										prof,
										&toRemove,
										ing.ObjectMeta.Namespace,
										fmt.Sprintf("/%v/%v", profile.Partition, profile.Name),
										&referenced,
									)
								}
							}
						} else {
							for _, tls := range ing.Spec.TLS {
								appMgr.checkProfile(
									prof,
									&toRemove,
									ing.ObjectMeta.Namespace,
									tls.SecretName,
									&referenced,
								)
							}
						}

						if serverProfile, ok :=
							ing.ObjectMeta.Annotations[F5ServerSslProfileAnnotation]; ok == true {
							appMgr.checkProfile(
								prof,
								&toRemove,
								ing.ObjectMeta.Namespace,
								serverProfile,
								&referenced,
							)
						}
					}
					if referenced {
						break
					}
				}
			} else if cfg.MetaData.ResourceType == "route" {
				routes, _ := appInf.routeInformer.GetIndexer().ByIndex(
					"namespace", namespace)
				for _, obj := range routes {
					route := obj.(*routeapi.Route)
					if route.Spec.TLS == nil {
						// Nothing to do if no TLS section
						continue
					}
					var cliProf, servProf ProfileRef
					if cli, ok := route.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]; ok {
						cliProf = ConvertStringToProfileRef(
							cli, CustomProfileClient, route.ObjectMeta.Namespace)
					} else {
						cliProf = MakeRouteClientSSLProfileRef(
							cfg.Virtual.Partition, namespace, route.ObjectMeta.Name)
					}
					switch route.Spec.TLS.Termination {
					case routeapi.TLSTerminationReencrypt:
						if serv, ok := route.ObjectMeta.Annotations[F5ServerSslProfileAnnotation]; ok {
							servProf = ConvertStringToProfileRef(
								serv, CustomProfileServer, route.ObjectMeta.Namespace)
						} else {
							servProf = MakeRouteServerSSLProfileRef(
								cfg.Virtual.Partition, namespace, route.ObjectMeta.Name)
						}
					}
					if prof == cliProf || prof == servProf {
						referenced = true
						break
					}
				}
			}
			if !referenced {
				log.Debugf("[CORE] deleteUnusedProfiles Removing profile: %v.",
					prof)
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
	for key, profile := range appMgr.customProfiles.Profs {
		if !profile.SNIDefault && profile.CAFile == "self" {
			caKey := MakeCertificateFileName(profile.Partition, key.Name)
			caRefs[caKey] = 0
		}
	}

	// Now look to delete any created customProfiles
	for key, profile := range appMgr.customProfiles.Profs {
		if profile.CAFile == "self" {
			// Don't touch CA profile
			continue
		}
		found = false
		for _, cfg := range appMgr.resources.RsMap {
			if key.ResourceName == cfg.GetName() &&
				cfg.Virtual.ReferencesProfile(profile) {
				found = true
			}
		}
		if !found {
			// Profile is not used
			delete(appMgr.customProfiles.Profs, key)
			stats.cpUpdated += 1
		} else if profile.CAFile != "" {
			// Add ref for this profile
			caRefs[profile.CAFile]++
		}
	}
	// Remove CA files that are no longer referenced
	for caKey, refs := range caRefs {
		if refs == 0 {
			delKey := SecretKey{Name: ExtractCertificateName(caKey)}
			delete(appMgr.customProfiles.Profs, delKey)
			stats.cpUpdated += 1
		}
	}
}

// Compare a Virtual's profile with a ConfigMap/Ingress profile to see if
// they are the same. If true, the profile is not deleted. If true but the
// profile name is a Secret that no longer exists, then we delete the profile
func (appMgr *Manager) checkProfile(
	prof ProfileRef,
	toRemove *[]ProfileRef,
	namespace,
	testName string,
	referenced *bool,
) {
	var profName string
	// Trim leading "/" from secret name (if it exists)
	secretName := strings.TrimSpace(strings.TrimPrefix(testName, "/"))
	// If another slash remains, then we know a partition is in the name
	if strings.ContainsAny(secretName, "/") {
		profName = fmt.Sprintf("%s/%s", prof.Partition, prof.Name)
	} else {
		profName = prof.Name
	}

	if profName == secretName {
		*referenced = true
		// May reference a secret that no longer exists
		if appMgr.useSecrets {
			secret := appMgr.rsrcSSLCtxt[testName]
			if secret == nil && !strings.ContainsAny(secretName, "/") {
				// No secret with this name, and name does not
				// contain "/", meaning it isn't a valid BIG-IP profile
				*toRemove = append(*toRemove, prof)
			}
		}
	}
}

func (appMgr *Manager) loadDefaultCert() (*ProfileRef, bool) {
	// OpenShift will put the default server SSL cert on each pod. We create a
	// server SSL profile for it and associate it to any reencrypt routes that
	// have not explicitly set a certificate.
	profileName := DefaultSslServerCAName
	profile := ProfileRef{
		Name:      profileName,
		Partition: DEFAULT_PARTITION,
		Context:   CustomProfileServer,
	}
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	skey := SecretKey{Name: profileName}
	_, found := appMgr.customProfiles.Profs[skey]
	if !found {
		path := "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
		data, err := ioutil.ReadFile(path)
		if nil != err {
			log.Errorf("[CORE] Unable to load default cluster certificate '%v': %v",
				path, err)
			return nil, false
		}
		appMgr.customProfiles.Profs[skey] =
			NewCustomProfile(
				profile,
				string(data),
				"",   // no key
				"",   // no serverName
				true, //
				PeerCertDefault,
				"self", // 'self' indicates this file is the CA file
				"",
			)
	}
	return &profile, !found
}
