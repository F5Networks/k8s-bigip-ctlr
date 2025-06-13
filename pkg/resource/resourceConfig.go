/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
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

package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	netv1 "k8s.io/api/networking/v1"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"

	routeapi "github.com/openshift/api/route/v1"
	"github.com/xeipuuv/gojsonschema"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// Definition of a Big-IP Virtual Server config
// Most of this comes directly from a ConfigMap, with the exception
// of NodePort and Nodes, which are dynamic
// For more information regarding this structure and data model:
//  f5/schemas/bigip-virtual-server_[version].json

func (v *Virtual) GetProfileCountByContext(context string) int {
	// Valid values of context are 'clientside', serverside', and 'all'.
	// 'all' does not mean all profiles, but profiles that can be used in
	// multiple contexts.

	profCt := 0

	for _, prof := range v.Profiles {
		if prof.Context == context {
			profCt++
		}
	}

	return profCt
}

func (v *Virtual) ReferencesProfile(profile CustomProfile) bool {
	for _, prof := range v.Profiles {
		if prof.Name == profile.Name &&
			prof.Partition == profile.Partition &&
			prof.Context == profile.Context {
			return true
		}
	}
	return false
}

// Adds an IRule reference to a Virtual object
func (v *Virtual) AddIRule(ruleName string) bool {
	for _, irule := range v.IRules {
		if irule == ruleName {
			return false
		}
	}
	v.IRules = append(v.IRules, ruleName)
	return true
}

// Removes an IRule reference from a Virtual object
func (v *Virtual) RemoveIRule(ruleName string) bool {
	for i, irule := range v.IRules {
		if irule == ruleName {
			copy(v.IRules[i:], v.IRules[i+1:])
			v.IRules[len(v.IRules)-1] = ""
			v.IRules = v.IRules[:len(v.IRules)-1]
			return true
		}
	}
	return false
}

func (v *Virtual) ToString() string {
	output, err := json.Marshal(v)
	if nil != err {
		log.Errorf("[RESOURCE] Unable to convert virtual {%+v} to string: %v", v, err)
		return ""
	}
	return string(output)
}

func (slice ProfileRefs) Less(i, j int) bool {
	return ((slice[i].Partition < slice[j].Partition) ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name))
}

func (slice ProfileRefs) Len() int {
	return len(slice)
}

func (slice ProfileRefs) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (v *Virtual) AddOrUpdateProfile(prof ProfileRef) bool {
	// The profiles are maintained as a sorted array.
	// The profiles are maintained as a sorted array.
	keyFunc := func(i int) bool {
		return ((v.Profiles[i].Partition > prof.Partition) ||
			(v.Profiles[i].Partition == prof.Partition &&
				v.Profiles[i].Name >= prof.Name))
	}
	profCt := v.Profiles.Len()
	i := sort.Search(profCt, keyFunc)
	if i < profCt && v.Profiles[i].Partition == prof.Partition &&
		v.Profiles[i].Name == prof.Name {
		// found, look for data changed
		if v.Profiles[i].Context == prof.Context {
			// unchanged
			return false
		}
	} else {
		// Insert into the correct position.
		v.Profiles = append(v.Profiles, ProfileRef{})
		copy(v.Profiles[i+1:], v.Profiles[i:])
	}
	v.Profiles[i] = prof

	return true
}

func (v *Virtual) RemoveProfile(prof ProfileRef) bool {
	// The profiles are maintained as a sorted array.
	keyFunc := func(i int) bool {
		return ((v.Profiles[i].Partition > prof.Partition) ||
			(v.Profiles[i].Partition == prof.Partition &&
				v.Profiles[i].Name >= prof.Name))
	}
	profCt := v.Profiles.Len()
	i := sort.Search(profCt, keyFunc)
	if i < profCt && v.Profiles[i].Partition == prof.Partition &&
		v.Profiles[i].Name == prof.Name {
		// found, remove it and adjust the array.
		profCt -= 1
		copy(v.Profiles[i:], v.Profiles[i+1:])
		v.Profiles[profCt] = ProfileRef{}
		v.Profiles = v.Profiles[:profCt]
		return true
	}
	return false
}

func (v *Virtual) SetVirtualAddress(bindAddr string, port int32, excludeCidr bool) {
	v.Destination = ""
	if bindAddr == "" && port == 0 {
		v.VirtualAddress = nil
	} else {
		v.VirtualAddress = &VirtualAddress{
			BindAddr: bindAddr,
			Port:     port,
		}
		// Validate the IP address, and create the destination
		ip, rd, cidr := Split_ip_with_route_domain_cidr(bindAddr)
		if len(rd) > 0 {
			rd = "%" + rd
		}
		if len(cidr) > 0 && !excludeCidr {
			cidr = "/" + cidr
		} else {
			cidr = ""
		}
		addr := net.ParseIP(ip)
		if nil != addr {
			var format string
			if nil != addr.To4() {
				format = "/%s/%s%s%s:%d"
			} else {
				format = "/%s/%s%s%s.%d"
			}
			v.Destination = fmt.Sprintf(format, v.Partition, ip, cidr, rd, port)
		}
	}
}

// SetVirtualAddressNetMask calculates the netmask from CIDR notation and sets it in virtual server
func (v *Virtual) SetVirtualAddressNetMask(bindAddr string) {
	if !strings.Contains(bindAddr, "/") {
		return
	}
	ipCIDR := strings.Split(bindAddr, "%")
	_, ipNet, err := net.ParseCIDR(ipCIDR[0])
	if err != nil {
		log.Errorf("Error setting netmask for Virtual server with bindAddress: %s : ", bindAddr, err)
		return
	}
	netMask := ipNet.Mask
	if len(netMask) == 4 {
		v.Mask = fmt.Sprintf("%d.%d.%d.%d", netMask[0], netMask[1], netMask[2], netMask[3])
	} else if len(netMask) == 16 {
		v.Mask = fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s", netMask[0:2], netMask[2:4], netMask[4:6], netMask[6:8],
			netMask[8:10], netMask[10:12], netMask[12:14], netMask[14:16])
	} else {
		log.Errorf("Error setting netmask for Virtual server with bindAddress: %s", bindAddr)
	}

}

// format the virtual server name for a ConfigMap

// To handle VS name which start with Number,
// we are prefixing with 'cfgmap_' to avoid errors with bigip.
func FormatConfigMapVSName(cm *v1.ConfigMap) string {
	VSprefix := "cfgmap"
	if _, err := strconv.Atoi(cm.ObjectMeta.Namespace[0:1]); err == nil {
		return fmt.Sprintf("%s_%s_%s", VSprefix, cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
	} else {
		return fmt.Sprintf("%s_%s", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
	}
}

// format the pool name for a ConfigMap
func formatConfigMapPoolName(namespace, cmName, svc string) string {
	return fmt.Sprintf("cfgmap_%s_%s_%s", namespace, cmName, svc)
}

// formats a health monitor name
func FormatMonitorName(poolName, monitorType string) string {
	return poolName + "_0_" + monitorType
}

// format the virtual server name for an Ingress
func FormatIngressVSName(ip string, port int32) string {
	// Strip any bracket characters; replace special characters ". : /"
	// with "-" and "%" with ".", for naming purposes
	ip = strings.Trim(ip, "[]")
	modifySpecialChars := map[string]string{
		".": "-",
		":": "-",
		"/": "-",
		"%": "."}
	SpecialChars := [4]string{".", ":", "/", "%"}
	for _, key := range SpecialChars {
		ip = strings.ReplaceAll(ip, key, modifySpecialChars[key])
	}
	return fmt.Sprintf("ingress_%s_%d", ip, port)
}

// format the pool name for an Ingress
func FormatIngressPoolName(namespace, svc, ingressName, port string) string {
	return fmt.Sprintf("ingress_%s_%s_%s_%s", namespace, ingressName, svc, port)
}

func GetRouteCanonicalServiceName(route *routeapi.Route) string {
	return route.Spec.To.Name
}

type RouteService struct {
	Weight int
	Name   string
}

// return the services associated with a route (names + weight)
func GetRouteServices(route *routeapi.Route) []RouteService {
	numOfSvcs := 1
	if route.Spec.AlternateBackends != nil {
		numOfSvcs += len(route.Spec.AlternateBackends)
	}
	svcs := make([]RouteService, numOfSvcs)

	svcIndex := 0
	if route.Spec.AlternateBackends != nil {
		for _, svc := range route.Spec.AlternateBackends {
			svcs[svcIndex].Name = svc.Name
			svcs[svcIndex].Weight = int(*(svc.Weight))
			svcIndex = svcIndex + 1
		}
	}
	svcs[svcIndex].Name = route.Spec.To.Name
	if route.Spec.To.Weight != nil {
		svcs[svcIndex].Weight = int(*(route.Spec.To.Weight))
	} else {
		// Older versions of openshift do not have a weight field
		// so we will basically ignore it.
		svcs[svcIndex].Weight = 0
	}

	return svcs
}

// return the service names associated with a route
func GetRouteAssociatedRuleNames(route *routeapi.Route) []string {
	var ruleNames []string
	ruleName := FormatRouteRuleName(route)
	ruleNames = append(ruleNames, ruleName)
	// Add whitelist or allow source rules
	if _, ok := route.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
		ruleNames = append(ruleNames, ruleName+"-reset")
	} else if _, ok := route.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
		ruleNames = append(ruleNames, ruleName+"-reset")
	}
	return ruleNames
}

// return the service names associated with a route
func GetRouteServiceNames(route *routeapi.Route) []string {
	svcs := GetRouteServices(route)
	svcNames := make([]string, len(svcs))
	for idx, svc := range svcs {
		svcNames[idx] = svc.Name
	}
	return svcNames
}

// Deletes a whitelist reset rule
func (rsCfg *ResourceConfig) DeleteWhitelistCondition() {
	for _, pol := range rsCfg.Policies {
		for i, rl := range pol.Rules {
			if strings.HasSuffix(rl.Name, "-reset") {
				if !pol.RemoveRuleAt(i) {
					log.Errorf("Error deleting reset rule for %v", pol.Name)
				}
			}
		}
		rsCfg.SetPolicy(pol)
	}
}

// Verify if the service is associated with the route
func ExistsRouteServiceName(route *routeapi.Route, expSvcName string) bool {
	// We don't expect an extensive list, so we're not using a map
	svcs := GetRouteServices(route)
	for _, svc := range svcs {
		if expSvcName == svc.Name {
			return true
		}
	}
	return false
}

// Verify if the service is associated with the route as AlternateBackend
func IsABServiceOfRoute(route *routeapi.Route, expSvcName string) bool {
	for _, svc := range route.Spec.AlternateBackends {
		if expSvcName == svc.Name {
			return true
		}
	}
	return false
}

func IsRouteABDeployment(route *routeapi.Route) bool {
	return route.Spec.AlternateBackends != nil && len(route.Spec.AlternateBackends) > 0
}

// format the pool name for a Route
func FormatRoutePoolName(namespace, svcName string) string {
	return fmt.Sprintf("openshift_%s_%s", namespace, svcName)
}

// format the Rule name for a Route
func FormatRouteRuleName(route *routeapi.Route) string {
	return fmt.Sprintf("openshift_route_%s_%s", route.ObjectMeta.Namespace,
		route.ObjectMeta.Name)
}

// format the client ssl profile name for a Route
func MakeRouteClientSSLProfileRef(partition, namespace, name string) ProfileRef {
	return ProfileRef{
		Partition: partition,
		Name:      fmt.Sprintf("openshift_route_%s_%s-client-ssl", namespace, name),
		Context:   CustomProfileClient,
		Namespace: namespace,
	}
}

// format the server ssl profile name for a Route
func MakeRouteServerSSLProfileRef(partition, namespace, name string) ProfileRef {
	return ProfileRef{
		Partition: partition,
		Name:      fmt.Sprintf("openshift_route_%s_%s-server-ssl", namespace, name),
		Context:   CustomProfileServer,
		Namespace: namespace,
	}
}

func MakeCertificateFileName(partition, name string) string {
	// All certificates are installed to the managed partition
	return JoinBigipPath(partition, name) + ".crt"
}

func ExtractCertificateName(fn string) string {
	// performs the reverse of MakeCertificateFileName
	_, name := SplitBigipPath(fn, false)
	if strings.HasSuffix(name, ".crt") {
		name = name[:len(name)-4]
	}
	return name
}

func FormatIngressSslProfileName(secret string) string {
	profName := strings.TrimSpace(strings.TrimPrefix(secret, "/"))
	parts := strings.Split(profName, "/")
	switch len(parts) {
	case 2:
		profName = fmt.Sprintf("%v/%v", parts[0], parts[1])
	case 1:
		// This is technically supported on the Big-IP, but will fail in the
		// python driver. Issue a warning here for better context.
		log.Warningf("[RESOURCE] TLS secret '%v' does not contain a full path.", secret)
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("[RESOURCE] TLS secret '%v' is formatted incorrectly.", secret)
	}
	return profName
}

func ConvertStringToProfileRef(profileName, context, ns string) ProfileRef {
	profName := strings.TrimSpace(strings.TrimPrefix(profileName, "/"))
	parts := strings.Split(profName, "/")
	profRef := ProfileRef{Context: context, Namespace: ns}
	switch len(parts) {
	case 2:
		profRef.Partition = parts[0]
		profRef.Name = parts[1]
	case 1:
		log.Debugf("[RESOURCE] Partition not provided in profile '%s', using default partition '%s'",
			profileName, DEFAULT_PARTITION)
		profRef.Partition = DEFAULT_PARTITION
		profRef.Name = profileName
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("[RESOURCE] Profile name '%v' is formatted incorrectly.", profileName)
	}
	return profRef
}

// Store of CustomProfiles
type CustomProfileStore struct {
	sync.Mutex
	Profs map[SecretKey]CustomProfile
}

// Contructor for CustomProfiles
func NewCustomProfiles() *CustomProfileStore {
	var cps CustomProfileStore
	cps.Profs = make(map[SecretKey]CustomProfile)
	return &cps
}

// Key is resource name, value is unused (since go doesn't have set objects).
type resourceList map[NameRef]bool

// Key is namespace/servicename/serviceport, value is map of resources.
type resourceKeyMap map[ServiceKey]resourceList

// Key is resource name, value is pointer to config. May be shared.
type ResourceConfigMap map[NameRef]*ResourceConfig

// ObjectDependency identifies a K8s Object
type ObjectDependency struct {
	Kind      string
	Namespace string
	Name      string
	PoolName  string
}

// ObjectDependencies contains each dependency and its use count (usually 1)
type ObjectDependencies map[ObjectDependency]int

// ObjectDependencyMap key is an Ingress or Route and the value is a
// map of other objects it depends on - typically services.
type ObjectDependencyMap map[ObjectDependency]ObjectDependencies

// Map of Resource configs
type Resources struct {
	sync.Mutex
	rm      resourceKeyMap
	RsMap   ResourceConfigMap
	objDeps ObjectDependencyMap
	//Only for ingress. For tracking translate address annotation across multiple ingress for single VS
	//Namespace Key -> VS key -> List of translate address for all ingress sharing same VS
	TranslateAddress map[string]map[NameRef][]string
}

const ServiceDep = "Service"
const RuleDep = "Rule"
const URLDep = "URL-Rewrite-Annotation"
const AppRootDep = "App-Root-Annotation"
const WhitelistDep = "Whitelist-Annotation"

// NewObjectDependencies parses an object and returns a map of its dependencies
func NewObjectDependencies(
	obj interface{},
) (ObjectDependency, ObjectDependencies) {
	var key ObjectDependency
	deps := make(ObjectDependencies)
	switch t := obj.(type) {
	case *routeapi.Route:
		route := obj.(*routeapi.Route)
		key.Kind = "Route"
		key.Namespace = route.ObjectMeta.Namespace
		key.Name = route.ObjectMeta.Name
		dep := ObjectDependency{
			Kind:      route.Spec.To.Kind,
			Namespace: route.ObjectMeta.Namespace,
			Name:      route.Spec.To.Name,
		}
		deps[dep] = 1
		for _, backend := range route.Spec.AlternateBackends {
			dep.Kind = backend.Kind
			dep.Name = backend.Name
			deps[dep]++
		}
		dep = ObjectDependency{
			Kind:      RuleDep,
			Namespace: route.ObjectMeta.Namespace,
			Name:      route.Spec.Host + route.Spec.Path,
		}
		deps[dep]++
		if urlRewrite, ok := route.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      URLDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      getAnnotationRuleNames(urlRewrite, false, route),
			}
			deps[dep]++
		}
		if appRoot, ok := route.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      AppRootDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      getAnnotationRuleNames(appRoot, true, route),
			}
			deps[dep]++
		}
		if whiteList, ok := route.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      WhitelistDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      whiteList,
			}
			deps[dep]++
		} else if whiteList, ok := route.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      WhitelistDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      whiteList,
			}
			deps[dep]++
		}
	case *netv1.Ingress:
		ingress := obj.(*netv1.Ingress)
		key.Kind = "Ingress"
		key.Namespace = ingress.ObjectMeta.Namespace
		key.Name = ingress.ObjectMeta.Name
		if nil != ingress.Spec.DefaultBackend {
			var poolPortString string
			if ingress.Spec.DefaultBackend.Service.Port.Number != 0 {
				poolPortString = fmt.Sprintf("%d", ingress.Spec.DefaultBackend.Service.Port.Number)
			} else {
				poolPortString = ingress.Spec.DefaultBackend.Service.Port.Name
			}
			dep := ObjectDependency{
				Kind:      ServiceDep,
				Namespace: ingress.ObjectMeta.Namespace,
				Name:      ingress.Spec.DefaultBackend.Service.Name,
				PoolName: FormatIngressPoolName(
					ingress.ObjectMeta.Namespace,
					ingress.Spec.DefaultBackend.Service.Name,
					ingress.ObjectMeta.Name,
					poolPortString,
				),
			}
			deps[dep]++
		}
		for _, rule := range ingress.Spec.Rules {
			if nil == rule.IngressRuleValue.HTTP {
				continue
			}
			for _, path := range rule.IngressRuleValue.HTTP.Paths {
				var poolPortString string
				if path.Backend.Service.Port.Number != 0 {
					poolPortString = fmt.Sprintf("%d", path.Backend.Service.Port.Number)
				} else if path.Backend.Service.Port.Name != "" {
					poolPortString = path.Backend.Service.Port.Name
				}
				dep := ObjectDependency{
					Kind:      ServiceDep,
					Namespace: ingress.ObjectMeta.Namespace,
					Name:      path.Backend.Service.Name,
					PoolName: FormatIngressPoolName(
						ingress.ObjectMeta.Namespace,
						path.Backend.Service.Name,
						ingress.ObjectMeta.Name,
						poolPortString,
					),
				}
				deps[dep]++
				dep = ObjectDependency{
					Kind:      RuleDep,
					Namespace: ingress.ObjectMeta.Namespace,
					Name:      rule.Host + path.Path,
				}
				deps[dep]++
				if urlRewrite, ok := ingress.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
					dep = ObjectDependency{
						Kind:      URLDep,
						Namespace: ingress.ObjectMeta.Namespace,
						Name:      getAnnotationRuleNames(urlRewrite, false, ingress),
					}
					deps[dep]++
				}
				if appRoot, ok := ingress.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
					dep = ObjectDependency{
						Kind:      AppRootDep,
						Namespace: ingress.ObjectMeta.Namespace,
						Name:      getAnnotationRuleNames(appRoot, true, ingress),
					}
					deps[dep]++
				}
			}
		}
		if whiteList, ok := ingress.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
			dep := ObjectDependency{
				Kind:      WhitelistDep,
				Namespace: ingress.ObjectMeta.Namespace,
				Name:      whiteList,
			}
			deps[dep]++
		} else if whiteList, ok := ingress.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
			dep := ObjectDependency{
				Kind:      WhitelistDep,
				Namespace: ingress.ObjectMeta.Namespace,
				Name:      whiteList,
			}
			deps[dep]++
		}
	default:
		log.Errorf("[RESOURCE] Unhandled object type: %v", t)
	}
	return key, deps
}

func generateMultiServiceAnnotationV1RuleNames(ing *netv1.Ingress, annotationMap map[string]string, prefix string) string {
	var ruleNames string
	appRoot := strings.HasPrefix(prefix, "app-root")

	for _, rule := range ing.Spec.Rules {
		if nil != rule.IngressRuleValue.HTTP {
			for _, path := range rule.IngressRuleValue.HTTP.Paths {
				var uri string
				if appRoot {
					uri = rule.Host
				} else {
					uri = rule.Host + path.Path
				}
				if targetVal, ok := annotationMap[uri]; ok {
					var nameEnd string
					if appRoot {
						nameEnd = uri + targetVal
					} else {
						nameEnd = uri + "-" + targetVal
					}
					nameEnd = strings.Replace(nameEnd, "/", "_", -1)
					ruleNames += prefix + nameEnd + ","
				}
			}
		}
	}
	ruleNames = strings.TrimSuffix(ruleNames, ",")

	return ruleNames
}

// formats annotation rule names in a comma separated string
func getAnnotationRuleNames(oldName string, isAppRoot bool, obj interface{}) string {
	var ruleNames string
	switch t := obj.(type) {
	case *routeapi.Route:
		route := obj.(*routeapi.Route)
		annotationMap := ParseAppRootURLRewriteAnnotations(oldName)
		nameEnd := route.Spec.Host + route.Spec.Path + "-" + annotationMap["single"]
		nameEnd = strings.Replace(nameEnd, "/", "_", -1)
		if isAppRoot {
			ruleNames = appRootRedirectRulePrefix + nameEnd
			ruleNames += "," + appRootForwardRulePrefix + nameEnd
		} else {
			ruleNames = urlRewriteRulePrefix + nameEnd
		}
	case *netv1.Ingress:
		ingress := obj.(*netv1.Ingress)
		if ingress.Spec.Rules != nil {
			annotationMap := ParseAppRootURLRewriteAnnotations(oldName)
			if isAppRoot {
				ruleNames = generateMultiServiceAnnotationV1RuleNames(ingress, annotationMap, appRootRedirectRulePrefix)
				ruleNames += "," + generateMultiServiceAnnotationV1RuleNames(ingress, annotationMap, appRootForwardRulePrefix)
			} else {
				ruleNames = generateMultiServiceAnnotationV1RuleNames(ingress, annotationMap, urlRewriteRulePrefix)
			}
		} else {
			if isAppRoot {
				annotationMap := ParseAppRootURLRewriteAnnotations(oldName)
				nameEnd := "single-service" + "-" + annotationMap["single"]
				ruleNames = appRootRedirectRulePrefix + nameEnd
				ruleNames += "," + appRootForwardRulePrefix + nameEnd
			}
		}
	default:
		log.Errorf("[RESOURCE] Unknown object type: %v", t)
	}
	return ruleNames
}

// RemoveDependency will remove the object dependencies from the rs.objDeps map for given route
func (rs *Resources) RemoveDependency(
	key ObjectDependency,
) {
	rs.Lock()
	defer rs.Unlock()
	if _, ok := rs.objDeps[key]; ok {
		delete(rs.objDeps, key)
	}

}

// UpdatePolicy will keep the rs.RsMap map updated and remove the unwanted rules from policy,
func (rs *Resources) UpdatePolicy(
	rsName NameRef,
	policyName string,
	ruleName string,
) {
	rs.Lock()
	defer rs.Unlock()
	var ruleOffsets []int
	if rsCfg, ok := rs.RsMap[rsName]; ok {
		for policyIndex, policy := range rsCfg.Policies {
			if policy.Name == policyName {
				for i, rule := range policy.Rules {
					if rule.Name == ruleName {
						ruleOffsets = append(ruleOffsets, i)
					}
				}
			}
			// remove the rules from policy
			policy.RemoveRules(ruleOffsets)
			// Update the policy in rsMap
			rs.RsMap[rsName].Policies[policyIndex] = policy
		}
	}
}

// UpdateDependencies will keep the rs.objDeps map updated, and return two
// arrays identifying what has changed - added for dependencies that were
// added, and removed for dependencies that were removed.
func (rs *Resources) UpdateDependencies(
	newKey ObjectDependency,
	newDeps ObjectDependencies,
	lookupFunc func(key ObjectDependency) bool,
) ([]ObjectDependency, []ObjectDependency) {
	rs.Lock()
	defer rs.Unlock()

	// Update dependencies for newKey
	var added, removed []ObjectDependency
	oldDeps, found := rs.objDeps[newKey]
	if found {
		// build list of removed deps
		for oldDep := range oldDeps {
			if _, found = newDeps[oldDep]; !found {
				// If Rule, put at front of list to ensure we unmerge before trying
				// to process any removed annotation rules
				if oldDep.Kind == RuleDep {
					removed = append([]ObjectDependency{oldDep}, removed...)
				} else {
					removed = append(removed, oldDep)
				}
			}
		}
		// build list of added deps
		for newDep := range newDeps {
			if _, found = oldDeps[newDep]; !found {
				added = append(added, newDep)
			}
		}
	} else {
		// all newDeps are adds
		for newDep := range newDeps {
			added = append(added, newDep)
		}
	}
	rs.objDeps[newKey] = newDeps
	// Look for all top level objects that depend on the service being handled
	// by the caller. Remove that top level object if it no longer exists. This
	// happens when a Route or Ingress is deleted.
	for objDepKey, objDepDep := range rs.objDeps {
		// cheeck if the object dependency key is present in the serviceDepKeys
		if shouldRemove := lookupFunc(objDepKey); shouldRemove {
			for dep := range objDepDep {
				// Process the dependencies for removal
				// remove the service dependency in case of ingress, as each ingress has its own pool
				// hence, we should remove the pool if the ingress is removed
				// poolName is set for ingress kind resources
				if dep.Kind == ServiceDep && dep.PoolName != "" {
					removed = append(removed, dep)
				}

				// For routes poolName does not include the port and resource name hence, if routes are sharing the
				// same service, we should not remove the service dependency and pool should be removed only when all routes are removed which shares the same service
				if dep.Kind != ServiceDep {
					// If Rule, put at front of list to ensure we unmerge before trying
					// to process any removed annotation rules
					if dep.Kind == RuleDep {
						removed = append([]ObjectDependency{dep}, removed...)
					} else {
						removed = append(removed, dep)
					}
				}
			}
			// After processing, remove the objDepKey from the map
			delete(rs.objDeps, objDepKey)
		}
	}
	return added, removed
}

// Constructor for Resources
func NewResources() *Resources {
	var rs Resources
	rs.Init()
	return &rs
}

// Receiver to initialize the object.
func (rs *Resources) Init() {
	rs.rm = make(resourceKeyMap)
	rs.RsMap = make(ResourceConfigMap)
	rs.objDeps = make(ObjectDependencyMap)
}

// callback type for ForEach()
type ResourceEnumFunc func(key ServiceKey, cfg *ResourceConfig)

// Add or update a Resource config, identified by key.
func (rs *Resources) Assign(svcKey ServiceKey, nameRef NameRef, cfg *ResourceConfig) {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		rsList = make(resourceList)
		rs.rm[svcKey] = rsList
	}
	rsList[nameRef] = true
	rs.RsMap[nameRef] = cfg
}

func (cfg *ResourceConfig) GetName() string {
	if cfg.MetaData.ResourceType == "iapp" {
		return cfg.IApp.Name
	}
	return cfg.Virtual.Name
}

func (cfg *ResourceConfig) GetPartition() string {
	if cfg.MetaData.ResourceType == "iapp" {
		return cfg.IApp.Partition
	}
	return cfg.Virtual.Partition
}

func (cfg *ResourceConfig) GetNameRef() NameRef {
	return NameRef{
		Name:      cfg.GetName(),
		Partition: cfg.GetPartition(),
	}
}

// Count of all pools (svcKeys) currently stored.
func (rs *Resources) PoolCount() int {
	var pools []Pool
	appendPool := func(rsPools []Pool, p Pool) []Pool {
		for _, rp := range rsPools {
			if rp.Name == p.Name && rp.Partition == p.Partition {
				return rsPools
			}
		}
		return append(rsPools, p)
	}
	for _, cfg := range rs.RsMap {
		for _, pool := range cfg.Pools {
			pools = appendPool(pools, pool)
		}
	}
	return len(pools)
}

// Count of all virtuals currently stored.
func (rs *Resources) VirtualCount() int {
	return len(rs.RsMap)
}

// Count of all configurations for a specific backend.
func (rs *Resources) CountOf(svcKey ServiceKey) int {
	if rsList, ok := rs.rm[svcKey]; ok {
		return len(rsList)
	}
	return 0
}

func (rs *Resources) deleteImpl(
	rsList resourceList,
	rsName NameRef,
	svcKey ServiceKey,
) {
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, svcKey.ServiceName, "parse-error")
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, rsName.Name, "port-not-found")
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, rsName.Name, "service-not-found")
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, rsName.Name, "success")

	// Remove mapping for a backend -> virtual/iapp
	delete(rsList, rsName)
	if len(rsList) == 0 {
		// Remove backend since no virtuals/iapps remain
		delete(rs.rm, svcKey)
	}

	// Look at all service keys to see if another references rsName
	useCt := 0
	for _, otherList := range rs.rm {
		for otherName := range otherList {
			if otherName == rsName {
				// Found one, can't delete this resource yet.
				useCt += 1
				break
			}
		}
	}
	if useCt == 0 {
		delete(rs.RsMap, rsName)
	}
}

// Remove a specific resource configuration.
func (rs *Resources) Delete(svcKey ServiceKey, nameRef NameRef) bool {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		// svcKey not found
		return false
	}
	if nameRef == (NameRef{}) {
		// Delete all resources for svcKey
		for rsName, _ := range rsList {
			rs.deleteImpl(rsList, rsName, svcKey)
		}
		return true
	}
	if _, ok = rsList[nameRef]; ok {
		// Delete specific named resource for svcKey
		rs.deleteImpl(rsList, nameRef, svcKey)
		return true
	}
	return false
}

// Remove a svcKey's reference to a config (pool was removed)
func (rs *Resources) DeleteKeyRef(sKey ServiceKey, nameRef NameRef) bool {
	rs.Lock()
	defer rs.Unlock()
	return rs.DeleteKeyRefLocked(sKey, nameRef)
}

// Remove a svcKey's reference to a config (pool was removed)
func (rs *Resources) DeleteKeyRefLocked(sKey ServiceKey, nameRef NameRef) bool {
	rsList, ok := rs.rm[sKey]
	if !ok {
		// sKey not found
		return false
	}
	if _, ok = rsList[nameRef]; ok {
		delete(rsList, nameRef)
		return true
	}
	return false
}

// Iterate over all configurations, calling the supplied callback with each.
func (rs *Resources) ForEach(f ResourceEnumFunc) {
	for svcKey, rsList := range rs.rm {
		for rsName, _ := range rsList {
			cfg, _ := rs.RsMap[rsName]
			f(svcKey, cfg)
		}
	}
}

// Get a specific Resource cfg
func (rs *Resources) Get(svcKey ServiceKey, nameRef NameRef) (*ResourceConfig, bool) {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		return nil, ok
	}
	_, ok = rsList[nameRef]
	if !ok {
		return nil, ok
	}
	resource, ok := rs.RsMap[nameRef]
	return resource, ok
}

// Get a specific Resource cfg
func (rs *Resources) GetByName(nameRef NameRef) (*ResourceConfig, bool) {
	resource, ok := rs.RsMap[nameRef]
	return resource, ok
}

// Get all configurations for a specific backend
func (rs *Resources) GetAll(svcKey ServiceKey) ResourceConfigs {
	var cfgs ResourceConfigs
	rsList, ok := rs.rm[svcKey]
	if ok {
		for rsKey, _ := range rsList {
			cfgs = append(cfgs, rs.RsMap[rsKey])
		}
	}
	return cfgs
}

// GetPoolCount gets the pool count for a service there is change that a service can be referred by multiple virtuals
func (rs *Resources) GetPoolCount(nameRef NameRef) int {
	if rsCfg, ok := rs.GetByName(nameRef); ok {
		return len(rsCfg.Pools)
	}
	return 0
}

// Get all configurations with a specific name, spanning multiple backends
// This is for multi-service ingress
func (rs *Resources) GetAllWithName(nameRef NameRef) (ResourceConfigs, []ServiceKey) {
	var cfgs ResourceConfigs
	var keys []ServiceKey
	rs.ForEach(func(key ServiceKey, cfg *ResourceConfig) {
		if nameRef == cfg.GetNameRef() {
			cfgs = append(cfgs, cfg)
			keys = append(keys, key)
		}
	})
	return cfgs, keys
}

func SetProfilesForMode(mode string, cfg *ResourceConfig) {
	tcpProf := ProfileRef{
		Partition: "Common",
		Name:      "tcp",
		Context:   CustomProfileAll,
	}
	switch mode {
	case "http":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "http",
				Context:   CustomProfileAll,
			})
		cfg.Virtual.AddOrUpdateProfile(tcpProf)
	case "tcp":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(tcpProf)
	case "udp":
		cfg.Virtual.IpProtocol = "udp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "udp",
				Context:   CustomProfileAll,
			})
	}
}

func SetSourceAddrTranslation(snatPoolName string) SourceAddrTranslation {
	if snatPoolName == "" {
		return SourceAddrTranslation{
			Type: DefaultSourceAddrTranslation,
		}
	}
	return SourceAddrTranslation{
		Type: SnatSourceAddrTranslation,
		Pool: snatPoolName,
	}
}

func ParseAppRootURLRewriteAnnotations(annotation string) map[string]string {
	annotationValMap := make(map[string]string)

	numSeps := strings.Count(annotation, ",")
	numReps := strings.Count(annotation, "=")
	if numSeps > 0 {
		splits := strings.Split(annotation, ",")
		for _, val := range splits {
			if strings.Count(val, "=") != 1 {
				log.Warningf("[RESOURCE] Annotation: %s value: %s not properly formatted should be replace-val=target-val, skipping", annotation, val)
				continue
			}
			split := strings.Split(val, "=")
			annotationValMap[split[0]] = split[1]
		}
	} else if numSeps == 0 && numReps == 1 {
		split := strings.Split(annotation, "=")
		annotationValMap[split[0]] = split[1]
	} else if numSeps == 0 && numReps == 0 {
		annotationValMap["single"] = annotation
	} else {
		log.Warningf("[RESOURCE] Annotation: %s improperly formatted should be single value or comma separated values, not processing", annotation)
	}

	return annotationValMap
}

func ParseWhitelistSourceRangeAnnotations(annotation string) []string {
	var annotationVals []string

	numSeps := strings.Count(annotation, ",")
	if numSeps > 0 {
		splits := strings.Split(annotation, ",")
		for _, val := range splits {
			val = strings.TrimSpace(val)
			_, _, err := net.ParseCIDR(val)
			if err != nil {
				log.Infof("[RESOURCE] Annotation: %s value: %s not properly formatted should be in CIDR format, skipping", annotation, val)
			}
			annotationVals = append(annotationVals, val)
		}
	} else if numSeps == 0 {
		annotationVals = append(annotationVals, annotation)
	} else {
		log.Warningf("[RESOURCE] Annotation: %s improperly formatted should be single value or comma separated values, not processing", annotation)
	}

	return annotationVals
}

const (
	MultiServiceIngressType = iota
	SingleServiceIngressType
	RouteType
)

func ParseAnnotationURL(urlString string) *url.URL {
	if !(strings.HasPrefix(urlString, "http://") || strings.HasPrefix(urlString, "https://")) {
		urlString = "http://" + urlString
	}

	u, err := url.Parse(urlString)
	if err != nil {
		log.Warningf("[RESOURCE] Error parsing url-rewrite url: %s, Error: %v, skipping", urlString, err)
		return nil
	}

	return u
}

func ProcessAppRoot(target, value, poolName string, rsType int) Rules {
	var rules []*Rule
	var redirectConditions []*Condition
	var forwardConditions []*Condition

	targetURL := ParseAnnotationURL(target)
	valueURL := ParseAnnotationURL(value)

	if rsType == MultiServiceIngressType && targetURL.Host == "" {
		return rules
	}
	if rsType == MultiServiceIngressType && targetURL.Path != "" {
		if targetURL.Path != valueURL.Path {
			return rules
		}
	}
	if rsType == RouteType && targetURL.Path != "" {
		return rules
	}
	if valueURL.Host != "" {
		return rules
	}
	if valueURL.Path == "" {
		return rules
	}

	rootCondition := &Condition{
		Name:    "0",
		Equals:  true,
		HTTPURI: true,
		Index:   0,
		Path:    true,
		Request: true,
		Values:  []string{"/"},
	}

	if targetURL.Host != "" {
		redirectConditions = append(redirectConditions, &Condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{targetURL.Host},
		})
		rootCondition.Name = "1"
	}
	redirectConditions = append(redirectConditions, rootCondition)
	redirectAction := &Action{
		Name:      "0",
		HttpReply: true,
		Location:  valueURL.Path,
		Redirect:  true,
		Request:   true,
	}

	var nameEnd string
	if rsType == SingleServiceIngressType {
		nameEnd = "single-service"
	} else {
		nameEnd = target
	}
	nameEnd = strings.Replace(nameEnd, "/", "_", -1)
	rules = append(rules, &Rule{
		Name:       appRootRedirectRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    []*Action{redirectAction},
		Conditions: redirectConditions,
	})

	pathCondition := &Condition{
		Name:    "0",
		Equals:  true,
		HTTPURI: true,
		Index:   0,
		Path:    true,
		Request: true,
		Values:  []string{valueURL.Path},
	}

	if targetURL.Host != "" {
		forwardConditions = append(forwardConditions, &Condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{targetURL.Host},
		})
		pathCondition.Name = "1"
	}
	forwardConditions = append(forwardConditions, pathCondition)
	forwardAction := &Action{
		Forward: true,
		Name:    "0",
		Pool:    poolName,
		Request: true,
	}

	rules = append(rules, &Rule{
		Name:       appRootForwardRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    []*Action{forwardAction},
		Conditions: forwardConditions,
	})

	return rules
}

func ParseRewriteAction(targetUrlPath, valueUrlPath string) string {
	var action string
	if valueUrlPath == "/" {
		action = fmt.Sprintf("tcl:[ expr {[string match [HTTP::uri] %s ] ? [regsub %s [HTTP::uri] / ] : [regsub %s [HTTP::uri] \"\" ] }]", targetUrlPath,
			targetUrlPath, targetUrlPath)
	} else {
		action = fmt.Sprintf("tcl:[regsub %s [HTTP::uri] %s ]", targetUrlPath, valueUrlPath)
	}
	return action
}

func ProcessURLRewrite(target, value string, rsType int) *Rule {
	var actions []*Action
	var conditions []*Condition

	targetURL := ParseAnnotationURL(target)
	valueURL := ParseAnnotationURL(value)

	if rsType == MultiServiceIngressType && targetURL.Host == "" {
		return nil
	}
	if rsType == MultiServiceIngressType && targetURL.Path == "" && valueURL.Path != "" {
		return nil
	}
	if rsType == RouteType && targetURL.Path == "" && valueURL.Path != "" {
		return nil
	}
	if rsType == RouteType && targetURL.Host == "" && valueURL.Host != "" {
		return nil
	}
	if valueURL.Host == "" && valueURL.Path == "" {
		return nil
	}

	if targetURL.Host != "" {
		conditions = append(conditions, &Condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{targetURL.Host},
		})
	}
	if 0 != len(targetURL.EscapedPath()) {
		conditions = append(conditions, createPathSegmentConditions(targetURL)...)
	}

	actionName := 0
	if valueURL.Host != "" {
		actions = append(actions, &Action{
			Name:     fmt.Sprintf("%d", actionName),
			HTTPHost: true,
			Replace:  true,
			Request:  true,
			Value:    valueURL.Host,
		})
		actionName++
	}
	if valueURL.Path != "" {
		if targetURL != nil && targetURL.Path != "" {
			actions = append(actions, &Action{
				Name:    fmt.Sprintf("%d", actionName),
				HTTPURI: true,
				Path:    targetURL.Path,
				Replace: true,
				Request: true,
				Value:   ParseRewriteAction(targetURL.Path, valueURL.Path),
			})
		} else {
			actions = append(actions, &Action{
				Name:    fmt.Sprintf("%d", actionName),
				HTTPURI: true,
				Replace: true,
				Request: true,
				Value:   valueURL.Path,
			})
		}
	}

	if len(actions) == 0 {
		log.Warningf("[RESOURCE] No actions were processed for url-rewrite value %s, skipping", value)
		return nil
	}

	nameEnd := target + "-" + value
	nameEnd = strings.Replace(nameEnd, "/", "_", -1)
	return &Rule{
		Name:       urlRewriteRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    actions,
		Conditions: conditions,
	}
}

// Unmarshal an expected ConfigMap object
func ParseConfigMap(cm *v1.ConfigMap, schemaDBPath, snatPoolName string) (*ResourceConfig, error) {
	var cfg ResourceConfig
	var cfgMap ConfigMap

	if data, ok := cm.Data["data"]; ok {
		err := json.Unmarshal([]byte(data), &cfgMap)
		if nil != err {
			return nil, err
		}
		if schemaName, ok := cm.Data["schema"]; ok {
			// FIXME For now, "f5schemadb" means the schema is local
			// Trim whitespace and embedded quotes
			schemaName = strings.TrimSpace(schemaName)
			schemaName = strings.Trim(schemaName, "\"")
			if strings.HasPrefix(schemaName, schemaIndicator) {
				schemaName = strings.Replace(
					schemaName, schemaIndicator, schemaDBPath, 1)
			}
			// Load the schema
			schemaLoader := gojsonschema.NewReferenceLoader(schemaName)
			schema, err := gojsonschema.NewSchema(schemaLoader)
			if err != nil {
				return &cfg, err
			}
			// Load the ConfigMap data and validate
			dataLoader := gojsonschema.NewStringLoader(data)
			result, err := schema.Validate(dataLoader)
			if err != nil {
				return &cfg, err
			}

			//Check if we care about the partition specified in the configmap
			if cfgMap.VirtualServer.Frontend.Partition != DEFAULT_PARTITION {
				errStr := fmt.Sprintf("The partition '%s' in the ConfigMap does not match '%s' that the controller watches for", cfgMap.VirtualServer.Frontend.Partition, DEFAULT_PARTITION)
				return &cfg, errors.New(errStr)
			}
			if result.Valid() {
				ns := cm.ObjectMeta.Namespace
				copyConfigMap(FormatConfigMapVSName(cm), ns, snatPoolName, &cfg, &cfgMap)

				// Checking for annotation in VS, not iApp
				if cfg.MetaData.ResourceType != "iapp" && cfg.Virtual.VirtualAddress != nil {
					// Precedence to configmap bindAddr if annotation is also set
					if cfg.Virtual.VirtualAddress.BindAddr != "" &&
						cm.ObjectMeta.Annotations[F5VsBindAddrAnnotation] != "" {
						log.Warningf(
							"Both configmap bindAddr and %s annotation are set. "+
								"Choosing configmap's bindAddr...", F5VsBindAddrAnnotation)
					} else if cfg.Virtual.VirtualAddress.BindAddr == "" {
						// Check for IP annotation provided by IPAM system
						if addr, ok := cm.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok == true {
							cfg.Virtual.SetVirtualAddress(addr, cfg.Virtual.VirtualAddress.Port, true)
						}
					}
				}
			} else {
				var errors []string
				for _, desc := range result.Errors() {
					errors = append(errors, desc.String())
				}
				return &cfg, fmt.Errorf("configMap is not valid, errors: %q", errors)
			}
		} else {
			return &cfg, fmt.Errorf("configmap %s does not contain schema key",
				cm.ObjectMeta.Name)
		}
	} else {
		return nil, fmt.Errorf("configmap %s does not contain data key",
			cm.ObjectMeta.Name)
	}

	return &cfg, nil
}

func copyConfigMap(virtualName, ns, snatPoolName string, cfg *ResourceConfig, cfgMap *ConfigMap) {
	cmName := strings.Split(virtualName, "_")[1]
	poolName := formatConfigMapPoolName(ns, cmName, cfgMap.VirtualServer.Backend.ServiceName)
	if cfgMap.VirtualServer.Frontend.IApp == "" {
		// Handle virtual server specific config.
		cfg.MetaData.ResourceType = "configmap"
		cfg.Virtual.Name = virtualName
		cfg.Virtual.Partition = cfgMap.VirtualServer.Frontend.Partition
		cfg.Virtual.Enabled = true
		cfg.Virtual.SourceAddrTranslation = SetSourceAddrTranslation(snatPoolName)
		cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, poolName)

		// If mode not set, use default
		mode := DEFAULT_MODE
		if cfgMap.VirtualServer.Frontend.Mode != "" {
			mode = strings.ToLower(cfgMap.VirtualServer.Frontend.Mode)
		}
		SetProfilesForMode(mode, cfg)

		if nil != cfgMap.VirtualServer.Frontend.VirtualAddress {
			cfg.Virtual.SetVirtualAddress(
				cfgMap.VirtualServer.Frontend.VirtualAddress.BindAddr,
				cfgMap.VirtualServer.Frontend.VirtualAddress.Port,
				true)
		} else {
			// Pool-only
			cfg.Virtual.SetVirtualAddress("", 0, true)
		}
		if nil != cfgMap.VirtualServer.Frontend.SslProfile {
			if len(cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileName) > 0 {
				profRef := ConvertStringToProfileRef(
					cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileName,
					CustomProfileClient, ns)
				cfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				for _, profName := range cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileNames {
					profRef := ConvertStringToProfileRef(profName, CustomProfileClient, ns)
					cfg.Virtual.AddOrUpdateProfile(profRef)
				}
			}
		}
	} else {
		// Handle IApp specific config.
		cfg.MetaData.ResourceType = "iapp"
		cfg.IApp.Name = virtualName
		cfg.IApp.Partition = cfgMap.VirtualServer.Frontend.Partition
		cfg.IApp.IApp = cfgMap.VirtualServer.Frontend.IApp
		cfg.IApp.IAppPoolMemberTable = cfgMap.VirtualServer.Frontend.IAppPoolMemberTable
		cfg.IApp.IAppOptions = cfgMap.VirtualServer.Frontend.IAppOptions
		cfg.IApp.IAppTables = cfgMap.VirtualServer.Frontend.IAppTables
		cfg.IApp.IAppVariables = cfgMap.VirtualServer.Frontend.IAppVariables
		poolName = virtualName
	}

	// If balance not set, use default
	var balance string
	if cfgMap.VirtualServer.Frontend.Balance == "" {
		balance = DEFAULT_BALANCE
	} else {
		balance = cfgMap.VirtualServer.Frontend.Balance
	}
	var monitorNames []string
	for index, mon := range cfgMap.VirtualServer.Backend.HealthMonitors {
		monitor := Monitor{
			// Append the protocol to the monitor names to differentiate them.
			// Also add a monitor index to the name to be consistent with the
			// marathon-bigip-ctlr. Since the monitor names are already unique here,
			// appending a '0' is sufficient.
			Name:      fmt.Sprintf("%s_%d_%s", poolName, index, mon.Protocol),
			Partition: cfgMap.VirtualServer.Frontend.Partition,
			Interval:  mon.Interval,
			Type:      mon.Protocol,
			Send:      mon.Send,
			Recv:      mon.Recv,
			Timeout:   mon.Timeout,
		}
		cfg.Monitors = append(cfg.Monitors, monitor)
		fullName := fmt.Sprintf("/%s/%s",
			cfgMap.VirtualServer.Frontend.Partition, monitor.Name)
		monitorNames = append(monitorNames, fullName)
	}
	pool := Pool{
		Name:         poolName,
		Partition:    cfgMap.VirtualServer.Frontend.Partition,
		Balance:      balance,
		ServiceName:  cfgMap.VirtualServer.Backend.ServiceName,
		ServicePort:  cfgMap.VirtualServer.Backend.ServicePort,
		Members:      nil,
		MonitorNames: monitorNames,
	}
	cfg.Pools = append(cfg.Pools, pool)
}

func IsAnnotationRule(ruleName string) bool {
	if strings.Contains(ruleName, "app-root") || strings.Contains(ruleName, "url-rewrite") {
		return true
	}
	return false
}

// Returns a copy of the resource config metadata
func copyRCMetaData(cfg *ResourceConfig) MetaData {
	metadata := MetaData{
		Active:             cfg.MetaData.Active,
		ResourceType:       cfg.MetaData.ResourceType,
		RouteProfs:         make(map[RouteKey]string),
		DefaultIngressName: cfg.MetaData.DefaultIngressName,
	}
	for k, v := range cfg.MetaData.RouteProfs {
		metadata.RouteProfs[k] = v
	}
	return metadata
}

// Copies from an existing config into our new config
func (rc *ResourceConfig) CopyConfig(cfg *ResourceConfig) {
	// MetaData
	rc.MetaData = copyRCMetaData(cfg)
	// Virtual
	rc.Virtual = cfg.Virtual
	// Profiles
	rc.Virtual.Profiles = make([]ProfileRef, len(cfg.Virtual.Profiles))
	copy(rc.Virtual.Profiles, cfg.Virtual.Profiles)
	// Policies ref
	if cfg.Virtual.Policies != nil {
		rc.Virtual.Policies = make([]NameRef, len(cfg.Virtual.Policies))
		copy(rc.Virtual.Policies, cfg.Virtual.Policies)
	}
	// IRules
	if len(cfg.Virtual.IRules) > 0 {
		rc.Virtual.IRules = make([]string, len(cfg.Virtual.IRules))
		copy(rc.Virtual.IRules, cfg.Virtual.IRules)
	}
	// Pools
	rc.Pools = make(Pools, len(cfg.Pools))
	copy(rc.Pools, cfg.Pools)
	// Pool Members and Monitor Names
	for i, _ := range rc.Pools {
		rc.Pools[i].Members = make([]Member, len(cfg.Pools[i].Members))
		copy(rc.Pools[i].Members, cfg.Pools[i].Members)
		//Dont copy if monitors is nil.
		if len(cfg.Pools[i].MonitorNames) > 0 {
			rc.Pools[i].MonitorNames = make([]string, len(cfg.Pools[i].MonitorNames))
			copy(rc.Pools[i].MonitorNames, cfg.Pools[i].MonitorNames)
		}
	}
	// Monitors
	if len(cfg.Monitors) > 0 {
		rc.Monitors = make(Monitors, len(cfg.Monitors))
		copy(rc.Monitors, cfg.Monitors)
	}
	// Policies
	rc.Policies = make([]Policy, len(cfg.Policies))
	copy(rc.Policies, cfg.Policies)

	for i, _ := range rc.Policies {
		rc.Policies[i].Controls = make([]string, len(cfg.Policies[i].Controls))
		copy(rc.Policies[i].Controls, cfg.Policies[i].Controls)
		rc.Policies[i].Requires = make([]string, len(cfg.Policies[i].Requires))
		copy(rc.Policies[i].Requires, cfg.Policies[i].Requires)

		// Rules
		rc.Policies[i].Rules = make([]*Rule, len(cfg.Policies[i].Rules))
		// Actions and Conditions
		for j, _ := range rc.Policies[i].Rules {
			rc.Policies[i].Rules[j] = &Rule{}
			rc.Policies[i].Rules[j].Actions = make([]*Action, len(cfg.Policies[i].Rules[j].Actions))
			rc.Policies[i].Rules[j].Conditions = make([]*Condition, len(cfg.Policies[i].Rules[j].Conditions))
			for k, _ := range rc.Policies[i].Rules[j].Conditions {
				rc.Policies[i].Rules[j].Conditions[k] = &Condition{}
				rc.Policies[i].Rules[j].Conditions[k].Values =
					make([]string, len(cfg.Policies[i].Rules[j].Conditions[k].Values))
			}
		}
		copy(rc.Policies[i].Rules, cfg.Policies[i].Rules)
		for j, _ := range rc.Policies[i].Rules {
			copy(rc.Policies[i].Rules[j].Actions, cfg.Policies[i].Rules[j].Actions)
			copy(rc.Policies[i].Rules[j].Conditions, cfg.Policies[i].Rules[j].Conditions)
			for k, _ := range rc.Policies[i].Rules[j].Conditions {
				copy(rc.Policies[i].Rules[j].Conditions[k].Values, cfg.Policies[i].Rules[j].Conditions[k].Values)
			}
		}
	}
}

func SetAnnotationRulesForRoute(
	policyName string,
	urlRewriteRule *Rule,
	appRootRules []*Rule,
	rc *ResourceConfig,
	skipUrlRewriteRule bool,
) {
	if len(appRootRules) == 2 {
		rc.AddRuleToPolicy(policyName, appRootRules[0])
		rc.AddRuleToPolicy(policyName, appRootRules[1])
	}
	if urlRewriteRule != nil && skipUrlRewriteRule != true {
		rc.AddRuleToPolicy(policyName, urlRewriteRule)
	}
}

func (rc *ResourceConfig) AddRuleToPolicy(
	policyName string,
	rule *Rule,
) {
	// We currently have at most 1 policy, 'forwarding'
	policy := rc.FindPolicy("forwarding")
	if nil != policy {
		foundMatch := false
		for i, r := range policy.Rules {
			if r.Name == rule.Name && r.FullURI == rule.FullURI {
				// Replace old rule with new rule, but make sure Ordinal is correct.
				foundMatch = true
				rule.Ordinal = r.Ordinal
				policy.Rules[i] = rule
				break
			}
		}
		if !foundMatch {
			// Rule not found, add.
			policy.Rules = append(policy.Rules, rule)
		}
	} else {
		policy = CreatePolicy(Rules{rule}, policyName, rc.Virtual.Partition)
	}
	rc.SetPolicy(*policy)
}

func (rc *ResourceConfig) DeleteRuleFromPolicy(
	policyName string,
	rule *Rule,
	mergedRulesMap map[string]map[string]MergedRuleEntry,
) {
	// We currently have at most 1 policy, 'forwarding'
	policy := rc.FindPolicy("forwarding")
	if nil != policy {
		for i, r := range policy.Rules {
			if r.Name == rule.Name && r.FullURI == rule.FullURI {
				// Remove old rule
				unmerged := rc.UnmergeRule(rule.Name, mergedRulesMap)
				if len(policy.Rules) == 1 && !unmerged {
					rc.RemovePolicy(*policy)
				} else if !unmerged {
					ruleOffsets := []int{i}
					policy.RemoveRules(ruleOffsets)
					rc.SetPolicy(*policy)
				}
				break
			}
		}
	}
}

func (rc *ResourceConfig) SetPolicy(policy Policy) {
	toFind := NameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	found := false
	for _, polName := range rc.Virtual.Policies {
		if toFind == polName {
			found = true
			break
		}
	}
	if !found {
		rc.Virtual.Policies = append(rc.Virtual.Policies, toFind)
	}
	for i, pol := range rc.Policies {
		if pol.Name == policy.Name && pol.Partition == policy.Partition {
			rc.Policies[i] = policy
			return
		}
	}
	rc.Policies = append(rc.Policies, policy)
}

func (rc *ResourceConfig) RemovePolicy(policy Policy) {
	toFind := NameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	for i, polName := range rc.Virtual.Policies {
		if toFind == polName {
			// Remove from array
			copy(rc.Virtual.Policies[i:], rc.Virtual.Policies[i+1:])
			rc.Virtual.Policies[len(rc.Virtual.Policies)-1] = NameRef{}
			rc.Virtual.Policies = rc.Virtual.Policies[:len(rc.Virtual.Policies)-1]
			break
		}
	}
	for i, pol := range rc.Policies {
		if pol.Name == toFind.Name && pol.Partition == toFind.Partition {
			if len(rc.Policies) == 1 {
				// No policies left
				rc.Policies = nil
			} else {
				// Remove from array
				copy(rc.Policies[i:], rc.Policies[i+1:])
				rc.Policies[len(rc.Policies)-1] = Policy{}
				rc.Policies = rc.Policies[:len(rc.Policies)-1]
			}
			return
		}
	}
}

func (rc *ResourceConfig) FindPolicy(controlType string) *Policy {
	for _, pol := range rc.Policies {
		for _, cType := range pol.Controls {
			if cType == controlType {
				return &pol
			}
		}
	}
	return nil
}

func (rc *ResourceConfig) SetMonitor(pool *Pool, monitor Monitor) bool {
	var updated, found bool
	toFind := fmt.Sprintf("/%s/%s", monitor.Partition, monitor.Name)
	for _, name := range pool.MonitorNames {
		if name == toFind {
			found = true
			break
		}
	}

	if !found {
		pool.MonitorNames = append(pool.MonitorNames, toFind)
		updated = true
	}
	for i, mon := range rc.Monitors {
		if mon.Name == monitor.Name && mon.Partition == monitor.Partition {
			if rc.Monitors[i] != monitor {
				rc.Monitors[i] = monitor
				updated = true
			}
			return updated
		}
	}
	rc.Monitors = append(rc.Monitors, monitor)
	return updated
}

func (rc *ResourceConfig) RemoveMonitor(pool string) bool {
	var removed bool
	var monitor string
	for i, pl := range rc.Pools {
		if pl.Name == pool {
			for j, mon := range pl.MonitorNames {
				if strings.Contains(mon, pool) {
					monitor = mon
					if j >= len(pl.MonitorNames)-1 {
						pl.MonitorNames = pl.MonitorNames[:len(pl.MonitorNames)-1]
					} else {
						copy(pl.MonitorNames[j:], pl.MonitorNames[j+1:])
						pl.MonitorNames[len(pl.MonitorNames)-1] = ""
						pl.MonitorNames = pl.MonitorNames[:len(pl.MonitorNames)-1]
					}
					rc.Pools[i].MonitorNames = pl.MonitorNames
					removed = true
					break
				}
			}
		}
	}
	for i, mon := range rc.Monitors {
		if strings.Contains(monitor, mon.Name) {
			if i >= len(rc.Monitors)-1 {
				rc.Monitors = rc.Monitors[:len(rc.Monitors)-1]
			} else {
				copy(rc.Monitors[i:], rc.Monitors[i+1:])
				rc.Monitors[len(rc.Monitors)-1] = Monitor{}
				rc.Monitors = rc.Monitors[:len(rc.Monitors)-1]
			}
			removed = true
			break
		}
	}
	return removed
}

func (rc *ResourceConfig) RemovePool(
	namespace,
	poolName string,
	//appMgr *Manager,
	mergedRulesMap map[string]map[string]MergedRuleEntry,
) (bool, *ServiceKey) {
	var cfgChanged bool
	var svcKey *ServiceKey
	var fullPoolName, resourceName string

	// Delete pool
	for i, pool := range rc.Pools {
		if pool.Name != poolName {
			continue
		}
		svcKey = &ServiceKey{
			Namespace:   namespace,
			ServiceName: pool.ServiceName,
			ServicePort: pool.ServicePort,
		}
		cfgChanged = rc.RemovePoolAt(i)
		break
	}
	fullPoolName = JoinBigipPath(DEFAULT_PARTITION, poolName)

	// Delete forwarding rule for the pool
	policy := rc.FindPolicy("forwarding")
	if nil != policy {
		// Loop through rules to find which one to remove
		ruleOffsets := []int{}
		for i, rule := range policy.Rules {
			if len(rule.Actions) > 0 && rule.Actions[0].Pool == fullPoolName {
				if rc.MetaData.ResourceType == "route" {
					resourceName = strings.Split(rule.Name, "_")[3]
				}
				ruleOffsets = append(ruleOffsets, i)
				unmerged := rc.UnmergeRule(rule.Name, mergedRulesMap)
				// If the next rule is a reset rule, remove that as well
				if len(policy.Rules) > i+1 &&
					strings.HasSuffix(policy.Rules[i+1].Name, "-reset") &&
					policy.Rules[i+1].FullURI == rule.FullURI {
					ruleOffsets = append(ruleOffsets, i+1)
				}
				if unmerged {
					cfgChanged = true
				}
			}
		}
		polChanged := policy.RemoveRules(ruleOffsets)
		// Update or remove the policy
		if 0 == len(policy.Rules) {
			rc.RemovePolicy(*policy)
			cfgChanged = true
		} else if polChanged {
			rc.SetPolicy(*policy)
			cfgChanged = true
		}
	}
	// Delete health monitor for the pool
	rc.RemoveMonitor(poolName)

	// Delete profile (route only)
	if resourceName != "" {
		if rc.MetaData.ResourceType == "route" {
			rc.DeleteRouteProfile(namespace, resourceName)
		}
	}

	return cfgChanged, svcKey
}

func (rc *ResourceConfig) DeleteRouteProfile(namespace, name string) {
	profRef := MakeRouteClientSSLProfileRef(
		rc.Virtual.Partition, namespace, name)
	rc.Virtual.RemoveProfile(profRef)
	serverProfile := MakeRouteServerSSLProfileRef(
		rc.Virtual.Partition, namespace, name)
	rc.Virtual.RemoveProfile(serverProfile)
}

func (rc *ResourceConfig) RemovePoolAt(offset int) bool {
	if offset >= len(rc.Pools) {
		return false
	}
	copy(rc.Pools[offset:], rc.Pools[offset+1:])
	rc.Pools[len(rc.Pools)-1] = Pool{}
	rc.Pools = rc.Pools[:len(rc.Pools)-1]
	return true
}

type MergedRuleEntry struct {
	RuleName       string
	OtherRuleNames []string
	MergedActions  map[string][]*Action
	OriginalRule   *Rule
}

func (rc *ResourceConfig) UnmergeRule(ruleName string, mergedRulesMap map[string]map[string]MergedRuleEntry) bool {
	rsName := rc.GetName()
	if _, ok := mergedRulesMap[rsName]; !ok {
		return false
	}
	if _, ok := mergedRulesMap[rsName][ruleName]; !ok {
		return false
	}
	entry := mergedRulesMap[rsName][ruleName]

	// This rule had other rules merged into it
	if entry.MergedActions != nil {
		// Find the policy and rule for this entry and delete it
		policy := rc.FindPolicy("forwarding")
		for i := range policy.Rules {
			if policy.Rules[i].Name == entry.RuleName {
				policy.Rules = append(policy.Rules[:i], policy.Rules[i+1:]...)
				break
			}
		}

		// Unmerge the rules that were merged with this rule
		for _, mergeeRuleName := range entry.OtherRuleNames {
			mergeeRuleEntry := mergedRulesMap[rsName][mergeeRuleName]
			mergeeRule := mergeeRuleEntry.OriginalRule

			// Add unmerged rule back to policy delete its mergedRulesMap entry
			policy.Rules = append(policy.Rules, mergeeRule)
			delete(mergedRulesMap[rsName], mergeeRuleName)
		}

		// Reset the policy and delete this mergedRulesMap entry and then merge the rules of the reset policy
		rc.SetPolicy(*policy)
		delete(mergedRulesMap[rsName], ruleName)
		rc.MergeRules(mergedRulesMap)
		// This rule was merged into anther rule
	} else {
		mergerRuleName := entry.OtherRuleNames[0]
		mergerRuleEntry := mergedRulesMap[rsName][mergerRuleName]

		// Remove ruleName from merged rule entry
		for i := range mergerRuleEntry.OtherRuleNames {
			if mergerRuleEntry.OtherRuleNames[i] == ruleName {
				mergerRuleEntry.OtherRuleNames = append(mergerRuleEntry.OtherRuleNames[:i], mergerRuleEntry.OtherRuleNames[i+1:]...)
				break
			}
		}

		// Get the merged actions and delete them from the merger entry and delete mergedRulesMap entries
		mergedActions := mergerRuleEntry.MergedActions[ruleName]
		delete(mergerRuleEntry.MergedActions, ruleName)
		if len(mergerRuleEntry.MergedActions) == 0 {
			delete(mergedRulesMap[rsName], mergerRuleName)
		}
		delete(mergedRulesMap[rsName], ruleName)

		// Find the merger rule and delete the merged actions from it
		policy := rc.FindPolicy("forwarding")
		for i := range policy.Rules {
			if policy.Rules[i].Name == mergerRuleName {
				var deletedActionIndices []int

				// Find and these merged actions indices
				for j := range mergedActions {
					for k := range policy.Rules[i].Actions {
						if mergedActions[j] == policy.Rules[i].Actions[k] {
							deletedActionIndices = append(deletedActionIndices, k)
						}
					}
				}

				// Delete these merged actions
				for _, index := range deletedActionIndices {
					policy.Rules[i].Actions = append(policy.Rules[i].Actions[:index], policy.Rules[i].Actions[index+1:]...)
					for j := range deletedActionIndices {
						deletedActionIndices[j]--
					}
				}

				// Delete the merged rule if everything has been unmerged
				if len(policy.Rules[i].Actions) == 0 {
					policy.Rules = append(policy.Rules[:i], policy.Rules[i+1:]...)
				}
				break
			}
		}

		// Delete the policy if its rules are empty
		if len(policy.Rules) == 0 {
			rc.RemovePolicy(*policy)
		} else {
			rc.SetPolicy(*policy)
		}
	}

	// Delete entry from the mergedRulesMap if it is empty for this config
	if len(mergedRulesMap[rsName]) == 0 {
		delete(mergedRulesMap, rsName)
	}
	return true
}

func (rc *ResourceConfig) MergeRules(mergedRulesMap map[string]map[string]MergedRuleEntry) {
	// Single service ingresses do not have rules that need merging
	policy := rc.FindPolicy("forwarding")
	if policy == nil {
		return
	}

	rules := policy.Rules

	var iDeletedRuleIndices []int
	var jDeletedRuleIndices []int

	// Iterate through the rules and compare them to each other
	for i, rl := range rules {
		if strings.HasSuffix(rl.Name, "-reset") {
			continue
		}
		// Do not merge the same rule to itself or to rules that have already been merged
		for j := i + 1; j < len(rules); j++ {
			if strings.HasSuffix(rules[j].Name, "-reset") {
				continue
			}
			numMatches := 0
			numIConditions := len(rules[i].Conditions)
			numJConditions := len(rules[j].Conditions)
			if numIConditions == numJConditions {
				for k := range rules[i].Conditions {
					for l := range rules[j].Conditions {
						kConditionName := rules[i].Conditions[k].Name
						lConditionName := rules[j].Conditions[l].Name
						rules[i].Conditions[k].Name = ""
						rules[j].Conditions[l].Name = ""
						if reflect.DeepEqual(rules[i].Conditions[k], rules[j].Conditions[l]) {
							numMatches++
						}
						rules[i].Conditions[k].Name = kConditionName
						rules[j].Conditions[l].Name = lConditionName
					}
				}

				// Only merge if both sets of conditions match
				if numMatches == numIConditions {
					var mergerEntry MergedRuleEntry
					var mergeeEntry MergedRuleEntry

					iName := rules[i].Name
					jName := rules[j].Name
					// Merge rule[i] into rule[j]
					if ((strings.Contains(iName, "app-root") || strings.Contains(iName, "url-rewrite")) && !(strings.Contains(jName, "app-root") || strings.Contains(jName, "url-rewrite"))) ||
						((strings.Contains(iName, "app-root") || strings.Contains(iName, "url-rewrite")) && (strings.Contains(jName, "app-root") || strings.Contains(jName, "url-rewrite"))) {
						iDeletedRuleIndices = append(iDeletedRuleIndices, i)
						mergerEntry.RuleName = jName
						mergeeEntry.RuleName = iName
						mergerEntry.OtherRuleNames = []string{iName}
						mergeeEntry.OtherRuleNames = []string{jName}
						mergerEntry.OriginalRule = rules[j]
						mergeeEntry.OriginalRule = rules[i]

						// Merge only unique actions
						for k := range rules[i].Actions {
							found := false
							for l := range rules[j].Actions {
								mergeeName := rules[i].Actions[k].Name
								mergerName := rules[j].Actions[l].Name
								rules[i].Actions[k].Name = ""
								rules[j].Actions[l].Name = ""
								if rules[i].Actions[k] == rules[j].Actions[l] {
									found = true
								}
								rules[i].Actions[k].Name = mergeeName
								rules[j].Actions[l].Name = mergerName
							}
							if !found {
								rules[j].Actions = append(rules[j].Actions, rules[i].Actions[k])
								mergerEntry.MergedActions = make(map[string][]*Action)
								mergerEntry.MergedActions[iName] = append(mergerEntry.MergedActions[iName], rules[i].Actions[k])
							}
						}
						// Merge rule[j] into rule[i]
					} else if !(strings.Contains(iName, "app-root") || strings.Contains(iName, "url-rewrite")) && (strings.Contains(jName, "app-root") || strings.Contains(jName, "url-rewrite")) {
						jDeletedRuleIndices = append(jDeletedRuleIndices, j)
						mergerEntry.RuleName = iName
						mergeeEntry.RuleName = jName
						mergerEntry.OtherRuleNames = []string{jName}
						mergeeEntry.OtherRuleNames = []string{iName}
						mergerEntry.OriginalRule = rules[i]
						mergeeEntry.OriginalRule = rules[j]

						// Merge only unique actions
						for k := range rules[j].Actions {
							found := false
							for l := range rules[i].Actions {
								mergeeName := rules[j].Actions[k].Name
								mergerName := rules[i].Actions[l].Name
								rules[j].Actions[k].Name = ""
								rules[i].Actions[l].Name = ""
								if rules[j].Actions[k] == rules[i].Actions[l] {
									found = true
								}
								rules[j].Actions[k].Name = mergeeName
								rules[i].Actions[l].Name = mergerName
							}
							if !found {
								rules[i].Actions = append(rules[i].Actions, rules[j].Actions[k])
								mergerEntry.MergedActions = make(map[string][]*Action)
								mergerEntry.MergedActions[jName] = append(mergerEntry.MergedActions[jName], rules[j].Actions[k])
							}
						}
					}

					Contains := func(slice []string, s string) bool {
						for _, v := range slice {
							if v == s {
								return true
							}
						}
						return false
					}

					// Process entries to the mergedRulesMap
					key := rc.GetName()
					if len(mergerEntry.MergedActions) != 0 {
						// Check if there is are entries for this resource config
						if _, ok := mergedRulesMap[key]; ok {
							// See if there is an entry for the merger
							if entry, ok := mergedRulesMap[key][mergerEntry.RuleName]; ok {
								if !Contains(entry.OtherRuleNames, mergerEntry.OtherRuleNames[0]) {
									mergerEntry.OtherRuleNames = append(mergerEntry.OtherRuleNames, entry.OtherRuleNames...)
								}
								mergerEntry.OriginalRule = entry.OriginalRule

								if len(entry.MergedActions) != 0 {
									for k, v := range entry.MergedActions {
										mergerEntry.MergedActions[k] = v
									}
								}
							}
							// See if there is an entry for the mergee
							if entry, ok := mergedRulesMap[key][mergeeEntry.RuleName]; ok {
								mergeeEntry.OriginalRule = entry.OriginalRule
							}
						} else {
							mergedRulesMap[key] = make(map[string]MergedRuleEntry)
						}

						mergedRulesMap[key][mergerEntry.RuleName] = mergerEntry
						mergedRulesMap[key][mergeeEntry.RuleName] = mergeeEntry
					}
				}
			}
		}
	}

	// Process deleted rule indices and remove duplicates
	deletedRuleIndices := append(iDeletedRuleIndices, jDeletedRuleIndices...)
	sort.Ints(deletedRuleIndices)
	var uniqueDeletedRuleIndices []int
	for i := range deletedRuleIndices {
		if i == 0 {
			uniqueDeletedRuleIndices = append(uniqueDeletedRuleIndices, deletedRuleIndices[i])
		} else {
			found := false
			for j := range uniqueDeletedRuleIndices {
				if uniqueDeletedRuleIndices[j] == deletedRuleIndices[i] {
					found = true
				}
			}
			if !found {
				uniqueDeletedRuleIndices = append(uniqueDeletedRuleIndices, deletedRuleIndices[i])
			}
		}
	}

	// Remove rules that were merged with others
	for _, index := range uniqueDeletedRuleIndices {
		rules = append(rules[:index], rules[index+1:]...)
		for i := range uniqueDeletedRuleIndices {
			uniqueDeletedRuleIndices[i]--
		}
	}

	// Sort the rules
	sort.Sort(sort.Reverse(&rules))

	policy.Rules = rules
	rc.SetPolicy(*policy)
}

func (pol *Policy) RemoveRuleAt(offset int) bool {
	if offset >= len(pol.Rules) {
		return false
	}
	copy(pol.Rules[offset:], pol.Rules[offset+1:])
	pol.Rules[len(pol.Rules)-1] = &Rule{}
	pol.Rules = pol.Rules[:len(pol.Rules)-1]
	return true
}

func (pol *Policy) RemoveRules(ruleOffsets []int) bool {
	polChanged := false
	if len(ruleOffsets) > 0 {
		polChanged = true
		for i := len(ruleOffsets) - 1; i >= 0; i-- {
			pol.RemoveRuleAt(ruleOffsets[i])
		}
		// Must fix the ordinals on the remaining rules
		for i, rule := range pol.Rules {
			rule.Ordinal = i
		}
	}
	return polChanged
}

// Sorting methods for unit testing
func (slice Virtuals) Len() int {
	return len(slice)
}

func (slice Virtuals) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name)
}

func (slice Virtuals) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortVirtuals() {
	sort.Sort(cfg.Virtuals)
	for _, vs := range cfg.Virtuals {
		sort.Sort(vs.Profiles)
	}
}

func (slice Pools) Len() int {
	return len(slice)
}

func (slice Pools) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name)
}

func (slice Pools) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortPools() {
	sort.Sort(cfg.Pools)
}

func (slice Monitors) Len() int {
	return len(slice)
}

func (slice Monitors) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name)
}

func (slice Monitors) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortMonitors() {
	sort.Sort(cfg.Monitors)
}

func (rc *ResourceConfig) SortMonitors() {
	sort.Sort(rc.Monitors)
}

func SplitBigipPath(path string, keepSlash bool) (partition, objName string) {
	cleanPath := strings.TrimLeft(path, "/")
	slashPos := strings.Index(cleanPath, "/")
	if slashPos == -1 {
		// No partition
		objName = cleanPath
	} else {
		// Partition and name
		partition = cleanPath[:slashPos]
		if keepSlash {
			objName = cleanPath[slashPos:]
		} else {
			objName = cleanPath[slashPos+1:]
		}
	}
	return
}

func JoinBigipPath(partition, objName string) string {
	if objName == "" {
		return ""
	}
	if partition == "" {
		return objName
	}
	return fmt.Sprintf("/%s/%s", partition, objName)
}

func NewIRule(name, partition, code string) *IRule {
	return &IRule{
		Name:      name,
		Partition: partition,
		Code:      code,
	}
}

func NewInternalDataGroup(name, partition string) *InternalDataGroup {
	// Need to explicitly initialize Records to an empty array so it isn't nil.
	return &InternalDataGroup{
		Name:      name,
		Partition: partition,
		Records:   []InternalDataGroupRecord{},
	}
}

// DataGroup flattening.
type FlattenConflictFunc func(key, oldVal, newVal string) string

// Internal data group for passthrough routes to map server names to pools.
const PassthroughHostsDgName = "ssl_passthrough_servername_dg"

// Internal data group for reencrypt routes.
const ReencryptHostsDgName = "ssl_reencrypt_servername_dg"

// Internal data group for edge routes.
const EdgeHostsDgName = "ssl_edge_servername_dg"

// Internal data group for reencrypt routes that maps the host name to the
// server ssl profile.
const ReencryptServerSslDgName = "ssl_reencrypt_serverssl_dg"

// Internal data group for edge routes that maps the host name to the
// false. This will help Irule to understand ssl should be disabled
// on serverside.
const EdgeServerSslDgName = "ssl_edge_serverssl_dg"

// Internal data group for https redirect
const HttpsRedirectDgName = "https_redirect_dg"

// Internal data group for ab deployment routes.
const AbDeploymentDgName = "ab_deployment_dg"

var groupFlattenFuncMap = map[string]FlattenConflictFunc{
	PassthroughHostsDgName:   flattenConflictWarn,
	ReencryptHostsDgName:     flattenConflictWarn,
	EdgeHostsDgName:          flattenConflictWarn,
	ReencryptServerSslDgName: flattenConflictWarn,
	EdgeServerSslDgName:      flattenConflictWarn,
	HttpsRedirectDgName:      flattenConflictConcat,
	AbDeploymentDgName:       flattenConflictConcat,
}

func flattenConflictConcat(key, oldVal, newVal string) string {
	// Tokenize both values and add to a map to ensure uniqueness
	pathMap := make(map[string]bool)
	for _, token := range strings.Split(oldVal, "|") {
		pathMap[token] = true
	}
	for _, token := range strings.Split(newVal, "|") {
		pathMap[token] = true
	}

	// Convert back to an array
	paths := []string{}
	for path, _ := range pathMap {
		paths = append(paths, path)
	}

	// Sort the paths to have consistent ordering
	sort.Strings(paths)

	// Write back out to a delimited string
	var buf bytes.Buffer
	for i, path := range paths {
		if i > 0 {
			buf.WriteString("|")
		}
		buf.WriteString(path)
	}

	return buf.String()
}

func flattenConflictWarn(key, oldVal, newVal string) string {
	fmt.Printf("Found mismatch for key '%v' old value: '%v' new value: '%v'\n", key, oldVal, newVal)
	return oldVal
}

func (dgnm DataGroupNamespaceMap) FlattenNamespaces() *InternalDataGroup {

	// Try to be efficient in these common cases.
	if len(dgnm) == 0 {
		// No namespaces.
		return nil
	} else if len(dgnm) == 1 {
		// Only 1 namespace, just return its dg - no flattening needed.
		for _, dg := range dgnm {
			return dg
		}
	}

	// Use a map to identify duplicates across namespaces
	var partition, name string
	flatMap := make(map[string]string)
	for _, dg := range dgnm {
		if partition == "" {
			partition = dg.Partition
		}
		if name == "" {
			name = dg.Name
		}
		for _, rec := range dg.Records {
			item, found := flatMap[rec.Name]
			if found {
				if item != rec.Data {
					conflictFunc, ok := groupFlattenFuncMap[dg.Name]
					if !ok {
						log.Warningf("[RESOURCE] No DataGroup conflict handler defined for '%v'",
							dg.Name)
						conflictFunc = flattenConflictWarn
					}
					newVal := conflictFunc(rec.Name, item, rec.Data)
					flatMap[rec.Name] = newVal
				}
			} else {
				flatMap[rec.Name] = rec.Data
			}
		}
	}

	// Create a new datagroup to hold the flattened results
	newDg := InternalDataGroup{
		Partition: partition,
		Name:      name,
	}
	for name, data := range flatMap {
		newDg.AddOrUpdateRecord(name, data)
	}

	return &newDg
}

func (slice InternalDataGroupRecords) Less(i, j int) bool {
	return slice[i].Name < slice[j].Name
}

func (slice InternalDataGroupRecords) Len() int {
	return len(slice)
}

func (slice InternalDataGroupRecords) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (idg *InternalDataGroup) AddOrUpdateRecord(name, data string) bool {
	// The records are maintained as a sorted array.
	nameKeyFunc := func(i int) bool {
		return idg.Records[i].Name >= name
	}
	i := sort.Search(idg.Records.Len(), nameKeyFunc)
	if i < idg.Records.Len() && idg.Records[i].Name == name {
		if idg.Records[i].Data != data {
			// name found with different data, update
			idg.Records[i].Data = data
			return true
		}
		// name found with same data
		return false
	}

	// Insert into the correct position.
	idg.Records = append(idg.Records, InternalDataGroupRecord{})
	copy(idg.Records[i+1:], idg.Records[i:])
	idg.Records[i] = InternalDataGroupRecord{Name: name, Data: data}

	return true
}

func (idg *InternalDataGroup) RemoveRecord(name string) bool {
	// The records are maintained as a sorted array.
	nameKeyFunc := func(i int) bool {
		return idg.Records[i].Name >= name
	}
	nbrRecs := idg.Records.Len()
	i := sort.Search(nbrRecs, nameKeyFunc)
	if i < nbrRecs && idg.Records[i].Name == name {
		// found, remove it and adjust the array.
		nbrRecs -= 1
		copy(idg.Records[i:], idg.Records[i+1:])
		idg.Records[nbrRecs] = InternalDataGroupRecord{}
		idg.Records = idg.Records[:nbrRecs]
		return true
	}
	return false
}

func NewCustomProfile(
	profile ProfileRef,
	cert,
	key,
	serverName string,
	sni bool,
	peerCertMode,
	caFile string,
	chainCA string,
) CustomProfile {
	cp := CustomProfile{
		Name:         profile.Name,
		Partition:    profile.Partition,
		Context:      profile.Context,
		Cert:         cert,
		Key:          key,
		ServerName:   serverName,
		SNIDefault:   sni,
		PeerCertMode: peerCertMode,
		ChainCA:      chainCA,
	}
	if peerCertMode == PeerCertRequired {
		cp.CAFile = caFile
	}
	return cp
}

// GetServicePort returns the port number, for a given port name,
// else, returns the first port found for a Route's service.
func GetServicePort(
	ns string,
	svcName string,
	svcIndexer cache.Indexer,
	portName string,
	rscType string,
) (int32, error) {
	key := ns + "/" + svcName

	obj, found, err := svcIndexer.GetByKey(key)
	if nil != err {
		return 0, fmt.Errorf("Error looking for service '%s': %v", key, err)
	}
	if found {
		svc := obj.(*v1.Service)
		if portName != "" {
			for _, port := range svc.Spec.Ports {
				if port.Name == portName {
					return port.Port, nil
				}
			}
			return 0,
				fmt.Errorf("Could not find service port '%s' on service '%s'", portName, key)
		} else if rscType == ResourceTypeRoute {
			return svc.Spec.Ports[0].Port, nil
		}
	}
	return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
}

// Contains returns whether x Contains y
func Contains(x interface{}, y interface{}) bool {
	if nil == x || nil == y {
		return false
	}

	if reflect.TypeOf(x).Kind() != reflect.Slice {
		return false
	}

	if reflect.TypeOf(x).Elem() != reflect.TypeOf(y) {
		return false
	}

	s := reflect.ValueOf(x)
	for i := 0; i < s.Len(); i++ {
		if reflect.DeepEqual(s.Index(i).Interface(), y) {
			return true
		}
	}

	return false
}

func (r Rules) Len() int { return len(r) }
func (r Rules) Less(i, j int) bool {
	iApprootRedirect := strings.Contains(r[i].Name, "app-root-redirect-rule")
	iApprootForward := strings.Contains(r[i].Name, "app-root-forward-rule")
	iUrlrewrite := strings.Contains(r[i].Name, "url-rewrite-rule")

	jApprootRedirect := strings.Contains(r[j].Name, "app-root-redirect-rule")
	jApprootForward := strings.Contains(r[j].Name, "app-root-forward-rule")
	jUrlrewrite := strings.Contains(r[j].Name, "url-rewrite-rule")

	if iApprootRedirect && !jApprootRedirect {
		return false
	}
	if !iApprootRedirect && jApprootRedirect {
		return true
	}
	if iApprootForward && !jApprootForward {
		return false
	}
	if !iApprootForward && jApprootForward {
		return true
	}
	if iUrlrewrite && !jUrlrewrite {
		return false
	}
	if !iUrlrewrite && jUrlrewrite {
		return true
	}

	if r[i].FullURI == r[j].FullURI {
		if len(r[j].Actions) > 0 && r[j].Actions[0].Reset {
			return false
		}
		return true
	}

	return r[i].FullURI < r[j].FullURI
}
func (r Rules) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
	r[i].Ordinal = i
	r[j].Ordinal = j
}

func createPathSegmentConditions(u *url.URL) []*Condition {
	var c []*Condition
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	segments := strings.Split(path, "/")
	for i, v := range segments {
		c = append(c, &Condition{
			Equals:      true,
			HTTPURI:     true,
			PathSegment: true,
			Name:        strconv.Itoa(i + 1),
			Index:       i + 1,
			Request:     true,
			Values:      []string{v},
		})
	}
	return c
}

func CreateRule(uri, poolName, partition, ruleName string) (*Rule, error) {
	_u := "scheme://" + uri
	_u = strings.TrimSuffix(_u, "/")
	u, err := url.Parse(_u)
	if nil != err {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteRune('/')
	b.WriteString(partition)
	b.WriteRune('/')
	b.WriteString(poolName)

	a := Action{
		Forward: true,
		Name:    "0",
		Pool:    b.String(),
		Request: true,
	}

	var c []*Condition
	if true == strings.HasPrefix(uri, "*.") {
		c = append(c, &Condition{
			EndsWith: true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{strings.TrimPrefix(u.Host, "*")},
		})
	} else if u.Host != "" {
		c = append(c, &Condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{u.Host},
		})
	}
	if 0 != len(u.EscapedPath()) {
		c = append(c, createPathSegmentConditions(u)...)
	}

	rl := Rule{
		Name:       ruleName,
		FullURI:    uri,
		Actions:    []*Action{&a},
		Conditions: c,
	}

	log.Debugf("[RESOURCE] Configured rule: %v", rl)
	return &rl, nil
}

func CreatePolicy(rls Rules, policyName, partition string) *Policy {
	plcy := Policy{
		Controls:  []string{"forwarding"},
		Legacy:    true,
		Name:      policyName,
		Partition: partition,
		Requires:  []string{"http"},
		Rules:     Rules{},
		Strategy:  "/Common/first-match",
	}

	plcy.Rules = rls

	// Check for the existence of the TCP field in the conditions.
	// This would indicate that a whitelist rule is in the policy
	// and that we need to add the "tcp" requirement to the policy.
	requiresTcp := false
	for _, x := range rls {
		for _, c := range x.Conditions {
			if c.Tcp == true {
				requiresTcp = true
			}
		}
	}

	// Add the tcp requirement if needed; indicated by the presence
	// of the TCP field.
	if requiresTcp {
		plcy.Requires = append(plcy.Requires, "tcp")
	}

	log.Debugf("[RESOURCE] Configured policy: %v", plcy)
	return &plcy
}

func (cm *AgentCfgMap) Init(n string, ns string, d string, l map[string]string, annotation string, getEP func(string, string, []interface{}, bool) ([]Member, []map[string]interface{}, error)) {
	cm.Name = n
	cm.Namespace = ns
	cm.Data = d
	cm.Label = l
	cm.Annotation = annotation
	cm.GetEndpoints = getEP
}
