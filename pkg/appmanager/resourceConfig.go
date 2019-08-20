/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"github.com/xeipuuv/gojsonschema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
)

// Definition of a Big-IP Virtual Server config
// Most of this comes directly from a ConfigMap, with the exception
// of NodePort and Nodes, which are dynamic
// For more information regarding this structure and data model:
//  f5/schemas/bigip-virtual-server_[version].json

const DEFAULT_MODE string = "tcp"
const DEFAULT_BALANCE string = "round-robin"
const DEFAULT_HTTP_PORT int32 = 80
const DEFAULT_HTTPS_PORT int32 = 443

const urlRewriteRulePrefix = "url-rewrite-rule-"
const appRootForwardRulePrefix = "app-root-forward-rule-"
const appRootRedirectRulePrefix = "app-root-redirect-rule-"

// FIXME: remove this global variable.
var DEFAULT_PARTITION string

// Indicator to use an F5 schema
const schemaIndicator string = "f5schemadb://"

// Constants for CustomProfile.Type as defined in CCCL
const customProfileAll string = "all"
const customProfileClient string = "clientside"
const customProfileServer string = "serverside"

// Constants for CustomProfile.PeerCertMode
const peerCertRequired = "require"
const peerCertIgnored = "ignore"
const peerCertDefault = peerCertIgnored

const defaultSourceAddrTranslation = "automap"
const snatSourceAddrTranslation = "snat"

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
		log.Errorf("Unable to convert virtual {%+v} to string: %v", v, err)
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
		if v.Profiles[i] == prof {
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

func (v *Virtual) SetVirtualAddress(bindAddr string, port int32) {
	v.Destination = ""
	if bindAddr == "" && port == 0 {
		v.VirtualAddress = nil
	} else {
		v.VirtualAddress = &virtualAddress{
			BindAddr: bindAddr,
			Port:     port,
		}
		// Validate the IP address, and create the destination
		ip, rd := split_ip_with_route_domain(bindAddr)
		if len(rd) > 0 {
			rd = "%" + rd
		}
		addr := net.ParseIP(ip)
		if nil != addr {
			var format string
			if nil != addr.To4() {
				format = "/%s/%s%s:%d"
			} else {
				format = "/%s/%s%s.%d"
			}
			v.Destination = fmt.Sprintf(format, v.Partition, ip, rd, port)
		}
	}
}

// format the virtual server name for a ConfigMap

// To handle VS name which start with Number,
// we are prefixing with 'cfgmap_' to avoid errors with bigip.
func formatConfigMapVSName(cm *v1.ConfigMap) string {
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
func formatMonitorName(poolName, monitorType string) string {
	return poolName + "_0_" + monitorType
}

// format the virtual server name for an Ingress
func formatIngressVSName(ip string, port int32) string {
	// Strip any bracket characters; replace special characters ". : /"
	// with "-" and "%" with ".", for naming purposes
	ip = strings.Trim(ip, "[]")
	var replacer = strings.NewReplacer(".", "-", ":", "-", "/", "-", "%", ".")
	ip = replacer.Replace(ip)
	return fmt.Sprintf("ingress_%s_%d", ip, port)
}

// format the pool name for an Ingress
func formatIngressPoolName(namespace, svc string) string {
	return fmt.Sprintf("ingress_%s_%s", namespace, svc)
}

// format the rule name for an Ingress
func formatIngressRuleName(host, path, pool string) string {
	var rule string
	if path == "" {
		rule = fmt.Sprintf("ingress_%s_%s", host, pool)
	} else {
		// Remove the first slash, then replace any subsequent slashes with '_'
		path = strings.TrimPrefix(path, "/")
		path = strings.Replace(path, "/", "_", -1)
		rule = fmt.Sprintf("ingress_%s_%s_%s", host, path, pool)
	}
	return rule
}

func getRouteCanonicalServiceName(route *routeapi.Route) string {
	return route.Spec.To.Name
}

type RouteService struct {
	weight int
	name   string
}

// return the services associated with a route (names + weight)
func getRouteServices(route *routeapi.Route) []RouteService {
	numOfSvcs := 1
	if route.Spec.AlternateBackends != nil {
		numOfSvcs += len(route.Spec.AlternateBackends)
	}
	svcs := make([]RouteService, numOfSvcs)

	svcIndex := 0
	if route.Spec.AlternateBackends != nil {
		for _, svc := range route.Spec.AlternateBackends {
			svcs[svcIndex].name = svc.Name
			svcs[svcIndex].weight = int(*(svc.Weight))
			svcIndex = svcIndex + 1
		}
	}
	svcs[svcIndex].name = route.Spec.To.Name
	if route.Spec.To.Weight != nil {
		svcs[svcIndex].weight = int(*(route.Spec.To.Weight))
	} else {
		// Older versions of openshift do not have a weight field
		// so we will basically ignore it.
		svcs[svcIndex].weight = 0
	}

	return svcs
}

// return the service names associated with a route
func getRouteServiceNames(route *routeapi.Route) []string {
	svcs := getRouteServices(route)
	svcNames := make([]string, len(svcs))
	for idx, svc := range svcs {
		svcNames[idx] = svc.name
	}
	return svcNames
}

// Verify if the service is associated with the route
func existsRouteServiceName(route *routeapi.Route, expSvcName string) bool {
	// We don't expect an extensive list, so we're not using a map
	svcs := getRouteServices(route)
	for _, svc := range svcs {
		if expSvcName == svc.name {
			return true
		}
	}
	return false
}

func isRouteABDeployment(route *routeapi.Route) bool {
	return route.Spec.AlternateBackends != nil && len(route.Spec.AlternateBackends) > 0
}

// format the pool name for a Route
func formatRoutePoolName(namespace, svcName string) string {
	return fmt.Sprintf("openshift_%s_%s", namespace, svcName)
}

// format the Rule name for a Route
func formatRouteRuleName(route *routeapi.Route) string {
	return fmt.Sprintf("openshift_route_%s_%s", route.ObjectMeta.Namespace,
		route.ObjectMeta.Name)
}

// format the client ssl profile name for a Route
func makeRouteClientSSLProfileRef(partition, namespace, name string) ProfileRef {
	return ProfileRef{
		Partition: partition,
		Name:      fmt.Sprintf("openshift_route_%s_%s-client-ssl", namespace, name),
		Context:   customProfileClient,
		Namespace: namespace,
	}
}

// format the server ssl profile name for a Route
func makeRouteServerSSLProfileRef(partition, namespace, name string) ProfileRef {
	return ProfileRef{
		Partition: partition,
		Name:      fmt.Sprintf("openshift_route_%s_%s-server-ssl", namespace, name),
		Context:   customProfileServer,
		Namespace: namespace,
	}
}

func makeCertificateFileName(partition, name string) string {
	// All certificates are installed to the managed partition
	return joinBigipPath(partition, name) + ".crt"
}

func extractCertificateName(fn string) string {
	// performs the reverse of makeCertificateFileName
	_, name := splitBigipPath(fn, false)
	if strings.HasSuffix(name, ".crt") {
		name = name[:len(name)-4]
	}
	return name
}

func formatIngressSslProfileName(secret string) string {
	profName := strings.TrimSpace(strings.TrimPrefix(secret, "/"))
	parts := strings.Split(profName, "/")
	switch len(parts) {
	case 2:
		profName = fmt.Sprintf("%v/%v", parts[0], parts[1])
	case 1:
		// This is technically supported on the Big-IP, but will fail in the
		// python driver. Issue a warning here for better context.
		log.Warningf("TLS secret '%v' does not contain a full path.", secret)
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("TLS secret '%v' is formatted incorrectly.", secret)
	}
	return profName
}

func convertStringToProfileRef(profileName, context, ns string) ProfileRef {
	profName := strings.TrimSpace(strings.TrimPrefix(profileName, "/"))
	parts := strings.Split(profName, "/")
	profRef := ProfileRef{Context: context, Namespace: ns}
	switch len(parts) {
	case 2:
		profRef.Partition = parts[0]
		profRef.Name = parts[1]
	case 1:
		log.Debugf("Partition not provided in profile '%s', using default partition '%s'",
			profileName, DEFAULT_PARTITION)
		profRef.Partition = DEFAULT_PARTITION
		profRef.Name = profileName
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("Profile name '%v' is formatted incorrectly.", profileName)
	}
	return profRef
}

// Store of CustomProfiles
type CustomProfileStore struct {
	sync.Mutex
	profs map[secretKey]CustomProfile
}

// Contructor for CustomProfiles
func NewCustomProfiles() *CustomProfileStore {
	var cps CustomProfileStore
	cps.profs = make(map[secretKey]CustomProfile)
	return &cps
}

// Key is resource name, value is unused (since go doesn't have set objects).
type resourceList map[string]bool

// Key is namespace/servicename/serviceport, value is map of resources.
type resourceKeyMap map[serviceKey]resourceList

// Key is resource name, value is pointer to config. May be shared.
type ResourceConfigMap map[string]*ResourceConfig

// ObjectDependency identifies a K8s Object
type ObjectDependency struct {
	Kind      string
	Namespace string
	Name      string
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
	rsMap   ResourceConfigMap
	objDeps ObjectDependencyMap
}

type ResourceInterface interface {
	Init()
	Assign(key serviceKey, name string, cfg *ResourceConfig)
	PoolCount() int
	VirtualCount() int
	CountOf(key serviceKey) int
	Get(key serviceKey, name string) (*ResourceConfig, bool)
	GetAll(key serviceKey) ResourceConfigs
	GetAllWithName(name string) (ResourceConfigs, []serviceKey)
	GetAllResources() ResourceConfigs
	Delete(key serviceKey, name string) bool
	ForEach(f ResourceEnumFunc)
	DependencyDiff(key ObjectDependency, newDeps ObjectDependencies) ([]ObjectDependency, []ObjectDependency)
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
		if urlRewrite, ok := route.ObjectMeta.Annotations[f5VsURLRewriteAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      URLDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      getAnnotationRuleNames(urlRewrite, false, route),
			}
			deps[dep]++
		}
		if appRoot, ok := route.ObjectMeta.Annotations[f5VsAppRootAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      AppRootDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      getAnnotationRuleNames(appRoot, true, route),
			}
			deps[dep]++
		}
		if whiteList, ok := route.ObjectMeta.Annotations[f5VsWhitelistSourceRangeAnnotation]; ok {
			dep = ObjectDependency{
				Kind:      WhitelistDep,
				Namespace: route.ObjectMeta.Namespace,
				Name:      whiteList,
			}
			deps[dep]++
		}
	case *v1beta1.Ingress:
		ingress := obj.(*v1beta1.Ingress)
		key.Kind = "Ingress"
		key.Namespace = ingress.ObjectMeta.Namespace
		key.Name = ingress.ObjectMeta.Name
		if nil != ingress.Spec.Backend {
			dep := ObjectDependency{
				Kind:      ServiceDep,
				Namespace: ingress.ObjectMeta.Namespace,
				Name:      ingress.Spec.Backend.ServiceName,
			}
			deps[dep]++
		}
		for _, rule := range ingress.Spec.Rules {
			if nil == rule.IngressRuleValue.HTTP {
				continue
			}
			for _, path := range rule.IngressRuleValue.HTTP.Paths {
				dep := ObjectDependency{
					Kind:      ServiceDep,
					Namespace: ingress.ObjectMeta.Namespace,
					Name:      path.Backend.ServiceName,
				}
				deps[dep]++
				dep = ObjectDependency{
					Kind:      RuleDep,
					Namespace: ingress.ObjectMeta.Namespace,
					Name:      rule.Host + path.Path,
				}
				deps[dep]++
				if urlRewrite, ok := ingress.ObjectMeta.Annotations[f5VsURLRewriteAnnotation]; ok {
					dep = ObjectDependency{
						Kind:      URLDep,
						Namespace: ingress.ObjectMeta.Namespace,
						Name:      getAnnotationRuleNames(urlRewrite, false, ingress),
					}
					deps[dep]++
				}
				if appRoot, ok := ingress.ObjectMeta.Annotations[f5VsAppRootAnnotation]; ok {
					dep = ObjectDependency{
						Kind:      AppRootDep,
						Namespace: ingress.ObjectMeta.Namespace,
						Name:      getAnnotationRuleNames(appRoot, true, ingress),
					}
					deps[dep]++
				}
			}
		}
		if whiteList, ok := ingress.ObjectMeta.Annotations[f5VsWhitelistSourceRangeAnnotation]; ok {
			dep := ObjectDependency{
				Kind:      WhitelistDep,
				Namespace: ingress.ObjectMeta.Namespace,
				Name:      whiteList,
			}
			deps[dep]++
		}
	default:
		log.Errorf("Unhandled object type: %v", t)
	}
	return key, deps
}

func generateMultiServiceAnnotationRuleNames(ing *v1beta1.Ingress, annotationMap map[string]string, prefix string) string {
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
		annotationMap := parseAppRootURLRewriteAnnotations(oldName)
		nameEnd := route.Spec.Host + route.Spec.Path + "-" + annotationMap["single"]
		nameEnd = strings.Replace(nameEnd, "/", "_", -1)
		if isAppRoot {
			ruleNames = appRootRedirectRulePrefix + nameEnd
			ruleNames += "," + appRootForwardRulePrefix + nameEnd
		} else {
			ruleNames = urlRewriteRulePrefix + nameEnd
		}
	case *v1beta1.Ingress:
		ingress := obj.(*v1beta1.Ingress)
		if ingress.Spec.Rules != nil {
			annotationMap := parseAppRootURLRewriteAnnotations(oldName)
			if isAppRoot {
				ruleNames = generateMultiServiceAnnotationRuleNames(ingress, annotationMap, appRootRedirectRulePrefix)
				ruleNames += "," + generateMultiServiceAnnotationRuleNames(ingress, annotationMap, appRootForwardRulePrefix)
			} else {
				ruleNames = generateMultiServiceAnnotationRuleNames(ingress, annotationMap, urlRewriteRulePrefix)
			}
		} else {
			if isAppRoot {
				annotationMap := parseAppRootURLRewriteAnnotations(oldName)
				nameEnd := "single-service" + "-" + annotationMap["single"]
				ruleNames = appRootRedirectRulePrefix + nameEnd
				ruleNames += "," + appRootForwardRulePrefix + nameEnd
			}
		}
	default:
		log.Errorf("Unknown object type: %v", t)
	}
	return ruleNames
}

// UpdateDependencies will keep the rs.objDeps map updated, and return two
// arrays identifying what has changed - added for dependencies that were
// added, and removed for dependencies that were removed.
func (rs *Resources) UpdateDependencies(
	newKey ObjectDependency,
	newDeps ObjectDependencies,
	svcDepKey ObjectDependency,
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
		if _, found := objDepDep[svcDepKey]; found {
			shouldRemove := lookupFunc(objDepKey)
			if shouldRemove {
				// Ingress or Route has been deleted, remove it from the map and add deps to removed
				for dep := range rs.objDeps[objDepKey] {
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
				delete(rs.objDeps, objDepKey)
			}
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
	rs.rsMap = make(ResourceConfigMap)
	rs.objDeps = make(ObjectDependencyMap)
}

// callback type for ForEach()
type ResourceEnumFunc func(key serviceKey, cfg *ResourceConfig)

// Add or update a Resource config, identified by key.
func (rs *Resources) Assign(svcKey serviceKey, name string, cfg *ResourceConfig) {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		rsList = make(resourceList)
		rs.rm[svcKey] = rsList
	}
	rsList[name] = true
	rs.rsMap[name] = cfg
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
	cfgs := rs.GetAllResources()
	for _, cfg := range cfgs {
		for _, pool := range cfg.Pools {
			pools = appendPool(pools, pool)
		}
	}
	return len(pools)
}

// Count of all virtuals currently stored.
func (rs *Resources) VirtualCount() int {
	return len(rs.rsMap)
}

// Count of all configurations for a specific backend.
func (rs *Resources) CountOf(svcKey serviceKey) int {
	if rsList, ok := rs.rm[svcKey]; ok {
		return len(rsList)
	}
	return 0
}

func (rs *Resources) deleteImpl(
	rsList resourceList,
	rsName string,
	svcKey serviceKey,
) {
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, svcKey.ServiceName, "parse-error")
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, rsName, "port-not-found")
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, rsName, "service-not-found")
	bigIPPrometheus.MonitoredServices.DeleteLabelValues(svcKey.Namespace, rsName, "success")

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
		delete(rs.rsMap, rsName)
	}
}

// Remove a specific resource configuration.
func (rs *Resources) Delete(svcKey serviceKey, name string) bool {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		// svcKey not found
		return false
	}
	if name == "" {
		// Delete all resources for svcKey
		for rsName, _ := range rsList {
			rs.deleteImpl(rsList, rsName, svcKey)
		}
		return true
	}
	if _, ok = rsList[name]; ok {
		// Delete specific named resource for svcKey
		rs.deleteImpl(rsList, name, svcKey)
		return true
	}
	return false
}

// Remove a svcKey's reference to a config (pool was removed)
func (rs *Resources) DeleteKeyRef(sKey serviceKey, name string) bool {
	rs.Lock()
	defer rs.Unlock()
	return rs.deleteKeyRefLocked(sKey, name)
}

// Remove a svcKey's reference to a config (pool was removed)
func (rs *Resources) deleteKeyRefLocked(sKey serviceKey, name string) bool {
	rsList, ok := rs.rm[sKey]
	if !ok {
		// sKey not found
		return false
	}
	if _, ok = rsList[name]; ok {
		delete(rsList, name)
		return true
	}
	return false
}

// Iterate over all configurations, calling the supplied callback with each.
func (rs *Resources) ForEach(f ResourceEnumFunc) {
	for svcKey, rsList := range rs.rm {
		for rsName, _ := range rsList {
			cfg, _ := rs.rsMap[rsName]
			f(svcKey, cfg)
		}
	}
}

// Get a specific Resource cfg
func (rs *Resources) Get(svcKey serviceKey, name string) (*ResourceConfig, bool) {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		return nil, ok
	}
	_, ok = rsList[name]
	if !ok {
		return nil, ok
	}
	resource, ok := rs.rsMap[name]
	return resource, ok
}

// Get a specific Resource cfg
func (rs *Resources) GetByName(name string) (*ResourceConfig, bool) {
	resource, ok := rs.rsMap[name]
	return resource, ok
}

// Get all configurations for a specific backend
func (rs *Resources) GetAll(svcKey serviceKey) ResourceConfigs {
	var cfgs ResourceConfigs
	rsList, ok := rs.rm[svcKey]
	if ok {
		for rsKey, _ := range rsList {
			cfgs = append(cfgs, rs.rsMap[rsKey])
		}
	}
	return cfgs
}

// Get all configurations with a specific name, spanning multiple backends
// This is for multi-service ingress
func (rs *Resources) GetAllWithName(name string) (ResourceConfigs, []serviceKey) {
	var cfgs ResourceConfigs
	var keys []serviceKey
	rs.ForEach(func(key serviceKey, cfg *ResourceConfig) {
		if name == cfg.Virtual.Name {
			cfgs = append(cfgs, cfg)
			keys = append(keys, key)
		}
	})
	return cfgs, keys
}

func (rs *Resources) GetAllResources() ResourceConfigs {
	var cfgs ResourceConfigs
	for _, cfg := range rs.rsMap {
		cfgs = append(cfgs, cfg)
	}
	return cfgs
}

func setProfilesForMode(mode string, cfg *ResourceConfig) {
	tcpProf := ProfileRef{
		Partition: "Common",
		Name:      "tcp",
		Context:   customProfileAll,
	}
	switch mode {
	case "http":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "http",
				Context:   customProfileAll,
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
				Context:   customProfileAll,
			})
	}
}

func setSourceAddrTranslation(snatPoolName string) SourceAddrTranslation {
	if snatPoolName == "" {
		return SourceAddrTranslation{
			Type: defaultSourceAddrTranslation,
		}
	}
	return SourceAddrTranslation{
		Type: snatSourceAddrTranslation,
		Pool: snatPoolName,
	}
}

func parseAppRootURLRewriteAnnotations(annotation string) map[string]string {
	annotationValMap := make(map[string]string)

	numSeps := strings.Count(annotation, ",")
	numReps := strings.Count(annotation, "=")
	if numSeps > 0 {
		splits := strings.Split(annotation, ",")
		for _, val := range splits {
			if strings.Count(val, "=") != 1 {
				log.Warningf("Annotation: %s value: %s not properly formatted should be replace-val=target-val, skipping", annotation, val)
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
		log.Warningf("Annotation: %s improperly formatted should be single value or comma separated values, not processing", annotation)
	}

	return annotationValMap
}

func parseWhitelistSourceRangeAnnotations(annotation string) []string {
	var annotationVals []string

	numSeps := strings.Count(annotation, ",")
	if numSeps > 0 {
		splits := strings.Split(annotation, ",")
		for _, val := range splits {
			val = strings.TrimSpace(val)
			_, _, err := net.ParseCIDR(val)
			if err != nil {
				log.Infof("Annotation: %s value: %s not properly formatted should be in CIDR format, skipping", annotation, val)
			}
			annotationVals = append(annotationVals, val)
		}
	} else if numSeps == 0 {
		annotationVals = append(annotationVals, annotation)
	} else {
		log.Warningf("Annotation: %s improperly formatted should be single value or comma separated values, not processing", annotation)
	}

	return annotationVals
}

const (
	multiServiceIngressType = iota
	singleServiceIngressType
	routeType
)

func parseAnnotationURL(urlString string) *url.URL {
	if !(strings.HasPrefix(urlString, "http://") || strings.HasPrefix(urlString, "https://")) {
		urlString = "http://" + urlString
	}

	u, err := url.Parse(urlString)
	if err != nil {
		log.Warningf("Error parsing url-rewrite url: %s, Error: %v, skipping", urlString, err)
		return nil
	}

	return u
}

func processAppRoot(target, value, poolName string, rsType int) Rules {
	var rules []*Rule
	var redirectConditions []*condition
	var forwardConditions []*condition

	targetURL := parseAnnotationURL(target)
	valueURL := parseAnnotationURL(value)

	if rsType == multiServiceIngressType && targetURL.Host == "" {
		return rules
	}
	if rsType == multiServiceIngressType && targetURL.Path != "" {
		if targetURL.Path != valueURL.Path {
			return rules
		}
	}
	if rsType == routeType && targetURL.Path != "" {
		return rules
	}
	if valueURL.Host != "" {
		return rules
	}
	if valueURL.Path == "" {
		return rules
	}

	rootCondition := &condition{
		Name:    "0",
		Equals:  true,
		HTTPURI: true,
		Index:   0,
		Path:    true,
		Request: true,
		Values:  []string{"/"},
	}

	if targetURL.Host != "" {
		redirectConditions = append(redirectConditions, &condition{
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
	redirectAction := &action{
		Name:      "0",
		HttpReply: true,
		Location:  valueURL.Path,
		Redirect:  true,
		Request:   true,
	}

	var nameEnd string
	if rsType == singleServiceIngressType {
		nameEnd = "single-service"
	} else {
		nameEnd = target
	}
	nameEnd = strings.Replace(nameEnd, "/", "_", -1)
	rules = append(rules, &Rule{
		Name:       appRootRedirectRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    []*action{redirectAction},
		Conditions: redirectConditions,
	})

	pathCondition := &condition{
		Name:    "0",
		Equals:  true,
		HTTPURI: true,
		Index:   0,
		Path:    true,
		Request: true,
		Values:  []string{valueURL.Path},
	}

	if targetURL.Host != "" {
		forwardConditions = append(forwardConditions, &condition{
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
	forwardAction := &action{
		Forward: true,
		Name:    "0",
		Pool:    poolName,
		Request: true,
	}

	rules = append(rules, &Rule{
		Name:       appRootForwardRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    []*action{forwardAction},
		Conditions: forwardConditions,
	})

	return rules
}

func processURLRewrite(target, value string, rsType int) *Rule {
	var actions []*action
	var conditions []*condition

	targetURL := parseAnnotationURL(target)
	valueURL := parseAnnotationURL(value)

	if rsType == multiServiceIngressType && targetURL.Host == "" {
		return nil
	}
	if rsType == multiServiceIngressType && targetURL.Path == "" && valueURL.Path != "" {
		return nil
	}
	if rsType == routeType && targetURL.Path == "" && valueURL.Path != "" {
		return nil
	}
	if rsType == routeType && targetURL.Host == "" && valueURL.Host != "" {
		return nil
	}
	if valueURL.Host == "" && valueURL.Path == "" {
		return nil
	}

	if targetURL.Host != "" {
		conditions = append(conditions, &condition{
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
		actions = append(actions, &action{
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
			actions = append(actions, &action{
				Name:    fmt.Sprintf("%d", actionName),
				HTTPURI: true,
				Path:    targetURL.Path,
				Replace: true,
				Request: true,
				Value:   valueURL.Path,
			})
		} else {
			actions = append(actions, &action{
				Name:    fmt.Sprintf("%d", actionName),
				HTTPURI: true,
				Replace: true,
				Request: true,
				Value:   valueURL.Path,
			})
		}
	}

	if len(actions) == 0 {
		log.Warningf("No actions were processed for url-rewrite value %s, skipping", value)
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
func parseConfigMap(cm *v1.ConfigMap, schemaDBPath, snatPoolName string) (*ResourceConfig, error) {
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
				copyConfigMap(formatConfigMapVSName(cm), ns, snatPoolName, &cfg, &cfgMap)

				// Checking for annotation in VS, not iApp
				if cfg.MetaData.ResourceType != "iapp" && cfg.Virtual.VirtualAddress != nil {
					// Precedence to configmap bindAddr if annotation is also set
					if cfg.Virtual.VirtualAddress.BindAddr != "" &&
						cm.ObjectMeta.Annotations[f5VsBindAddrAnnotation] != "" {
						log.Warningf(
							"Both configmap bindAddr and %s annotation are set. "+
								"Choosing configmap's bindAddr...", f5VsBindAddrAnnotation)
					} else if cfg.Virtual.VirtualAddress.BindAddr == "" {
						// Check for IP annotation provided by IPAM system
						if addr, ok := cm.ObjectMeta.Annotations[f5VsBindAddrAnnotation]; ok == true {
							cfg.Virtual.SetVirtualAddress(addr, cfg.Virtual.VirtualAddress.Port)
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
		cfg.Virtual.SourceAddrTranslation = setSourceAddrTranslation(snatPoolName)
		cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, poolName)

		// If mode not set, use default
		mode := DEFAULT_MODE
		if cfgMap.VirtualServer.Frontend.Mode != "" {
			mode = strings.ToLower(cfgMap.VirtualServer.Frontend.Mode)
		}
		setProfilesForMode(mode, cfg)

		if nil != cfgMap.VirtualServer.Frontend.VirtualAddress {
			cfg.Virtual.SetVirtualAddress(
				cfgMap.VirtualServer.Frontend.VirtualAddress.BindAddr,
				cfgMap.VirtualServer.Frontend.VirtualAddress.Port)
		} else {
			// Pool-only
			cfg.Virtual.SetVirtualAddress("", 0)
		}
		if nil != cfgMap.VirtualServer.Frontend.SslProfile {
			if len(cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileName) > 0 {
				profRef := convertStringToProfileRef(
					cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileName,
					customProfileClient, ns)
				cfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				for _, profName := range cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileNames {
					profRef := convertStringToProfileRef(profName, customProfileClient, ns)
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

func isAnnotationRule(ruleName string) bool {
	if strings.Contains(ruleName, "app-root") || strings.Contains(ruleName, "url-rewrite") {
		return true
	}
	return false
}

// Create a ResourceConfig based on an Ingress resource config
func (appMgr *Manager) createRSConfigFromIngress(
	ing *v1beta1.Ingress,
	resources *Resources,
	ns string,
	svcIndexer cache.Indexer,
	pStruct portStruct,
	defaultIP,
	snatPoolName string,
) *ResourceConfig {
	if class, ok := ing.ObjectMeta.Annotations[k8sIngressClass]; ok == true {
		if class != "f5" {
			return nil
		}
	}

	var cfg ResourceConfig
	var balance string
	if bal, ok := ing.ObjectMeta.Annotations[f5VsBalanceAnnotation]; ok == true {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	if partition, ok := ing.ObjectMeta.Annotations[f5VsPartitionAnnotation]; ok == true {
		cfg.Virtual.Partition = partition
	} else {
		cfg.Virtual.Partition = DEFAULT_PARTITION
	}

	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[f5VsBindAddrAnnotation]; ok == true {
		if addr == "controller-default" {
			bindAddr = defaultIP
		} else {
			bindAddr = addr
		}
	}
	cfg.Virtual.Name = formatIngressVSName(bindAddr, pStruct.port)

	// Handle url-rewrite annotation
	var urlRewriteMap map[string]string
	if urlRewrite, ok := ing.ObjectMeta.Annotations[f5VsURLRewriteAnnotation]; ok {
		urlRewriteMap = parseAppRootURLRewriteAnnotations(urlRewrite)
	}

	// Handle whitelist-source-range annotation
	var whitelistSourceRanges []string
	if sourceRange, ok := ing.ObjectMeta.Annotations[f5VsWhitelistSourceRangeAnnotation]; ok {
		whitelistSourceRanges = parseWhitelistSourceRangeAnnotations(sourceRange)
	}

	// Handle app-root annotation
	var appRootMap map[string]string
	if appRoot, ok := ing.ObjectMeta.Annotations[f5VsAppRootAnnotation]; ok {
		appRootMap = parseAppRootURLRewriteAnnotations(appRoot)
	}

	// Create our pools and policy/rules based on the Ingress
	var pools Pools
	var plcy *Policy
	var rules *Rules
	var ssPoolName string

	urlRewriteRefs := make(map[string]string)
	appRootRefs := make(map[string][]string)
	if nil != ing.Spec.Rules { //multi-service
		for _, rule := range ing.Spec.Rules {
			if nil != rule.IngressRuleValue.HTTP {
				for _, path := range rule.IngressRuleValue.HTTP.Paths {
					exists := false
					for _, pl := range pools {
						if pl.ServiceName == path.Backend.ServiceName &&
							pl.ServicePort == path.Backend.ServicePort.IntVal {
							exists = true
						}
					}
					if exists {
						continue
					}
					// If service doesn't exist, don't create a pool for it
					sKey := ns + "/" + path.Backend.ServiceName
					_, svcFound, _ := svcIndexer.GetByKey(sKey)
					if !svcFound {
						continue
					}
					pool := Pool{
						Name: formatIngressPoolName(
							ing.ObjectMeta.Namespace,
							path.Backend.ServiceName,
						),
						Partition:   cfg.Virtual.Partition,
						Balance:     balance,
						ServiceName: path.Backend.ServiceName,
						ServicePort: path.Backend.ServicePort.IntVal,
					}
					pools = append(pools, pool)
				}
			}
		}

		rules, urlRewriteRefs, appRootRefs = processIngressRules(
			&ing.Spec,
			urlRewriteMap,
			whitelistSourceRanges,
			appRootMap,
			pools,
			cfg.Virtual.Partition,
		)
		plcy = createPolicy(*rules, cfg.Virtual.Name, cfg.Virtual.Partition)
	} else { // single-service
		pool := Pool{
			Name: formatIngressPoolName(
				ing.ObjectMeta.Namespace,
				ing.Spec.Backend.ServiceName,
			),
			Partition:   cfg.Virtual.Partition,
			Balance:     balance,
			ServiceName: ing.Spec.Backend.ServiceName,
			ServicePort: ing.Spec.Backend.ServicePort.IntVal,
		}
		ssPoolName = pool.Name
		pools = append(pools, pool)
		cfg.Virtual.PoolName = joinBigipPath(cfg.Virtual.Partition, ssPoolName)

		// Process app root annotation
		if len(appRootMap) == 1 {
			if appRootVal, ok := appRootMap["single"]; ok == true {
				appRootRules := processAppRoot("", appRootVal, fmt.Sprintf("/%s/%s", pool.Partition, pool.Name), singleServiceIngressType)
				rules = &appRootRules
				if len(appRootRules) == 2 {
					plcy = createPolicy(appRootRules, cfg.Virtual.Name, cfg.Virtual.Partition)
					appRootRefs[pool.Name] = append(appRootRefs[pool.Name], appRootRules[0].Name)
					appRootRefs[pool.Name] = append(appRootRefs[pool.Name], appRootRules[1].Name)
				}
			}
		}
	}
	cfg.MetaData.ingName = ing.ObjectMeta.Name

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we already have any Ingresses for this IP:Port
	if oldCfg, exists := resources.GetByName(cfg.Virtual.Name); exists {
		// If we do, use an existing config
		cfg.copyConfig(oldCfg)

		// If any of the new pools don't already exist, add them
		for _, newPool := range pools {
			found := false
			for _, pl := range cfg.Pools {
				if pl.Name == newPool.Name {
					found = true
					break
				}
			}
			if !found {
				cfg.Pools = append(cfg.Pools, newPool)
			}
		}
		if len(cfg.Pools) > 1 && nil != ing.Spec.Rules {
			cfg.Virtual.PoolName = ""
		} else if nil == ing.Spec.Rules {
			// If updating an Ingress from multi-service to single-service, we need to
			// reset the virtual's default pool
			cfg.Virtual.PoolName = joinBigipPath(cfg.Virtual.Partition, ssPoolName)
		}

		// If any of the new rules already exist, update them; else add them
		if len(cfg.Policies) > 0 && rules != nil {
			policy := cfg.Policies[0]
			for _, newRule := range *rules {
				found := false
				for i, rl := range policy.Rules {
					if rl.Name == newRule.Name || (!isAnnotationRule(rl.Name) &&
						!isAnnotationRule(newRule.Name) && rl.FullURI == newRule.FullURI) {
						found = true
						policy.Rules[i] = newRule
						break
					}
				}
				if !found {
					cfg.AddRuleToPolicy(policy.Name, newRule)
				}
			}
		} else if len(cfg.Policies) == 0 && plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	} else { // This is a new VS for an Ingress
		cfg.MetaData.ResourceType = "ingress"
		cfg.Virtual.Enabled = true
		setProfilesForMode("http", &cfg)
		cfg.Virtual.SourceAddrTranslation = setSourceAddrTranslation(snatPoolName)
		cfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		cfg.Pools = append(cfg.Pools, pools...)
		if plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	}

	if len(urlRewriteRefs) > 0 || len(appRootRefs) > 0 {
		cfg.MergeRules(appMgr.mergedRulesMap)
	}

	return &cfg
}

// Return value is whether or not a custom profile was updated
func (appMgr *Manager) handleIngressTls(
	rsCfg *ResourceConfig,
	ing *v1beta1.Ingress,
	svcFwdRulesMap ServiceFwdRuleMap,
) bool {
	if 0 == len(ing.Spec.TLS) {
		// Nothing to do if no TLS section
		return false
	}
	if nil == rsCfg.Virtual.VirtualAddress ||
		rsCfg.Virtual.VirtualAddress.BindAddr == "" {
		// Nothing to do for pool-only mode
		return false
	}

	var httpsPort int32
	if port, ok :=
		ing.ObjectMeta.Annotations[f5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// If we are processing the HTTPS server,
	// then we don't need a redirect policy, only profiles
	if rsCfg.Virtual.VirtualAddress.Port == httpsPort {
		var cpUpdated, updateState bool
		for _, tls := range ing.Spec.TLS {
			// Check if profile is contained in a Secret
			if appMgr.useSecrets {
				secret, err := appMgr.kubeClient.Core().Secrets(ing.ObjectMeta.Namespace).
					Get(tls.SecretName, metav1.GetOptions{})
				if err != nil {
					// No secret, so we assume the profile is a BIG-IP default
					log.Debugf("No Secret with name '%s' in namespace '%s', "+
						"parsing secretName as path instead.",
						tls.SecretName, ing.ObjectMeta.Namespace)
					profRef := convertStringToProfileRef(
						tls.SecretName, customProfileClient, ing.ObjectMeta.Namespace)
					rsCfg.Virtual.AddOrUpdateProfile(profRef)
					continue
				}
				err, cpUpdated = appMgr.createSecretSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("%v", err)
					continue
				}
				updateState = updateState || cpUpdated
				profRef := ProfileRef{
					Partition: rsCfg.Virtual.Partition,
					Name:      tls.SecretName,
					Context:   customProfileClient,
					Namespace: ing.ObjectMeta.Namespace,
				}
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				secretName := formatIngressSslProfileName(tls.SecretName)
				profRef := convertStringToProfileRef(
					secretName, customProfileClient, ing.ObjectMeta.Namespace)
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			}
		}
		if serverProfile, ok :=
			ing.ObjectMeta.Annotations[f5ServerSslProfileAnnotation]; ok == true {
			secretName := formatIngressSslProfileName(serverProfile)
			profRef := convertStringToProfileRef(
				secretName, customProfileServer, ing.ObjectMeta.Namespace)
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
		}
		return cpUpdated
	}

	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		ingressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		ingressAllowHttp, false)
	// -----------------------------------------------------------------
	// | State | sslRedirect | allowHttp | Description                 |
	// -----------------------------------------------------------------
	// |   1   |     F       |    F      | Just HTTPS, nothing on HTTP |
	// -----------------------------------------------------------------
	// |   2   |     T       |    F      | HTTP redirects to HTTPS     |
	// -----------------------------------------------------------------
	// |   2   |     T       |    T      | Honor sslRedirect == true   |
	// -----------------------------------------------------------------
	// |   3   |     F       |    T      | Both HTTP and HTTPS         |
	// -----------------------------------------------------------------
	if sslRedirect {
		// State 2, set HTTP redirect iRule
		log.Debugf("TLS: Applying HTTP redirect iRule.")
		ruleName := fmt.Sprintf("%s_%d", httpRedirectIRuleName, httpsPort)
		appMgr.addIRule(ruleName, DEFAULT_PARTITION,
			httpRedirectIRule(httpsPort))
		appMgr.addInternalDataGroup(httpsRedirectDgName, DEFAULT_PARTITION)
		ruleName = joinBigipPath(DEFAULT_PARTITION, ruleName)
		rsCfg.Virtual.AddIRule(ruleName)
		if nil != ing.Spec.Backend {
			svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
				ing.Spec.Backend.ServiceName, "\\*", "/")
		}
		for _, rul := range ing.Spec.Rules {
			if nil != rul.HTTP {
				host := rul.Host
				for _, path := range rul.HTTP.Paths {
					svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
						path.Backend.ServiceName, host, path.Path)
				}
			}
		}
	} else if allowHttp {
		// State 3, do not apply any policy
		log.Debugf("TLS: Not applying any policies.")
	}
	return false
}

func (appMgr *Manager) createRSConfigFromRoute(
	route *routeapi.Route,
	svcName string,
	resources *Resources,
	routeConfig RouteConfig,
	pStruct portStruct,
	svcIndexer cache.Indexer,
	svcFwdRulesMap ServiceFwdRuleMap,
	snatPoolName string,
) (*ResourceConfig, error, Pool) {
	var rsCfg ResourceConfig
	rsCfg.MetaData.RouteProfs = make(map[routeKey]string)
	var policyName, rsName string

	if pStruct.protocol == "http" {
		policyName = "openshift_insecure_routes"
		rsName = routeConfig.HttpVs
	} else {
		policyName = "openshift_secure_routes"
		rsName = routeConfig.HttpsVs
	}

	var backendPort int32
	var err error
	if route.Spec.Port != nil {
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			backendPort = route.Spec.Port.TargetPort.IntVal
		} else {
			backendPort, err = getServicePort(route, svcName, svcIndexer, strVal)
			if nil != err {
				return &rsCfg, err, Pool{}
			}
		}
	} else {
		backendPort, err = getServicePort(route, svcName, svcIndexer, "")
		if nil != err {
			return &rsCfg, err, Pool{}
		}
	}
	var balance string
	if bal, ok := route.ObjectMeta.Annotations[f5VsBalanceAnnotation]; ok {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	// Create the pool
	pool := Pool{
		Name:        formatRoutePoolName(route.ObjectMeta.Namespace, svcName),
		Partition:   DEFAULT_PARTITION,
		Balance:     balance,
		ServiceName: svcName,
		ServicePort: backendPort,
	}
	// Create the rule
	uri := route.Spec.Host + route.Spec.Path
	rule, err := createRule(uri, pool.Name, pool.Partition, formatRouteRuleName(route))
	if nil != err {
		err = fmt.Errorf("Error configuring rule for Route %s: %v", route.ObjectMeta.Name, err)
		return &rsCfg, err, Pool{}
	}

	// Handle url-rewrite annotation
	var urlRewriteRule *Rule
	if urlRewrite, ok := route.ObjectMeta.Annotations[f5VsURLRewriteAnnotation]; ok {
		urlRewriteMap := parseAppRootURLRewriteAnnotations(urlRewrite)
		if len(urlRewriteMap) == 1 {
			if urlRewriteVal, ok := urlRewriteMap["single"]; ok == true {
				urlRewriteRule = processURLRewrite(uri, urlRewriteVal, routeType)
			}
		}
	}

	// Handle app-root annotation
	var appRootRules []*Rule
	if appRoot, ok := route.ObjectMeta.Annotations[f5VsAppRootAnnotation]; ok {
		appRootMap := parseAppRootURLRewriteAnnotations(appRoot)
		if len(appRootMap) == 1 {
			if appRootVal, ok := appRootMap["single"]; ok == true {
				appRootRules = processAppRoot(uri, appRootVal, fmt.Sprintf("/%s/%s", pool.Partition, pool.Name), routeType)
			}
		}
	}

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we have any Routes already saved for this VS type
	if oldCfg, exists := resources.GetByName(rsName); exists {
		// If we do, use an existing config
		rsCfg.copyConfig(oldCfg)

		// If this pool doesn't already exist, add it
		var found bool
		for i, pl := range rsCfg.Pools {
			if pl.Name == pool.Name {
				// If port has changed, update it
				if pl.ServicePort != pool.ServicePort {
					rsCfg.Pools[i].ServicePort = pool.ServicePort
				}
				found = true
				break
			}
		}
		if !found {
			rsCfg.Pools = append(rsCfg.Pools, pool)
		}
	} else { // This is a new VS for a Route
		rsCfg.MetaData.ResourceType = "route"
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.Enabled = true
		setProfilesForMode("http", &rsCfg)
		rsCfg.Virtual.SourceAddrTranslation = setSourceAddrTranslation(snatPoolName)
		rsCfg.Virtual.Partition = DEFAULT_PARTITION
		bindAddr := ""
		if routeConfig.RouteVSAddr != "" {
			bindAddr = routeConfig.RouteVSAddr
		}
		rsCfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		rsCfg.Pools = append(rsCfg.Pools, pool)
	}

	abDeployment := isRouteABDeployment(route)
	appMgr.handleRouteRules(&rsCfg,
		route,
		pStruct.protocol,
		policyName,
		rsName,
		pool.Name,
		rule,
		urlRewriteRule,
		appRootRules,
		svcFwdRulesMap,
		abDeployment)

	return &rsCfg, nil, pool
}

// Copies from an existing config into our new config
func (rc *ResourceConfig) copyConfig(cfg *ResourceConfig) {
	// MetaData
	rc.MetaData = cfg.MetaData
	// Virtual
	rc.Virtual = cfg.Virtual
	// Profiles
	rc.Virtual.Profiles = make([]ProfileRef, len(cfg.Virtual.Profiles))
	copy(rc.Virtual.Profiles, cfg.Virtual.Profiles)
	// Policies ref
	rc.Virtual.Policies = make([]nameRef, len(cfg.Virtual.Policies))
	copy(rc.Virtual.Policies, cfg.Virtual.Policies)
	// IRules
	rc.Virtual.IRules = make([]string, len(cfg.Virtual.IRules))
	copy(rc.Virtual.IRules, cfg.Virtual.IRules)
	// Pools
	rc.Pools = make(Pools, len(cfg.Pools))
	copy(rc.Pools, cfg.Pools)
	// Pool Members and Monitor Names
	for i, _ := range rc.Pools {
		rc.Pools[i].Members = make([]Member, len(cfg.Pools[i].Members))
		copy(rc.Pools[i].Members, cfg.Pools[i].Members)

		rc.Pools[i].MonitorNames = make([]string, len(cfg.Pools[i].MonitorNames))
		copy(rc.Pools[i].MonitorNames, cfg.Pools[i].MonitorNames)
	}
	// Monitors
	rc.Monitors = make(Monitors, len(cfg.Monitors))
	copy(rc.Monitors, cfg.Monitors)
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
			rc.Policies[i].Rules[j].Actions = make([]*action, len(cfg.Policies[i].Rules[j].Actions))
			rc.Policies[i].Rules[j].Conditions = make([]*condition, len(cfg.Policies[i].Rules[j].Conditions))
			for k, _ := range rc.Policies[i].Rules[j].Conditions {
				rc.Policies[i].Rules[j].Conditions[k] = &condition{}
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

func setAnnotationRulesForRoute(
	policyName,
	virtualName,
	poolName string,
	urlRewriteRule *Rule,
	appRootRules []*Rule,
	rc *ResourceConfig,
	appMgr *Manager,
) {
	if len(appRootRules) == 2 {
		rc.AddRuleToPolicy(policyName, appRootRules[0])
		rc.AddRuleToPolicy(policyName, appRootRules[1])
	}
	if urlRewriteRule != nil {
		rc.AddRuleToPolicy(policyName, urlRewriteRule)
	}
}

func (appMgr *Manager) handleRouteRules(
	rc *ResourceConfig,
	route *routeapi.Route,
	protocol string,
	policyName string,
	virtualName string,
	poolName string,
	rule *Rule,
	urlRewriteRule *Rule,
	appRootRules []*Rule,
	svcFwdRulesMap ServiceFwdRuleMap,
	abDeployment bool,
) {
	tls := route.Spec.TLS
	abPathIRuleName := joinBigipPath(DEFAULT_PARTITION, abDeploymentPathIRuleName)

	if abDeployment {
		rc.DeleteRuleFromPolicy(policyName, rule, appMgr.mergedRulesMap)
	}

	if protocol == "http" {
		if nil == tls || len(tls.Termination) == 0 {
			if abDeployment {
				appMgr.addIRule(
					abDeploymentPathIRuleName, DEFAULT_PARTITION, abDeploymentPathIRule())
				appMgr.addInternalDataGroup(abDeploymentDgName, DEFAULT_PARTITION)
				rc.Virtual.AddIRule(abPathIRuleName)
			} else {
				rc.AddRuleToPolicy(policyName, rule)
				setAnnotationRulesForRoute(policyName, virtualName, poolName, urlRewriteRule, appRootRules, rc, appMgr)
			}
		} else {
			// Handle redirect policy for edge. Reencrypt and passthrough do not
			// support redirect policies, despite what the OpenShift docs say.
			if tls.Termination == routeapi.TLSTerminationEdge {
				// edge supports 'allow' and 'redirect'
				switch tls.InsecureEdgeTerminationPolicy {
				case routeapi.InsecureEdgeTerminationPolicyAllow:
					if abDeployment {
						rc.Virtual.AddIRule(abPathIRuleName)
					} else {
						rc.AddRuleToPolicy(policyName, rule)
						setAnnotationRulesForRoute(policyName, virtualName, poolName, urlRewriteRule, appRootRules, rc, appMgr)
					}
				case routeapi.InsecureEdgeTerminationPolicyRedirect:
					redirectIRuleName := joinBigipPath(DEFAULT_PARTITION,
						httpRedirectIRuleName)
					appMgr.addIRule(httpRedirectIRuleName, DEFAULT_PARTITION,
						httpRedirectIRule(DEFAULT_HTTPS_PORT))
					appMgr.addInternalDataGroup(httpsRedirectDgName, DEFAULT_PARTITION)
					rc.Virtual.AddIRule(redirectIRuleName)
					// TLS config indicates to forward http to https.
					path := "/"
					if route.Spec.Path != "" {
						path = route.Spec.Path
					}
					svcFwdRulesMap.AddEntry(route.ObjectMeta.Namespace, route.Spec.To.Name,
						route.Spec.Host, path)
				}
			}
		}
	} else {
		// https
		if nil != tls {
			passThroughIRuleName := joinBigipPath(DEFAULT_PARTITION,
				sslPassthroughIRuleName)
			switch tls.Termination {
			case routeapi.TLSTerminationEdge:
				if abDeployment {
					appMgr.addIRule(
						abDeploymentPathIRuleName, DEFAULT_PARTITION, abDeploymentPathIRule())
					appMgr.addInternalDataGroup(abDeploymentDgName, DEFAULT_PARTITION)
					rc.Virtual.AddIRule(abPathIRuleName)
				} else {
					rc.AddRuleToPolicy(policyName, rule)
					setAnnotationRulesForRoute(policyName, virtualName, poolName, urlRewriteRule, appRootRules, rc, appMgr)
				}
			case routeapi.TLSTerminationPassthrough:
				appMgr.addIRule(
					sslPassthroughIRuleName, DEFAULT_PARTITION, appMgr.sslPassthroughIRule())
				appMgr.addInternalDataGroup(passthroughHostsDgName, DEFAULT_PARTITION)
				rc.Virtual.AddIRule(passThroughIRuleName)
			case routeapi.TLSTerminationReencrypt:
				appMgr.addIRule(
					sslPassthroughIRuleName, DEFAULT_PARTITION, appMgr.sslPassthroughIRule())
				appMgr.addInternalDataGroup(reencryptHostsDgName, DEFAULT_PARTITION)
				appMgr.addInternalDataGroup(reencryptServerSslDgName, DEFAULT_PARTITION)
				rc.Virtual.AddIRule(passThroughIRuleName)
				if !abDeployment {
					rc.AddRuleToPolicy(policyName, rule)
					setAnnotationRulesForRoute(policyName, virtualName, poolName, urlRewriteRule, appRootRules, rc, appMgr)
				}
			}
		}
	}
	if urlRewriteRule != nil || len(appRootRules) != 0 {
		rc.MergeRules(appMgr.mergedRulesMap)
	}

	// Add whitelist condition
	var whitelistSourceRanges []string
	if sourceRange, ok := route.ObjectMeta.Annotations[f5VsWhitelistSourceRangeAnnotation]; ok {
		whitelistSourceRanges = parseWhitelistSourceRangeAnnotations(sourceRange)
	}
	if len(whitelistSourceRanges) > 0 {
		for _, pol := range rc.Policies {
			if pol.Name == policyName {
				for i, rl := range pol.Rules {
					if rl.FullURI == rule.FullURI && !strings.HasSuffix(rl.Name, "-reset") {
						origCond := make([]*condition, len(rl.Conditions))
						copy(origCond, rl.Conditions)
						cond := condition{
							Tcp:     true,
							Address: true,
							Matches: true,
							Name:    "0",
							Values:  whitelistSourceRanges,
						}
						if !contains(rl.Conditions, cond) {
							rl.Conditions = append(rl.Conditions, &cond)
						}

						// Add reset traffic rule immediately after this rule
						if (len(pol.Rules) > i+1 && pol.Rules[i+1].Name != rl.Name+"-reset") ||
							i == len(pol.Rules)-1 {
							reset := &Rule{
								Name:    rl.Name + "-reset",
								FullURI: rl.FullURI,
								Actions: []*action{{
									Name:    "0",
									Forward: true,
									Request: true,
									Reset:   true,
								}},
								Conditions: origCond,
							}
							if i == len(pol.Rules)-1 {
								pol.Rules = append(pol.Rules, reset)
							} else {
								pol.Rules = append(pol.Rules, &Rule{})
								copy(pol.Rules[i+2:], pol.Rules[i+1:])
								pol.Rules[i+1] = reset
							}
						}
					}
				}
				if !contains(pol.Requires, "tcp") {
					pol.Requires = append(pol.Requires, "tcp")
				}
				rc.SetPolicy(pol)
				break
			}
		}
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
		policy = createPolicy(Rules{rule}, policyName, rc.Virtual.Partition)
	}
	rc.SetPolicy(*policy)
}

func (rc *ResourceConfig) DeleteRuleFromPolicy(
	policyName string,
	rule *Rule,
	mergedRulesMap map[string]map[string]mergedRuleEntry,
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
	toFind := nameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	found := false
	for _, polName := range rc.Virtual.Policies {
		if reflect.DeepEqual(toFind, polName) {
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
	toFind := nameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	for i, polName := range rc.Virtual.Policies {
		if reflect.DeepEqual(toFind, polName) {
			// Remove from array
			copy(rc.Virtual.Policies[i:], rc.Virtual.Policies[i+1:])
			rc.Virtual.Policies[len(rc.Virtual.Policies)-1] = nameRef{}
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
			if !reflect.DeepEqual(rc.Monitors[i], monitor) {
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
	appMgr *Manager,
) (bool, *serviceKey) {
	var cfgChanged bool
	var svcKey *serviceKey
	var fullPoolName, resourceName string

	// Delete pool
	for i, pool := range rc.Pools {
		if pool.Name != poolName {
			continue
		}
		svcKey = &serviceKey{
			Namespace:   namespace,
			ServiceName: pool.ServiceName,
			ServicePort: pool.ServicePort,
		}
		cfgChanged = rc.RemovePoolAt(i)
		break
	}
	fullPoolName = joinBigipPath(DEFAULT_PARTITION, poolName)

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
				unmerged := rc.UnmergeRule(rule.Name, appMgr.mergedRulesMap)
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
	profRef := makeRouteClientSSLProfileRef(
		rc.Virtual.Partition, namespace, name)
	rc.Virtual.RemoveProfile(profRef)
	serverProfile := makeRouteServerSSLProfileRef(
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

type mergedRuleEntry struct {
	RuleName       string
	OtherRuleNames []string
	MergedActions  map[string][]*action
	OriginalRule   *Rule
}

func (rc *ResourceConfig) UnmergeRule(ruleName string, mergedRulesMap map[string]map[string]mergedRuleEntry) bool {
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

func (rc *ResourceConfig) MergeRules(mergedRulesMap map[string]map[string]mergedRuleEntry) {
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
					var mergerEntry mergedRuleEntry
					var mergeeEntry mergedRuleEntry

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
								if reflect.DeepEqual(rules[i].Actions[k], rules[j].Actions[l]) {
									found = true
								}
								rules[i].Actions[k].Name = mergeeName
								rules[j].Actions[l].Name = mergerName
							}
							if !found {
								rules[j].Actions = append(rules[j].Actions, rules[i].Actions[k])
								mergerEntry.MergedActions = make(map[string][]*action)
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
								if reflect.DeepEqual(rules[j].Actions[k], rules[i].Actions[l]) {
									found = true
								}
								rules[j].Actions[k].Name = mergeeName
								rules[i].Actions[l].Name = mergerName
							}
							if !found {
								rules[i].Actions = append(rules[i].Actions, rules[j].Actions[k])
								mergerEntry.MergedActions = make(map[string][]*action)
								mergerEntry.MergedActions[jName] = append(mergerEntry.MergedActions[jName], rules[j].Actions[k])
							}
						}
					}

					contains := func(slice []string, s string) bool {
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
								if !contains(entry.OtherRuleNames, mergerEntry.OtherRuleNames[0]) {
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
							mergedRulesMap[key] = make(map[string]mergedRuleEntry)
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

func splitBigipPath(path string, keepSlash bool) (partition, objName string) {
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

func joinBigipPath(partition, objName string) string {
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

// Creates an IRule if it doesn't already exist
func (appMgr *Manager) addIRule(name, partition, rule string) {
	appMgr.irulesMutex.Lock()
	defer appMgr.irulesMutex.Unlock()

	key := nameRef{
		Name:      name,
		Partition: partition,
	}
	if _, found := appMgr.irulesMap[key]; !found {
		appMgr.irulesMap[key] = NewIRule(name, partition, rule)
	}
}

// Creates an InternalDataGroup if it doesn't already exist
func (appMgr *Manager) addInternalDataGroup(name, partition string) {
	appMgr.intDgMutex.Lock()
	defer appMgr.intDgMutex.Unlock()

	key := nameRef{
		Name:      name,
		Partition: partition,
	}
	if _, found := appMgr.intDgMap[key]; !found {
		appMgr.intDgMap[key] = make(DataGroupNamespaceMap)
	}
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
	}
	if peerCertMode == peerCertRequired {
		cp.CAFile = caFile
	}
	return cp
}

// If name is provided, return port number for that port name,
// else return the first port found from a Route's service.
func getServicePort(
	route *routeapi.Route,
	svcName string,
	svcIndexer cache.Indexer,
	name string,
) (int32, error) {
	ns := route.ObjectMeta.Namespace
	key := ns + "/" + svcName

	obj, found, err := svcIndexer.GetByKey(key)
	if nil != err {
		return 0, fmt.Errorf("Error looking for service '%s': %v", key, err)
	}
	if found {
		svc := obj.(*v1.Service)
		if name != "" {
			for _, port := range svc.Spec.Ports {
				if port.Name == name {
					return port.Port, nil
				}
			}
			return 0,
				fmt.Errorf("Could not find service port '%s' on service '%s'", name, key)
		} else {
			return svc.Spec.Ports[0].Port, nil
		}
	}
	return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
}

// contains returns whether x contains y
func contains(x interface{}, y interface{}) bool {
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
