package appmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/miekg/dns"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CCCLAgent = "cccl"
)

type IngressList []*netv1.Ingress

func (appMgr *Manager) checkV1Ingress(
	ing *netv1.Ingress,
) (bool, []*serviceQueueKey) {
	namespace := ing.ObjectMeta.Namespace
	appInf, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	partition := DEFAULT_PARTITION
	if p, ok := ing.ObjectMeta.Annotations[F5VsPartitionAnnotation]; ok {
		if _, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; !ok {
			log.Warningf("%v annotation should be provided with %v in ingress %s/%s", F5VsBindAddrAnnotation, F5VsPartitionAnnotation, ing.Namespace, ing.Name)
			return false, nil
		}
		partition = p
	}
	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok {
		bindAddr = addr
	} else {
		bindAddr = appMgr.defaultIngIP
	}
	var keyList []*serviceQueueKey
	// Depending on the Ingress, we may loop twice here, once for http and once for https
	for _, portStruct := range appMgr.v1VirtualPorts(ing) {
		var rsType int
		rsName := NameRef{Name: FormatIngressVSName(bindAddr, portStruct.port), Partition: partition}
		// If we have a config for this IP:Port, then it should have only one default ingress
		// multiple default ingress does not make any sense
		if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
			if ing.Spec.Rules == nil &&
				oldCfg.MetaData.DefaultIngressName != "" &&
				oldCfg.MetaData.DefaultIngressName != ing.ObjectMeta.Name &&
				oldCfg.Virtual.VirtualAddress.BindAddr != "" {
				log.Warningf(
					"Single-service Ingress cannot share the IP and port for ingress %s/%s: '%s:%d'.", ing.Namespace, ing.Name,
					oldCfg.Virtual.VirtualAddress.BindAddr, oldCfg.Virtual.VirtualAddress.Port)
				return false, nil
			}
		}

		rsCfg, otherIngClass := appMgr.createRSConfigFromV1Ingress(
			ing,
			appMgr.resources,
			namespace,
			appInf,
			portStruct,
			appMgr.defaultIngIP,
			appMgr.vsSnatPoolName,
		)
		// If it belongs to some other ingress class that CIS isn't managing then skip processing it
		if otherIngClass {
			log.Debugf("Skip processing ingress %s as cis doesn't manage this ingress class", ing.Name)
			return false, nil
		}

		// If rsCfg is nil, delete any resources tied to this Ingress
		if rsCfg == nil {
			if nil == ing.Spec.Rules { //single-service
				rsType = SingleServiceIngressType
				serviceName := ing.Spec.DefaultBackend.Service.Name
				servicePort := ing.Spec.DefaultBackend.Service.Port.Number
				sKey := ServiceKey{ServiceName: serviceName, ServicePort: servicePort, Namespace: namespace}
				if _, ok := appMgr.resources.Get(sKey, rsName); ok {
					appMgr.resources.Delete(sKey, rsName)
					appMgr.deployResource()
				}
			} else { //multi-service
				rsType = MultiServiceIngressType
				_, keys := appMgr.resources.GetAllWithName(rsName)
				for _, key := range keys {
					appMgr.resources.Delete(key, rsName)
					appMgr.deployResource()
				}
			}
			return false, nil
		}

		// Validate url-rewrite annotations
		if urlRewrite, ok := ing.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
			if rsType == MultiServiceIngressType {
				urlRewriteMap := ParseAppRootURLRewriteAnnotations(urlRewrite)
				validateURLRewriteAnnotations(rsType, urlRewriteMap)
			} else {
				log.Warning("Single service ingress does not support url-rewrite annotation, not processing")
			}
		}

		// Validate app-root annotations
		if appRoot, ok := ing.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
			appRootMap := ParseAppRootURLRewriteAnnotations(appRoot)
			if rsType == SingleServiceIngressType {
				if len(appRootMap) > 1 {
					log.Warningf("Single service ingress does not support multiple app-root annotation values for single service ingress %s/%s, not processing", ing.Namespace, ing.Name)
				} else {
					if _, ok := appRootMap["single"]; ok {
						validateAppRootAnnotations(rsType, appRootMap)
					} else {
						log.Warningf("[CORE] App root annotation: %s does not support targeted values for single service ingress %s/%s, not processing", appRoot, ing.Namespace, ing.Name)
					}
				}
			} else {
				validateAppRootAnnotations(rsType, appRootMap)
			}
		}
	}
	svcs := getIngressV1Backend(ing)
	for _, svc := range svcs {
		key := &serviceQueueKey{
			ServiceName:  svc,
			Namespace:    namespace,
			ResourceKind: Ingresses,
			ResourceName: ing.Name,
		}
		keyList = append(keyList, key)
	}
	return true, keyList
}

func (appMgr *Manager) checkV1SingleServivceIngress(
	ing *netv1.Ingress,
) bool {
	bindAddr := ""
	partition := DEFAULT_PARTITION
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok {
		bindAddr = addr
	} else {
		bindAddr = appMgr.defaultIngIP
	}
	if p, ok := ing.ObjectMeta.Annotations[F5VsPartitionAnnotation]; ok {
		partition = p
	}
	// Depending on the Ingress, we may loop twice here, once for http and once for https
	for _, portStruct := range appMgr.v1VirtualPorts(ing) {
		rsName := NameRef{Name: FormatIngressVSName(bindAddr, portStruct.port), Partition: partition}
		// If we have a config for this IP:Port, then it should have only one default ingress
		// multiple default ingress does not make any sense for an ip-port combination
		if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
			if ing.Spec.Rules == nil &&
				oldCfg.MetaData.DefaultIngressName != "" &&
				oldCfg.MetaData.DefaultIngressName != ing.ObjectMeta.Name &&
				oldCfg.Virtual.VirtualAddress.BindAddr != "" {
				log.Warningf(
					"Single-service Ingress cannot share the IP and port for ingress %s/%s: '%s:%d'.", ing.Namespace, ing.Name,
					oldCfg.Virtual.VirtualAddress.BindAddr, oldCfg.Virtual.VirtualAddress.Port)
				return false
			}
		}
	}
	return true
}

func (appMgr *Manager) v1VirtualPorts(ing *netv1.Ingress) []portStruct {
	var httpPort int32
	var httpsPort int32
	if port, ok := ing.ObjectMeta.Annotations[F5VsHttpPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpPort = int32(p)
	} else {
		httpPort = DEFAULT_HTTP_PORT
	}
	if port, ok := ing.ObjectMeta.Annotations[F5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressAllowHttp, false)

	http := portStruct{
		protocol: "http",
		port:     httpPort,
	}
	https := portStruct{
		protocol: "https",
		port:     httpsPort,
	}
	var ports []portStruct
	if len(ing.Spec.TLS) > 0 || len(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]) > 0 {
		if sslRedirect || allowHttp {
			// States 2,3; both HTTP and HTTPS
			// 2 virtual servers needed
			ports = append(ports, http)
			ports = append(ports, https)
		} else {
			// State 1; HTTPS only
			ports = append(ports, https)
		}
	} else {
		// HTTP only, no TLS
		ports = append(ports, http)
	}
	return ports
}

func (appMgr *Manager) setV1IngressStatus(
	ing *netv1.Ingress,
	rsCfg *ResourceConfig,
	appInf *appInformer,
) {
	// Set the ingress status to include the virtual IP
	ip, _, _ := Split_ip_with_route_domain_cidr(rsCfg.Virtual.VirtualAddress.BindAddr)
	lbIngress := v1.LoadBalancerIngress{IP: ip}
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, lbIngress)
	} else if ing.Status.LoadBalancer.Ingress[0].IP != ip {
		ing.Status.LoadBalancer.Ingress[0] = lbIngress
	} else {
		return
	}
	go appMgr.updateV1IngressStatus(ing, rsCfg, appInf)
}

func (appMgr *Manager) updateV1IngressStatus(ing *netv1.Ingress, rsCfg *ResourceConfig, appInf *appInformer) {
	ingKey := ing.Namespace + "/" + ing.Name
	_, ingFound, _ := appInf.ingInformer.GetIndexer().GetByKey(ingKey)
	if ingFound {
		_, updateErr := appMgr.kubeClient.NetworkingV1().
			Ingresses(ing.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ing, metav1.UpdateOptions{})
		if nil != updateErr {
			// Multi-service causes the controller to try to update the status multiple times
			// at once. Ignore this error.
			if strings.Contains(updateErr.Error(), "object has been modified") {
				return
			}
			warning := "Error when setting Ingress status IP for virtual server " + rsCfg.GetName() + ":" + updateErr.Error()
			log.Warning(warning)
			appMgr.recordV1IngressEvent(ing, "StatusIPError", warning)
		}
	}
}

// Resolve the first host name in an Ingress and use the IP address as the VS address
func (appMgr *Manager) resolveV1IngressHost(ing *netv1.Ingress, namespace string) {
	var host, ipAddress string
	var err error
	var netIPs []net.IP
	logDNSError := func(msg string) {
		log.Warning(msg)
		appMgr.recordV1IngressEvent(ing, "DNSResolutionError", msg)
	}

	if nil != ing.Spec.Rules {
		// Use the host from the first rule
		host = ing.Spec.Rules[0].Host
		if host == "" {
			// Host field is empty
			logDNSError("First host is empty on Ingress " + ing.ObjectMeta.Name + "; cannot resolve.")
			return
		}
	} else {
		logDNSError("No host found for DNS resolution on Ingress " + ing.ObjectMeta.Name)
		return
	}

	if appMgr.resolveIng == "LOOKUP" {
		// Use local DNS
		netIPs, err = net.LookupIP(host)
		if nil != err {
			logDNSError("Error while resolving host " + host + ":" + err.Error())
			return
		} else {
			if len(netIPs) > 1 {
				log.Warningf(
					"Resolved multiple IP addresses for host '%s', "+
						"choosing first resolved address for ingress %s/%s.", host, ing.Namespace, ing.Name)
			}
			ipAddress = netIPs[0].String()
		}
	} else {
		// Use custom DNS server
		port := "53"
		customDNS := appMgr.resolveIng
		// Grab the port if it exists
		slice := strings.Split(customDNS, ":")
		if _, err = strconv.Atoi(slice[len(slice)-1]); err == nil {
			port = slice[len(slice)-1]
		}
		isIP := net.ParseIP(customDNS)
		if isIP == nil {
			// customDNS is not an IPAddress, it is a hostname that we need to resolve first
			netIPs, err = net.LookupIP(customDNS)
			if nil != err {
				logDNSError("Error while resolving host " + appMgr.resolveIng + ":" + err.Error())
				return
			}
			customDNS = netIPs[0].String()
		}
		client := dns.Client{}
		msg := dns.Msg{}
		msg.SetQuestion(host+".", dns.TypeA)
		var res *dns.Msg
		res, _, err = client.Exchange(&msg, customDNS+":"+port)
		if nil != err {
			logDNSError("Error while resolving host " + host + " using DNS server " + appMgr.resolveIng + " : " + err.Error())
			return
		} else if len(res.Answer) == 0 {
			logDNSError("No results for host " + host + "using DNS server " + appMgr.resolveIng)
			return
		}
		Arecord := res.Answer[0].(*dns.A)
		ipAddress = Arecord.A.String()
	}

	// Update the virtual-server annotation with the resolved IP Address
	if ing.ObjectMeta.Annotations == nil {
		ing.ObjectMeta.Annotations = make(map[string]string)
	}
	ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation] = ipAddress
	_, err = appMgr.kubeClient.NetworkingV1().Ingresses(namespace).Update(context.TODO(), ing, metav1.UpdateOptions{})
	if nil != err {
		msg := "Error while setting virtual-server IP for Ingress " + ing.ObjectMeta.Name + ": " + err.Error()
		log.Warning(msg)
		appMgr.recordV1IngressEvent(ing, "IPAnnotationError", msg)
	} else {
		msg := "Resolved host " + host + " as " + ipAddress + "; " +
			"set " + F5VsBindAddrAnnotation + " annotation with address."
		log.Info(msg)
		appMgr.recordV1IngressEvent(ing, "HostResolvedSuccessfully", msg)
	}
}

// This function expects either an Ingress resource or the name of a VS for
// an Ingress.
func (appMgr *Manager) recordV1IngressEvent(
	ing *netv1.Ingress,
	reason,
	message string,
) {
	namespace := ing.ObjectMeta.Namespace
	// Create the event
	evNotifier := appMgr.eventNotifier.CreateNotifierForNamespace(
		namespace, appMgr.kubeClient.CoreV1())
	evNotifier.RecordEvent(ing, v1.EventTypeNormal, reason, message)
}

func processV1IngressRules(
	ing *netv1.IngressSpec,
	urlRewriteMap map[string]string,
	whitelistSourceRanges []string,
	appRootMap map[string]string,
	pools []Pool,
	partition string,
) (*Rules, map[string]string, map[string][]string) {
	var err error
	var uri, poolName string
	var rl *Rule
	var urlRewriteRules []*Rule
	var appRootRules []*Rule

	rlMap := make(RuleMap)
	wildcards := make(RuleMap)
	urlRewriteRefs := make(map[string]string)
	appRootRefs := make(map[string][]string)

	for _, rule := range ing.Rules {
		if nil != rule.IngressRuleValue.HTTP {
			for _, path := range rule.IngressRuleValue.HTTP.Paths {
				uri = rule.Host + path.Path
				for _, pool := range pools {
					if path.Backend.Service.Name == pool.ServiceName &&
						path.Backend.Service.Port.Number == pool.ServicePort {
						poolName = pool.Name
					}
				}
				if poolName == "" {
					continue
				}
				ruleName := formatIngressRuleName(rule.Host, path.Path, poolName)
				// This blank name gets overridden by an ordinal later on
				rl, err = createRule(uri, poolName, partition, ruleName)
				if nil != err {
					log.Warningf("[CORE] Error configuring rule: %v", err)
					return nil, nil, nil
				}
				if true == strings.HasPrefix(uri, "*.") {
					wildcards[uri] = rl
				} else {
					rlMap[uri] = rl
				}

				// Process url-rewrite annotation
				if urlRewriteTargetedVal, ok := urlRewriteMap[uri]; ok == true {
					urlRewriteRule := ProcessURLRewrite(uri, urlRewriteTargetedVal, MultiServiceIngressType)
					urlRewriteRules = append(urlRewriteRules, urlRewriteRule)
					urlRewriteRefs[poolName] = urlRewriteRule.Name
				}

				// Process app-root annotation
				if appRootTargetedVal, ok := appRootMap[rule.Host]; ok == true {
					appRootRulePair := ProcessAppRoot(uri, appRootTargetedVal, fmt.Sprintf("/%s/%s", partition, poolName), MultiServiceIngressType)
					appRootRules = append(appRootRules, appRootRulePair...)
					if len(appRootRulePair) == 2 {
						appRootRefs[poolName] = append(appRootRefs[poolName], appRootRulePair[0].Name)
						appRootRefs[poolName] = append(appRootRefs[poolName], appRootRulePair[1].Name)
					}
				}
				poolName = ""
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	sortrules := func(r RuleMap, rls *Rules, ordinal int) {
		for _, v := range r {
			*rls = append(*rls, v)
		}
		sort.Sort(sort.Reverse(*rls))
		for _, v := range *rls {
			v.Ordinal = ordinal
			ordinal++
		}
		wg.Done()
	}

	rls := Rules{}
	go sortrules(rlMap, &rls, 0)

	w := Rules{}
	go sortrules(wildcards, &w, len(rlMap))

	wg.Wait()

	rls = append(rls, w...)

	if len(appRootRules) != 0 {
		rls = append(rls, appRootRules...)
	}
	if len(urlRewriteRules) != 0 {
		rls = append(rls, urlRewriteRules...)
	}

	if len(whitelistSourceRanges) != 0 {
		// Add whitelist entries to each rule.
		//
		// Whitelist rules are added as other conditions on the rule so that
		// the whitelist is actually enforced. The whitelist entries cannot
		// be separate rules because of the matching strategy that is used.
		//
		// The matching strategy used is first-match. Therefore, if the
		// whitelist were a separate rule, and they did not match, then
		// further rules will be processed and this is not what the function
		// of a whitelist should be.
		//
		// Whitelists should be used to *prevent* access. So they need to be
		// a separate condition of *each* rule.
		for _, x := range rls {
			cond := Condition{
				Tcp:     true,
				Address: true,
				Matches: true,
				Name:    "0",
				Values:  whitelistSourceRanges,
			}
			x.Conditions = append(x.Conditions, &cond)
		}
	}

	return &rls, urlRewriteRefs, appRootRefs
}

func (appMgr *Manager) verifyDefaultIngressClass(appInf *appInformer) bool {
	ingresClass, _, err := appInf.ingClassInformer.GetIndexer().GetByKey(appMgr.ingressClass)
	if err != nil {
		log.Errorf("[CORE] %s", err.Error())
	} else {
		if ingresClass != nil {
			return getBooleanAnnotation(ingresClass.(*netv1.IngressClass).ObjectMeta.Annotations, DefaultIngressClass, false)
		} else {
			log.Error("[CORE] Ingress class resource not found.")
		}
	}
	return false
}

func (appMgr *Manager) verifyIngressClass(ing *netv1.Ingress, appInf *appInformer) bool {
	if *ing.Spec.IngressClassName != appMgr.ingressClass {
		// return false to skip processing of ingress
		return false
	}
	// Check that ingress class exists or not
	ingresClass, ingClassFound, err := appInf.ingClassInformer.GetIndexer().GetByKey(appMgr.ingressClass)
	if err != nil {
		log.Debugf("[CORE] %s", err.Error())
	} else {
		if !ingClassFound {
			log.Errorf("[CORE] No IngressClass resource with name %s found", appMgr.ingressClass)
			return false
		}
		if ingresClass.(*netv1.IngressClass).Spec.Controller == CISControllerName {
			// return true to process the ingress
			return true
		} else {
			log.Debugf("[CORE] Unable to process ingress as incorrect controller name provided in Ingress Class resource, it should be \"%s\" instead of \"%s\"", CISControllerName, ingresClass.(*netv1.IngressClass).Spec.Controller)
		}

	}
	// return false to skip processing of ingress
	return false
}

func (appMgr *Manager) checkManageIngressClass(ing *netv1.Ingress) bool {
	// If old ingress class annotation is defined it's given priority
	appInf, _ := appMgr.getNamespaceInformer(ing.Namespace)
	// TODO once old annotation is deprecated we can remove this conditional check
	if class, ok := ing.ObjectMeta.Annotations[K8sIngressClass]; ok == true {
		if class != appMgr.ingressClass {
			return false
		}
	} else if ing.Spec.IngressClassName != nil {
		// If IngressClassName does not match IngressClass provided in CIS deployment or IngressClassName provided in CIS deployment does not exist
		return appMgr.verifyIngressClass(ing, appInf)
	} else {
		// at this point we dont have k8sIngressClass defined in annotation and spec.IngressClass Name.
		// So check whether we need to process those ingress or not.
		return appMgr.verifyDefaultIngressClass(appInf)
	}
	return true
}

// Create a ResourceConfig based on an Ingress resource config
func (appMgr *Manager) createRSConfigFromV1Ingress(
	ing *netv1.Ingress,
	resources *Resources,
	ns string,
	appInf *appInformer,
	pStruct portStruct,
	defaultIP,
	snatPoolName string,
) (*ResourceConfig, bool) {
	//check ingressclass exists
	if !appMgr.checkManageIngressClass(ing) {
		return nil, true
	}
	var cfg ResourceConfig
	var balance string
	if bal, ok := ing.ObjectMeta.Annotations[F5VsBalanceAnnotation]; ok == true {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	if partition, ok := ing.ObjectMeta.Annotations[F5VsPartitionAnnotation]; ok == true {
		cfg.Virtual.Partition = partition
	} else {
		cfg.Virtual.Partition = DEFAULT_PARTITION
	}

	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok == true {
		if addr == "controller-default" {
			bindAddr = defaultIP
		} else {
			bindAddr = addr
		}
	} else {
		// if no annotation is provided, take the IP from controller config.
		if defaultIP != "" && defaultIP != "0.0.0.0" {
			bindAddr = defaultIP
		} else {
			// Ingress IP is not given in either as controller deployment option or in annotation, exit with error log.
			log.Error("Ingress IP Address is not provided. Unable to process ingress resources. " +
				"Either configure controller with 'default-ingress-ip' or Ingress with annotation 'virtual-server.f5.com/ip'.")
		}
	}

	cfg.Virtual.Name = FormatIngressVSName(bindAddr, pStruct.port)

	// Handle url-rewrite annotation
	var urlRewriteMap map[string]string
	if urlRewrite, ok := ing.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
		urlRewriteMap = ParseAppRootURLRewriteAnnotations(urlRewrite)
	}

	// Handle whitelist-source-range annotation
	// Handle allow-source-range annotation
	var whitelistSourceRanges []string
	if sourceRange, ok := ing.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	} else if sourceRange, ok := ing.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	}

	// Handle app-root annotation
	var appRootMap map[string]string
	if appRoot, ok := ing.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
		appRootMap = ParseAppRootURLRewriteAnnotations(appRoot)
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
					if strings.ContainsAny(path.Path, "*") {
						log.Errorf("[CORE] Ingress path should not contain wildcard character '*' for ingress %s/%s", ing.Namespace, ing.Name)
						continue
					}
					exists := false
					for _, pl := range pools {
						if path.Backend.Service.Port.Name != "" {
							backendPort, err := GetServicePort(ns, path.Backend.Service.Name, appInf.svcInformer.GetIndexer(), path.Backend.Service.Port.Name, ResourceTypeIngress)
							if err != nil {
								log.Warningf("[CORE] Error fetching service port for ingress %s/%s: %v", ing.Namespace, ing.Name, err)
								continue
							}
							//Assigning backendPort to find existing pool entries
							path.Backend.Service.Port.Number = backendPort
						}
						if pl.ServiceName == path.Backend.Service.Name &&
							pl.ServicePort == path.Backend.Service.Port.Number {
							exists = true
						}
					}
					if exists {
						continue
					}
					var backendPort int32
					var err error
					if path.Backend.Service.Port.Number != 0 {
						// If service doesn't exist, don't create a pool for it
						sKey := ns + "/" + path.Backend.Service.Name
						_, svcFound, _ := appInf.svcInformer.GetIndexer().GetByKey(sKey)
						if !svcFound {
							continue
						}
						backendPort = path.Backend.Service.Port.Number
					} else if path.Backend.Service.Port.Name != "" {
						backendPort, err = GetServicePort(ns, path.Backend.Service.Name, appInf.svcInformer.GetIndexer(), path.Backend.Service.Port.Name, ResourceTypeIngress)
						if err != nil {
							log.Warningf("[CORE] Error fetching service port for ingress %s/%s: %v", ing.Namespace, ing.Name, err)
							continue
						}
						//Assigning backendPort to find existing pool entries
						path.Backend.Service.Port.Number = backendPort
					}
					var poolPortString string
					if path.Backend.Service.Port.Number != 0 {
						poolPortString = fmt.Sprintf("%d", path.Backend.Service.Port.Number)
					} else if path.Backend.Service.Port.Name != "" {
						poolPortString = path.Backend.Service.Port.Name
					}
					pool := Pool{
						Name: FormatIngressPoolName(
							ing.ObjectMeta.Namespace,
							path.Backend.Service.Name,
							ing.ObjectMeta.Name,
							poolPortString,
						),
						Partition:   cfg.Virtual.Partition,
						Balance:     balance,
						ServiceName: path.Backend.Service.Name,
						ServicePort: backendPort,
					}
					pools = append(pools, pool)
				}
			}
		}

		rules, urlRewriteRefs, appRootRefs = processV1IngressRules(
			&ing.Spec,
			urlRewriteMap,
			whitelistSourceRanges,
			appRootMap,
			pools,
			cfg.Virtual.Partition,
		)
		plcy = CreatePolicy(*rules, cfg.Virtual.Name, cfg.Virtual.Partition)
	} else { // single-service
		var backendPort int32
		var err error
		if ing.Spec.DefaultBackend.Service.Port.Number != 0 {
			backendPort = ing.Spec.DefaultBackend.Service.Port.Number
		} else if ing.Spec.DefaultBackend.Service.Port.Name != "" {
			backendPort, err = GetServicePort(ns, ing.Spec.DefaultBackend.Service.Name, appInf.svcInformer.GetIndexer(), ing.Spec.DefaultBackend.Service.Port.Name, ResourceTypeIngress)
			if err != nil {
				log.Warningf("[CORE] Error fetching service port for ingress %s/%s: %v", ing.Namespace, ing.Name, err)
			}
		}
		var poolPortString string
		if ing.Spec.DefaultBackend.Service.Port.Number != 0 {
			poolPortString = fmt.Sprintf("%d", ing.Spec.DefaultBackend.Service.Port.Number)
		} else if ing.Spec.DefaultBackend.Service.Port.Name != "" {
			poolPortString = ing.Spec.DefaultBackend.Service.Port.Name
		}
		pool := Pool{
			Name: FormatIngressPoolName(
				ing.ObjectMeta.Namespace,
				ing.Spec.DefaultBackend.Service.Name,
				ing.ObjectMeta.Name,
				poolPortString,
			),
			Partition:   cfg.Virtual.Partition,
			Balance:     balance,
			ServiceName: ing.Spec.DefaultBackend.Service.Name,
			ServicePort: backendPort,
		}
		ssPoolName = pool.Name
		pools = append(pools, pool)
		// Process app root annotation
		if len(appRootMap) == 1 {
			if appRootVal, ok := appRootMap["single"]; ok == true {
				appRootRules := ProcessAppRoot("", appRootVal, fmt.Sprintf("/%s/%s", pool.Partition, pool.Name), SingleServiceIngressType)
				rules = &appRootRules
				if len(appRootRules) == 2 {
					plcy = CreatePolicy(appRootRules, cfg.Virtual.Name, cfg.Virtual.Partition)
					appRootRefs[pool.Name] = append(appRootRefs[pool.Name], appRootRules[0].Name)
					appRootRefs[pool.Name] = append(appRootRefs[pool.Name], appRootRules[1].Name)
				}
			}
		}
	}

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we already have any Ingresses for this IP:Port
	if oldCfg, exists := resources.GetByName(cfg.GetNameRef()); exists {
		// If we do, use an existing config
		cfg.CopyConfig(oldCfg)

		// If any of the new pools don't already exist, add them
		for _, newPool := range pools {
			found := false
			for i, pl := range cfg.Pools {
				if pl.Name == newPool.Name {
					found = true
					if pl.Balance != newPool.Balance {
						cfg.Pools[i].Balance = newPool.Balance
					}
					if pl.ServicePort != newPool.ServicePort {
						cfg.Pools[i].ServicePort = newPool.ServicePort
					}
					break
				}
			}
			if !found {
				cfg.Pools = append(cfg.Pools, newPool)
			}
		}

		if ing.Spec.Rules == nil {
			if oldCfg.MetaData.DefaultIngressName == "" {
				// this is the case where multi-service ingress is created first and then single service ingress is created
				cfg.Virtual.PoolName = JoinBigipPath(cfg.Virtual.Partition, ssPoolName)
				cfg.MetaData.DefaultIngressName = ing.ObjectMeta.Name
			}
		} else {
			if oldCfg.MetaData.DefaultIngressName != "" {
				// this is definitely a case where multiservice ingress is there with the default pool
				// clean up the DefaultIngressName if it's deleted
				rscKey := fmt.Sprintf("%v/%v", ing.Namespace, cfg.MetaData.DefaultIngressName)
				_, exist, err := appInf.ingInformer.GetIndexer().GetByKey(rscKey)
				if err != nil {
					log.Debugf("Error while fetching Ingress: %v: %v",
						rscKey, err)
				}
				if !exist {
					cfg.MetaData.DefaultIngressName = ""
					cfg.Virtual.PoolName = ""
				} else {
					// this is the case where single service ingress is created first and then multi-service ingress is created
					cfg.Virtual.PoolName = oldCfg.Virtual.PoolName
				}
			}
		}

		// If any of the new rules already exist, update them; else add them
		if len(cfg.Policies) > 0 && rules != nil {
			policy := cfg.Policies[0]
			for _, newRule := range *rules {
				found := false
				for i, rl := range policy.Rules {
					if rl.Name == newRule.Name || (!IsAnnotationRule(rl.Name) &&
						!IsAnnotationRule(newRule.Name) && rl.FullURI == newRule.FullURI) {
						found = true
						// Replace old rule with new rule, but make sure Ordinal is correct.
						newRule.Ordinal = rl.Ordinal
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
		if ing.Spec.Rules == nil {
			cfg.Virtual.PoolName = JoinBigipPath(cfg.Virtual.Partition, ssPoolName)
			cfg.MetaData.DefaultIngressName = ing.ObjectMeta.Name
		}
		cfg.MetaData.ResourceType = "ingress"
		cfg.Virtual.Enabled = true
		SetProfilesForMode("http", &cfg)
		cfg.Virtual.SourceAddrTranslation = SetSourceAddrTranslation(snatPoolName)
		if appMgr.AgentName == CCCLAgent {
			// CCCL doesn't support CIDR notation, it supports subnet mask
			cfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port, true)
			cfg.Virtual.SetVirtualAddressNetMask(bindAddr)
		} else {
			// AS3 supports CIDR notation
			cfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port, false)
		}
		cfg.Pools = append(cfg.Pools, pools...)
		if plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	}

	if len(urlRewriteRefs) > 0 || len(appRootRefs) > 0 {
		cfg.MergeRules(appMgr.mergedRulesMap)
	}
	// Sort the rules
	for _, policy := range cfg.Policies {
		sort.Sort(sort.Reverse(&policy.Rules))
	}

	if appMgr.resources.TranslateAddress == nil {
		appMgr.resources.TranslateAddress = make(map[string]map[NameRef][]string)
	}
	if _, ok := appMgr.resources.TranslateAddress[ing.Namespace]; !ok {
		appMgr.resources.TranslateAddress[ing.Namespace] = make(map[NameRef][]string)
	}
	nameRef := cfg.GetNameRef()
	if transAdd, ok := ing.ObjectMeta.Annotations[F5VSTranslateServerAddress]; ok {
		appMgr.resources.TranslateAddress[ing.Namespace][nameRef] = append(appMgr.resources.TranslateAddress[ing.Namespace][nameRef], transAdd)
	} else {
		appMgr.resources.TranslateAddress[ing.Namespace][nameRef] = append(appMgr.resources.TranslateAddress[ing.Namespace][nameRef], "")
	}
	return &cfg, false
}

// Return value is whether or not a custom profile was updated
func (appMgr *Manager) handleV1IngressTls(
	rsCfg *ResourceConfig,
	ing *netv1.Ingress,
	svcFwdRulesMap ServiceFwdRuleMap,
) bool {
	if 0 == len(ing.Spec.TLS) && 0 == len(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]) {
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
		ing.ObjectMeta.Annotations[F5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// If we are processing the HTTPS server,
	// then we don't need a redirect policy, only profiles
	if rsCfg.Virtual.VirtualAddress.Port == httpsPort {
		var cpUpdated, updateState bool
		// If annotation is set, use that profiles.
		if len(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]) > 0 {
			if profiles, err := appMgr.getProfilesFromAnnotations(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation], ing); err != nil {
				msg := "Unable to parse bigip clientssl profile JSON array " + ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation] + " for ingress " + ing.Namespace + "/" + ing.Name + ": " + err.Error()
				log.Errorf("[CORE] %s", msg)
				appMgr.recordV1IngressEvent(ing, "InvalidData", msg)
			} else {
				for _, profile := range profiles {
					rsCfg.Virtual.AddOrUpdateProfile(profile)
				}
			}
		} else {
			for _, tls := range ing.Spec.TLS {
				secret := appMgr.rsrcSSLCtxt[tls.SecretName]
				if secret == nil {
					// No secret, Hence we won't process this ingress
					msg := "No Secret with name " + tls.SecretName + " in namespace " + ing.ObjectMeta.Namespace + " for ingress " + ing.Name + ", "
					log.Errorf("[CORE] %s", msg)
					appMgr.recordV1IngressEvent(ing, "SecretNotFound", msg)
					profRef := ConvertStringToProfileRef(
						tls.SecretName, CustomProfileClient, ing.ObjectMeta.Namespace)
					rsCfg.Virtual.RemoveProfile(profRef)
					continue
				}
				var err error
				err, cpUpdated = appMgr.createSecretSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("[CORE] Error creating ssl profiles for ingress %s/%s: %v", ing.Namespace, ing.Name, err)
					continue
				}
				updateState = updateState || cpUpdated
				profRef := ProfileRef{
					Partition: rsCfg.Virtual.Partition,
					Name:      tls.SecretName,
					Context:   CustomProfileClient,
					Namespace: ing.ObjectMeta.Namespace,
				}
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			}
		}

		if serverProfile, ok :=
			ing.ObjectMeta.Annotations[F5ServerSslProfileAnnotation]; ok == true {
			secretName := FormatIngressSslProfileName(serverProfile)
			profRef := ConvertStringToProfileRef(
				secretName, CustomProfileServer, ing.ObjectMeta.Namespace)
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
		}
		return cpUpdated
	}

	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressAllowHttp, false)
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
		log.Debugf("[CORE] TLS: Applying HTTP redirect iRule.")
		ruleName := fmt.Sprintf("%s_%d", HttpRedirectIRuleName, httpsPort)
		appMgr.addIRule(ruleName, rsCfg.Virtual.Partition,
			httpRedirectIRule(httpsPort, rsCfg.Virtual.Partition, appMgr.TeemData.Agent))
		appMgr.addInternalDataGroup(HttpsRedirectDgName, rsCfg.Virtual.Partition)
		ruleName = JoinBigipPath(rsCfg.Virtual.Partition, ruleName)
		rsCfg.Virtual.AddIRule(ruleName)
		if nil != ing.Spec.DefaultBackend {
			svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
				ing.Spec.DefaultBackend.Service.Name, "\\*", "/")
		}
		defaultHttpPort := false
		for _, rul := range ing.Spec.Rules {
			if nil != rul.HTTP {
				host := rul.Host
				if port, ok := ing.ObjectMeta.Annotations[F5VsHttpPortAnnotation]; ok {
					p, err := strconv.Atoi(port)
					if err == nil {
						if p != int(DEFAULT_HTTP_PORT) {
							host = host + ":" + port
						} else {
							defaultHttpPort = true
						}
					}
				} else {
					//when no annotation set.default port is 80
					defaultHttpPort = true
				}
				for _, path := range rul.HTTP.Paths {
					svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
						path.Backend.Service.Name, host, path.Path)
					//for default port 80, when host header is sent as host or host:port
					//needs to be redirected in sslRedirect scenario
					if defaultHttpPort {
						defaultHost := host + ":" + strconv.Itoa(int(DEFAULT_HTTP_PORT))
						svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
							path.Backend.Service.Name, defaultHost, path.Path)
					}
				}
			}
		}
	} else if allowHttp {
		// State 3, do not apply any policy
		log.Debugf("[CORE] TLS: Not applying any policies.")
	}
	return false
}

func prepareV1IngressSSLContext(appMgr *Manager, ing *netv1.Ingress) {
	// Prepare Ingress SSL Transient Context
	for _, tls := range ing.Spec.TLS {
		// Check if TLS Secret already exists
		if _, ok := appMgr.rsrcSSLCtxt[tls.SecretName]; ok {
			continue
		}
		// Check if profile is contained in a Secret
		appInf, found := appMgr.getNamespaceInformer(ing.ObjectMeta.Namespace)
		if !found {
			log.Debugf("[CORE] No Informer found while fetching secret with name '%s' in namespace '%s'",
				tls.SecretName, ing.ObjectMeta.Namespace)
			continue
		}
		obj, found, err := appInf.secretInformer.GetIndexer().GetByKey(
			fmt.Sprintf("%s/%s", ing.ObjectMeta.Namespace, tls.SecretName))
		if err != nil || !found {
			appMgr.rsrcSSLCtxt[tls.SecretName] = nil
			continue
		}
		secret := obj.(*v1.Secret)
		appMgr.rsrcSSLCtxt[tls.SecretName] = secret
	}
}

func (appMgr *Manager) handleSingleServiceV1IngressHealthMonitors(
	poolName string,
	cfg *ResourceConfig,
	ing *netv1.Ingress,
	monitors AnnotationHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	ruleItem := make(PathToRuleMap)
	ruleItem["/"] = &RuleData{
		SvcName: ing.Spec.DefaultBackend.Service.Name,
		SvcPort: ing.Spec.DefaultBackend.Service.Port.Number,
	}
	htpMap := make(HostToPathMap)
	htpMap["*"] = ruleItem

	err := appMgr.assignHealthMonitorsByPathForV1Ingress(
		ing, htpMap, monitors)
	if nil != err {
		log.Errorf("[CORE] %s", err.Error())
		appMgr.recordV1IngressEvent(ing, "MonitorError", err.Error())
		_, pool := SplitBigipPath(poolName, false)
		cfg.RemoveMonitor(pool)
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for _, paths := range htpMap {
		for _, ruleData := range paths {
			appMgr.assignMonitorToPool(cfg, poolName, ruleData)
		}
	}

	appMgr.notifyUnusedHealthMonitorRulesForV1Ingress(ing, htpMap)
}

func (appMgr *Manager) handleMultiServiceV1IngressHealthMonitors(
	cfg *ResourceConfig,
	ing *netv1.Ingress,
	monitors AnnotationHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	htpMap := make(HostToPathMap)
	for _, rule := range ing.Spec.Rules {
		if nil == rule.IngressRuleValue.HTTP {
			continue
		}
		host := rule.Host
		if host == "" {
			host = "*"
		}
		ruleItem, found := htpMap[host]
		if !found {
			ruleItem = make(PathToRuleMap)
			htpMap[host] = ruleItem
		}
		for _, path := range rule.IngressRuleValue.HTTP.Paths {
			pathKey := path.Path
			if "" == pathKey {
				pathKey = "/"
			}
			pathItem, found := ruleItem[pathKey]
			if found {
				msg := fmt.Sprintf(
					"Health Monitor path '%s' already exists for host '%s' in ingress '%s'/'%s'",
					path.Path, rule.Host, ing.Namespace, ing.Name)
				log.Warningf("[CORE] %s", msg)
				appMgr.recordV1IngressEvent(ing, "DuplicatePath", msg)
			} else {
				pathItem = &RuleData{
					SvcName: path.Backend.Service.Name,
					SvcPort: path.Backend.Service.Port.Number,
				}
				ruleItem[pathKey] = pathItem
			}
		}
	}
	if _, found := htpMap["*"]; found {
		for key, _ := range htpMap {
			if key == "*" {
				continue
			}
			msg := "Health Monitor rule for host " + key + " conflicts with rule for all hosts in ingress " + ing.Namespace + "/" + ing.Name
			log.Warningf("[CORE] %s", msg)
			appMgr.recordV1IngressEvent(ing, "DuplicatePath", msg)
		}
	}

	err := appMgr.assignHealthMonitorsByPathForV1Ingress(
		ing, htpMap, monitors)
	if nil != err {
		log.Errorf("[CORE] %s", err.Error())
		appMgr.recordV1IngressEvent(ing, "MonitorError", err.Error())
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for host, paths := range htpMap {
		for path, ruleData := range paths {
			if 0 == len(ruleData.HealthMon.Path) {
				// htpMap has an entry for each rule, but not necessarily an
				// associated health monitor.
				continue
			}
			for _, pol := range cfg.Policies {
				if pol.Name != cfg.Virtual.Name {
					continue
				}
				for _, rule := range pol.Rules {
					slashPos := strings.Index(rule.FullURI, "/")
					var ruleHost, rulePath string
					if slashPos == -1 {
						ruleHost = rule.FullURI
						rulePath = "/"
					} else {
						ruleHost = rule.FullURI[:slashPos]
						rulePath = rule.FullURI[slashPos:]
					}
					if (host == "*" || host == ruleHost) && path == rulePath {
						for _, action := range rule.Actions {
							if action.Forward && "" != action.Pool {
								appMgr.assignMonitorToPool(cfg, action.Pool, ruleData)
							}
						}
					}
				}
			}
		}
	}

	appMgr.notifyUnusedHealthMonitorRulesForV1Ingress(ing, htpMap)
}

func (appMgr *Manager) notifyUnusedHealthMonitorRulesForV1Ingress(
	ing *netv1.Ingress,
	htpMap HostToPathMap,
) {
	for _, paths := range htpMap {
		for _, ruleData := range paths {
			if false == ruleData.Assigned {
				msg := "Health Monitor path " + ruleData.HealthMon.Path + " does not match any Ingress paths."
				appMgr.recordV1IngressEvent(ing, "MonitorRuleNotUsed", msg)
			}
		}
	}
}

func (appMgr *Manager) getProfilesFromAnnotations(profstr string, ing *netv1.Ingress) (profRef []ProfileRef, err error) {
	var profiles AnnotationProfiles
	err = json.Unmarshal([]byte(profstr), &profiles)
	if err != nil {
		return nil, err
	} else {
		for _, profile := range profiles {
			profileName := FormatIngressSslProfileName(profile.Bigipprofile)
			profRef = append(profRef, ConvertStringToProfileRef(
				profileName, CustomProfileClient, ing.ObjectMeta.Namespace))
		}
		return profRef, nil
	}
}

func (appMgr *Manager) assignHealthMonitorsByPathForV1Ingress(
	ing *netv1.Ingress, // used in Ingress case for logging events
	rulesMap HostToPathMap,
	monitors AnnotationHealthMonitors,
) error {
	// The returned error is used for 'fatal' errors only, meaning abandon
	// any further processing of health monitors for this resource.
	for _, mon := range monitors {
		slashPos := strings.Index(mon.Path, "/")
		if slashPos == -1 {
			return fmt.Errorf("health monitor path '%v' is not valid for ingress %s/%s", mon.Path, ing.Namespace, ing.Name)
		}

		host := mon.Path[:slashPos]
		path := mon.Path[slashPos:]
		pm, found := rulesMap[host]
		if false == found && host != "*" {
			pm, found = rulesMap["*"]
		}
		if false == found {
			msg := "Rule not found for Health Monitor host " + host + " in ingress " + ing.Namespace + "/" + ing.Namespace
			appMgr.processedResourcesMutex.Lock()
			if _, ok := appMgr.processedResources[prepareResourceKey(Ingresses, ing.Namespace, ing.Name)]; !ok {
				log.Warningf("[CORE] %s", msg)
			}
			if ing != nil {
				appMgr.recordV1IngressEvent(ing, "MonitorRuleNotFound", msg)
			}
			appMgr.processedResourcesMutex.Unlock()
			continue
		}
		ruleData, found := pm[path]
		if false == found {
			msg := "Rule not found for Health Monitor path " + mon.Path + " in ingress " + ing.Namespace + "/" + ing.Namespace
			appMgr.processedResourcesMutex.Lock()
			if _, ok := appMgr.processedResources[prepareResourceKey(Ingresses, ing.Namespace, ing.Name)]; !ok {
				log.Warningf("[CORE] %s", msg)
			}
			if ing != nil {
				appMgr.recordV1IngressEvent(ing, "MonitorRuleNotFound", msg)
			}
			appMgr.processedResourcesMutex.Unlock()
			continue
		}
		ruleData.HealthMon = mon
	}
	return nil
}

func (appMgr *Manager) removeOldVIngressObjects(ing *netv1.Ingress) {
	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok {
		bindAddr = addr
	} else {
		bindAddr = appMgr.defaultIngIP
	}
	partition := DEFAULT_PARTITION
	if p, ok := ing.ObjectMeta.Annotations[F5VsPartitionAnnotation]; ok {
		partition = p
	}
	appMgr.resources.Lock()
	for _, portStruct := range appMgr.v1VirtualPorts(ing) {
		rsName := NameRef{Name: FormatIngressVSName(bindAddr, portStruct.port), Partition: partition}
		if nil == ing.Spec.Rules { //single-service
			serviceName := ing.Spec.DefaultBackend.Service.Name
			servicePort := ing.Spec.DefaultBackend.Service.Port.Number
			sKey := ServiceKey{ServiceName: serviceName, ServicePort: servicePort, Namespace: ing.ObjectMeta.Namespace}
			if _, ok := appMgr.resources.Get(sKey, rsName); ok {
				appMgr.resources.Delete(sKey, rsName)
			}
		} else { //multi-service
			_, keys := appMgr.resources.GetAllWithName(rsName)
			for _, key := range keys {
				appMgr.resources.Delete(key, rsName)
			}
		}
	}
	var vsCount int
	for nameRef, _ := range appMgr.resources.RsMap {
		if nameRef.Partition == partition {
			vsCount++
		}
	}
	appMgr.resources.Unlock()
	if vsCount == 0 {
		redirectDG := NameRef{Name: HttpsRedirectDgName, Partition: partition}
		if _, ok := appMgr.intDgMap[redirectDG]; ok {
			delete(appMgr.intDgMap, redirectDG)
		}
	}
	appMgr.syncIRules()
	appMgr.deployResource()
}

func (slice IngressList) Len() int {
	return len(slice)
}

func (slice IngressList) Less(i, j int) bool {
	return slice[i].CreationTimestamp.Before(&slice[j].CreationTimestamp)
}

func (slice IngressList) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (appInf *appInformer) getOrderedIngress(namespace string) (IngressList, error) {
	ingByIndex, err := appInf.ingInformer.GetIndexer().ByIndex(
		"namespace", namespace)
	var ingresses IngressList
	for _, obj := range ingByIndex {
		route := obj.(*netv1.Ingress)
		ingresses = append(ingresses, route)
	}
	sort.Sort(ingresses)
	return ingresses, err
}
