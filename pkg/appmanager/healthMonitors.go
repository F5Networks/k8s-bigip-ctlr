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

// Configures Health Monitors for Ingresses and Routes, supplied by annotations

package appmanager

import (
	"fmt"
	"strings"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"

	"k8s.io/api/extensions/v1beta1"
)

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) assignHealthMonitorsByPath(
	ing *v1beta1.Ingress, // used in Ingress case for logging events
	rulesMap HostToPathMap,
	monitors AnnotationHealthMonitors,
) error {
	// The returned error is used for 'fatal' errors only, meaning abandon
	// any further processing of health monitors for this resource.
	for _, mon := range monitors {
		slashPos := strings.Index(mon.Path, "/")
		if slashPos == -1 {
			return fmt.Errorf("Health Monitor path '%v' is not valid.", mon.Path)
		}

		host := mon.Path[:slashPos]
		path := mon.Path[slashPos:]
		pm, found := rulesMap[host]
		if false == found && host != "*" {
			pm, found = rulesMap["*"]
		}
		if false == found {
			msg := "Rule not found for Health Monitor host " + host
			log.Warningf("[CORE] %s", msg)
			if ing != nil {
				appMgr.recordIngressEvent(ing, "MonitorRuleNotFound", msg)
			}
			continue
		}
		ruleData, found := pm[path]
		if false == found {
			msg := "Rule not found for Health Monitor path " + mon.Path
			log.Warningf("[CORE] %s", msg)
			if ing != nil {
				appMgr.recordIngressEvent(ing, "MonitorRuleNotFound", msg)
			}
			continue
		}
		ruleData.HealthMon = mon
	}
	return nil
}

func (appMgr *Manager) assignMonitorToPool(
	cfg *ResourceConfig,
	fullPoolPath string,
	ruleData *RuleData,
) bool {
	var updated bool
	partition, poolName := SplitBigipPath(fullPoolPath, false)
	for poolNdx, pool := range cfg.Pools {
		if pool.Partition == partition && pool.Name == poolName {
			ruleData.Assigned = true
			monitorType := ruleData.HealthMon.Type
			if monitorType == "" {
				monitorType = "http"
			}
			monitor := Monitor{
				// Append the protocol to the monitor names to differentiate them.
				// Also add a monitor index to the name to be consistent with the
				// marathon-bigip-ctlr. Since the monitor names are already unique here,
				// appending a '0' is sufficient.
				Name:      FormatMonitorName(poolName, monitorType),
				Partition: partition,
				Type:      monitorType,
				Interval:  ruleData.HealthMon.Interval,
				Send:      ruleData.HealthMon.Send,
				Recv:      ruleData.HealthMon.Recv,
				Timeout:   ruleData.HealthMon.Timeout,
			}
			if monitorType == "https" && ruleData.HealthMon.SslProfile != "" {
				monitor.SslProfile = ruleData.HealthMon.SslProfile
			}
			updated = cfg.SetMonitor(&cfg.Pools[poolNdx], monitor)
		}
	}
	return updated
}

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) notifyUnusedHealthMonitorRules(
	ing *v1beta1.Ingress,
	htpMap HostToPathMap,
) {
	for _, paths := range htpMap {
		for _, ruleData := range paths {
			if false == ruleData.Assigned {
				msg := "Health Monitor path " + ruleData.HealthMon.Path + " does not match any Ingress paths."
				appMgr.recordIngressEvent(ing, "MonitorRuleNotUsed", msg)
			}
		}
	}
}

func RemoveUnReferredHealthMonitors(rsCfg *ResourceConfig, fullPoolName string, monitors AnnotationHealthMonitors) {
	// For this pool remove the monitor names that are not present in - monitors
	for pi, pool := range rsCfg.Pools {
		_, poolName := SplitBigipPath(fullPoolName, false)
		if pool.Name == poolName {
			foundMon := make([]string, 0)
			for _, monName := range pool.MonitorNames {
				found := false
				for _, mon := range monitors {
					monType := mon.Type
					if monType == "" {
						monType = "http"
					}
					if strings.HasSuffix(monName, monType) {
						found = true
					}
				}
				if found {
					foundMon = append(foundMon, monName)
				}
			}
			rsCfg.Pools[pi].MonitorNames = foundMon
			break
		}
	}
}

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) handleSingleServiceHealthMonitors(
	poolName string,
	cfg *ResourceConfig,
	ing *v1beta1.Ingress,
	monitors AnnotationHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	ruleItem := make(PathToRuleMap)
	ruleItem["/"] = &RuleData{
		SvcName: ing.Spec.Backend.ServiceName,
		SvcPort: ing.Spec.Backend.ServicePort.IntVal,
	}
	htpMap := make(HostToPathMap)
	htpMap["*"] = ruleItem

	err := appMgr.assignHealthMonitorsByPath(
		ing, htpMap, monitors)
	if nil != err {
		log.Errorf("[CORE] %s", err.Error())
		appMgr.recordIngressEvent(ing, "MonitorError", err.Error())
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

	appMgr.notifyUnusedHealthMonitorRules(ing, htpMap)
}

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) handleMultiServiceHealthMonitors(
	cfg *ResourceConfig,
	ing *v1beta1.Ingress,
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
					"Health Monitor path '%v' already exists for host '%v'",
					path, rule.Host)
				log.Warningf("[CORE] %s", msg)
				appMgr.recordIngressEvent(ing, "DuplicatePath", msg)
			} else {
				pathItem = &RuleData{
					SvcName: path.Backend.ServiceName,
					SvcPort: path.Backend.ServicePort.IntVal,
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
			msg := "Health Monitor rule for host " + key + " conflicts with rule for all hosts."
			log.Warningf("[CORE] %s", msg)
			appMgr.recordIngressEvent(ing, "DuplicatePath", msg)
		}
	}

	err := appMgr.assignHealthMonitorsByPath(
		ing, htpMap, monitors)
	if nil != err {
		log.Errorf("[CORE] %s", err.Error())
		appMgr.recordIngressEvent(ing, "MonitorError", err.Error())
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

	appMgr.notifyUnusedHealthMonitorRules(ing, htpMap)
}

func (appMgr *Manager) handleRouteHealthMonitors(
	pool Pool,
	cfg *ResourceConfig,
	monitors AnnotationHealthMonitors, // Only one monitor in this list
	stats *vsSyncStats,
) {
	poolPath := fmt.Sprintf("/%s/%s", pool.Partition, pool.Name)

	// Setup the rule-to-pool map from the route
	ruleItem := make(PathToRuleMap)
	ruleItem["/"] = &RuleData{
		SvcName: pool.ServiceName,
		SvcPort: pool.ServicePort,
	}
	htpMap := make(HostToPathMap)
	htpMap["*"] = ruleItem

	err := appMgr.assignHealthMonitorsByPath(nil, htpMap, monitors)
	if nil != err {
		log.Errorf("[CORE] %s", err.Error())
		// If this monitor exists already, remove it
		if removed := cfg.RemoveMonitor(pool.Name); removed {
			stats.vsUpdated += 1
		}
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	var updated, updateState bool
	for _, paths := range htpMap {
		for _, ruleData := range paths {
			updateState = appMgr.assignMonitorToPool(cfg, poolPath, ruleData)
			updated = updated || updateState
		}
	}
	if updated {
		stats.vsUpdated += 1
	}
}

// RemoveUnusedHealthMonitors removes unused health monitors if there are any
func RemoveUnusedHealthMonitors(rsCfg *ResourceConfig) {
	var exists = struct{}{}
	monitors := make(map[string]struct{})
	for _, pl := range rsCfg.Pools {
		for _, mn := range pl.MonitorNames {
			monitors[mn] = exists
		}
	}
	var usedMonitors []Monitor
	for _, mn := range rsCfg.Monitors {
		if _, ok := monitors["/"+mn.Partition+"/"+mn.Name]; ok {
			usedMonitors = append(usedMonitors, mn)
		}
	}
	rsCfg.Monitors = usedMonitors
}
