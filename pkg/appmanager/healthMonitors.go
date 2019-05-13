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

// Configures Health Monitors for Ingresses and Routes, supplied by annotations

package appmanager

import (
	"fmt"
	"strings"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (appMgr *Manager) assignHealthMonitorsByPath(
	rsName string,
	ing *v1beta1.Ingress, // used in Ingress case for logging events
	rulesMap hostToPathMap,
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
			msg := fmt.Sprintf("Rule not found for Health Monitor host '%v'", host)
			log.Warningf("%s", msg)
			if ing != nil {
				appMgr.recordIngressEvent(ing, "MonitorRuleNotFound", msg)
			}
			continue
		}
		ruleData, found := pm[path]
		if false == found {
			msg := fmt.Sprintf("Rule not found for Health Monitor path '%v'",
				mon.Path)
			log.Warningf("%s", msg)
			if ing != nil {
				appMgr.recordIngressEvent(ing, "MonitorRuleNotFound", msg)
			}
			continue
		}
		ruleData.healthMon = mon
	}
	return nil
}

func (appMgr *Manager) assignMonitorToPool(
	cfg *ResourceConfig,
	fullPoolPath string,
	ruleData *ruleData,
) bool {
	var updated bool
	partition, poolName := splitBigipPath(fullPoolPath, false)
	for poolNdx, pool := range cfg.Pools {
		if pool.Partition == partition && pool.Name == poolName {
			ruleData.assigned = true
			monitorType := ruleData.healthMon.Type
			if monitorType == "" {
				monitorType = "http"
			}
			monitor := Monitor{
				// Append the protocol to the monitor names to differentiate them.
				// Also add a monitor index to the name to be consistent with the
				// marathon-bigip-ctlr. Since the monitor names are already unique here,
				// appending a '0' is sufficient.
				Name:      formatMonitorName(poolName, monitorType),
				Partition: partition,
				Type:      monitorType,
				Interval:  ruleData.healthMon.Interval,
				Send:      ruleData.healthMon.Send,
				Recv:      ruleData.healthMon.Recv,
				Timeout:   ruleData.healthMon.Timeout,
			}
			updated = cfg.SetMonitor(&cfg.Pools[poolNdx], monitor)
		}
	}
	return updated
}

func (appMgr *Manager) notifyUnusedHealthMonitorRules(
	rsName string,
	ing *v1beta1.Ingress,
	htpMap hostToPathMap,
) {
	for _, paths := range htpMap {
		for _, ruleData := range paths {
			if false == ruleData.assigned {
				msg := fmt.Sprintf(
					"Health Monitor path '%v' does not match any Ingress paths.",
					ruleData.healthMon.Path)
				appMgr.recordIngressEvent(ing, "MonitorRuleNotUsed", msg)
			}
		}
	}
}

func (appMgr *Manager) handleSingleServiceHealthMonitors(
	rsName,
	poolName string,
	cfg *ResourceConfig,
	ing *v1beta1.Ingress,
	monitors AnnotationHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	ruleItem := make(pathToRuleMap)
	ruleItem["/"] = &ruleData{
		svcName: ing.Spec.Backend.ServiceName,
		svcPort: ing.Spec.Backend.ServicePort.IntVal,
	}
	htpMap := make(hostToPathMap)
	htpMap["*"] = ruleItem

	err := appMgr.assignHealthMonitorsByPath(
		rsName, ing, htpMap, monitors)
	if nil != err {
		log.Errorf("%s", err.Error())
		appMgr.recordIngressEvent(ing, "MonitorError", err.Error())
		_, pool := splitBigipPath(poolName, false)
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

	appMgr.notifyUnusedHealthMonitorRules(rsName, ing, htpMap)
}

func (appMgr *Manager) handleMultiServiceHealthMonitors(
	rsName string,
	cfg *ResourceConfig,
	ing *v1beta1.Ingress,
	monitors AnnotationHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	htpMap := make(hostToPathMap)
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
			ruleItem = make(pathToRuleMap)
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
				log.Warningf("%s", msg)
				appMgr.recordIngressEvent(ing, "DuplicatePath", msg)
			} else {
				pathItem = &ruleData{
					svcName: path.Backend.ServiceName,
					svcPort: path.Backend.ServicePort.IntVal,
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
			msg := fmt.Sprintf(
				"Health Monitor rule for host '%v' conflicts with rule for all hosts.",
				key)
			log.Warningf("%s", msg)
			appMgr.recordIngressEvent(ing, "DuplicatePath", msg)
		}
	}

	err := appMgr.assignHealthMonitorsByPath(
		rsName, ing, htpMap, monitors)
	if nil != err {
		log.Errorf("%s", err.Error())
		appMgr.recordIngressEvent(ing, "MonitorError", err.Error())
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for host, paths := range htpMap {
		for path, ruleData := range paths {
			if 0 == len(ruleData.healthMon.Path) {
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

	appMgr.notifyUnusedHealthMonitorRules(rsName, ing, htpMap)
}

func (appMgr *Manager) handleRouteHealthMonitors(
	rsName string,
	pool Pool,
	cfg *ResourceConfig,
	monitors AnnotationHealthMonitors, // Only one monitor in this list
	stats *vsSyncStats,
) {
	poolPath := fmt.Sprintf("/%s/%s", pool.Partition, pool.Name)

	// Setup the rule-to-pool map from the route
	ruleItem := make(pathToRuleMap)
	ruleItem["/"] = &ruleData{
		svcName: pool.ServiceName,
		svcPort: pool.ServicePort,
	}
	htpMap := make(hostToPathMap)
	htpMap["*"] = ruleItem

	err := appMgr.assignHealthMonitorsByPath(rsName, nil, htpMap, monitors)
	if nil != err {
		log.Errorf("%s", err.Error())
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
