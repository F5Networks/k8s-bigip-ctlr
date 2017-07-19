/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
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
	"strings"

	log "f5/vlogger"

	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (appMgr *Manager) assignHealthMonitorsByPath(
	rsName string,
	ing *v1beta1.Ingress,
	rulesMap ingressHostToPathMap,
	monitors IngressHealthMonitors,
) error {
	// The returned error is used for 'fatal' errors only, meaning abandon
	// any further processing of health monitors for this Ingress.
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
			appMgr.recordIngressEvent(ing, "MonitorRuleNotFound", msg, rsName)
			continue
		}
		ruleData, found := pm[path]
		if false == found {
			msg := fmt.Sprintf("Rule not found for Health Monitor path '%v'",
				mon.Path)
			log.Warningf("%s", msg)
			appMgr.recordIngressEvent(ing, "MonitorRuleNotFound", msg, rsName)
			continue
		}
		ruleData.healthMon = mon
	}
	return nil
}

func (appMgr *Manager) assignMonitorToPool(
	cfg *ResourceConfig,
	fullPoolPath string,
	ruleData *ingressRuleData,
) {
	partition, poolName := splitBigipPath(fullPoolPath, false)
	for poolNdx, pool := range cfg.Pools {
		if pool.Partition == partition && pool.Name == poolName {
			ruleData.assigned = true
			monitor := Monitor{
				Name:      poolName,
				Partition: partition,
				Protocol:  "http",
				Interval:  ruleData.healthMon.Interval,
				Send:      ruleData.healthMon.Send,
				Timeout:   ruleData.healthMon.Timeout,
			}
			cfg.SetMonitor(&cfg.Pools[poolNdx], monitor)
		}
	}
}

func (appMgr *Manager) notifyUnusedHealthMonitorRules(
	rsName string,
	ing *v1beta1.Ingress,
	hostToPathMap ingressHostToPathMap,
) {
	for _, paths := range hostToPathMap {
		for _, ruleData := range paths {
			if false == ruleData.assigned {
				msg := fmt.Sprintf(
					"Health Monitor path '%v' does not match any Ingress paths.",
					ruleData.healthMon.Path)
				appMgr.recordIngressEvent(ing, "MonitorRuleNotUsed", msg, rsName)
			}
		}
	}
}

func (appMgr *Manager) handleSingleServiceHealthMonitors(
	rsName string,
	cfg *ResourceConfig,
	ing *v1beta1.Ingress,
	monitors IngressHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	ruleItem := make(ingressPathToRuleMap)
	ruleItem["/"] = &ingressRuleData{
		svcName: ing.Spec.Backend.ServiceName,
		svcPort: ing.Spec.Backend.ServicePort.IntVal,
	}
	hostToPathMap := make(ingressHostToPathMap)
	hostToPathMap["*"] = ruleItem

	err := appMgr.assignHealthMonitorsByPath(
		rsName, ing, hostToPathMap, monitors)
	if nil != err {
		log.Errorf("%s", err.Error())
		appMgr.recordIngressEvent(ing, "MonitorError", err.Error(), rsName)
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for _, paths := range hostToPathMap {
		for _, ruleData := range paths {
			appMgr.assignMonitorToPool(cfg, cfg.Virtual.PoolName, ruleData)
		}
	}

	appMgr.notifyUnusedHealthMonitorRules(rsName, ing, hostToPathMap)
}

func (appMgr *Manager) handleMultiServiceHealthMonitors(
	rsName string,
	cfg *ResourceConfig,
	ing *v1beta1.Ingress,
	monitors IngressHealthMonitors,
) {
	// Setup the rule-to-pool map from the ingress
	hostToPathMap := make(ingressHostToPathMap)
	for _, rule := range ing.Spec.Rules {
		if nil == rule.IngressRuleValue.HTTP {
			continue
		}
		host := rule.Host
		if host == "" {
			host = "*"
		}
		ruleItem, found := hostToPathMap[host]
		if !found {
			ruleItem = make(ingressPathToRuleMap)
			hostToPathMap[host] = ruleItem
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
				appMgr.recordIngressEvent(ing, "DuplicatePath", msg, rsName)
			} else {
				pathItem = &ingressRuleData{
					svcName: path.Backend.ServiceName,
					svcPort: path.Backend.ServicePort.IntVal,
				}
				ruleItem[pathKey] = pathItem
			}
		}
	}
	if _, found := hostToPathMap["*"]; found {
		for key, _ := range hostToPathMap {
			if key == "*" {
				continue
			}
			msg := fmt.Sprintf(
				"Health Monitor rule for host '%v' conflicts with rule for all hosts.",
				key)
			log.Warningf("%s", msg)
			appMgr.recordIngressEvent(ing, "DuplicatePath", msg, rsName)
		}
	}

	err := appMgr.assignHealthMonitorsByPath(
		rsName, ing, hostToPathMap, monitors)
	if nil != err {
		log.Errorf("%s", err.Error())
		appMgr.recordIngressEvent(ing, "MonitorError", err.Error(), rsName)
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for host, paths := range hostToPathMap {
		for path, ruleData := range paths {
			if 0 == len(ruleData.healthMon.Path) {
				// hostToPathMap has an entry for each rule, but not necessarily an
				// associated health monitor.
				continue
			}
			for _, pol := range cfg.Policies {
				if pol.Name != cfg.Virtual.VirtualServerName {
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

	appMgr.notifyUnusedHealthMonitorRules(rsName, ing, hostToPathMap)
}
