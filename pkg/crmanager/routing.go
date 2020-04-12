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

package crmanager

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

// processVirtualServerRules process rules for VirtualServer
func processVirtualServerRules(
	vs *cisapiv1.VirtualServer,
	pools []Pool,
	partition string,
) *Rules {
	var err error
	var uri, poolName string
	var rl *Rule

	rlMap := make(ruleMap)
	wildcards := make(ruleMap)

	for _, pl := range vs.Spec.Pools {
		uri = vs.Spec.Host + pl.Path
		poolName = pl.Service
		// Service cannot be empty
		if poolName == "" {
			continue
		}
		ruleName := formatVirtualServerRuleName(vs.Spec.Host, pl.Path, poolName)
		rl, err = createRule(uri, poolName, partition, ruleName)
		if nil != err {
			log.Warningf("Error configuring rule: %v", err)
			return nil
		}
		if true == strings.HasPrefix(uri, "*.") {
			wildcards[uri] = rl
		} else {
			rlMap[uri] = rl
		}
		poolName = ""
	}

	var wg sync.WaitGroup
	wg.Add(2)

	sortrules := func(r ruleMap, rls *Rules, ordinal int) {
		for _, v := range r {
			*rls = append(*rls, v)
		}
		//sort.Sort(sort.Reverse(*rls))
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

	return &rls
}

// format the rule name for VirtualServer
func formatVirtualServerRuleName(host, path, pool string) string {
	var rule string
	if path == "" {
		rule = fmt.Sprintf("vs_%s_%s", host, pool)
	} else {
		// Remove the first slash, then replace any subsequent slashes with '_'
		path = strings.TrimPrefix(path, "/")
		path = strings.Replace(path, "/", "_", -1)
		rule = fmt.Sprintf("vs_%s_%s_%s", host, path, pool)
	}
	return rule
}

// Create LTM policy rules
func createRule(uri, poolName, partition, ruleName string) (*Rule, error) {
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

	a := action{
		Forward: true,
		Name:    "0",
		Pool:    b.String(),
		Request: true,
	}

	var c []*condition
	if true == strings.HasPrefix(uri, "*.") {
		c = append(c, &condition{
			EndsWith: true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{strings.TrimPrefix(u.Host, "*")},
		})
	} else if u.Host != "" {
		c = append(c, &condition{
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
		Actions:    []*action{&a},
		Conditions: c,
	}

	log.Debugf("Configured rule: %v", rl)
	return &rl, nil
}

func createPathSegmentConditions(u *url.URL) []*condition {
	var c []*condition
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	segments := strings.Split(path, "/")
	for i, v := range segments {
		c = append(c, &condition{
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

func createPolicy(rls Rules, policyName, partition string) *Policy {
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

	log.Debugf("Configured policy: %v", plcy)
	return &plcy
}
