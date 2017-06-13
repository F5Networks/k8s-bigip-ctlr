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
 * WITHOUT WARRANTIES OR conditionS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"bytes"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	log "f5/vlogger"

	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (r Rules) Len() int           { return len(r) }
func (r Rules) Less(i, j int) bool { return r[i].FullURI < r[j].FullURI }
func (r Rules) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

func createRule(uri, poolName, partition string) (*Rule, error) {
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
	} else {
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
	}

	rl := Rule{
		FullURI:    uri,
		Actions:    []*action{&a},
		Conditions: c,
	}

	log.Debugf("Configured rule: %v", rl)
	return &rl, nil
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

	log.Debugf("Configured policy: %v", plcy)
	return &plcy
}

func processIngressRules(
	ing *v1beta1.IngressSpec,
	pools []Pool,
	partition string,
) *Rules {
	var err error
	var uri, poolName string
	var rl *Rule
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)
	for _, rule := range ing.Rules {
		if nil != rule.IngressRuleValue.HTTP {
			for _, path := range rule.IngressRuleValue.HTTP.Paths {
				if rule.Host == "" {
					rule.Host = "*"
				}
				uri = rule.Host + path.Path
				for _, pool := range pools {
					if path.Backend.ServiceName == pool.ServiceName {
						poolName = pool.Name
					}
				}
				if poolName == "" {
					continue
				}
				rl, err = createRule(uri, poolName, partition)
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
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	sortrules := func(r ruleMap, rls *Rules, ordinal int) {
		for _, v := range r {
			*rls = append(*rls, v)
		}
		sort.Sort(sort.Reverse(*rls))
		for _, v := range *rls {
			v.Ordinal = ordinal
			v.Name = strconv.Itoa(ordinal)
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
