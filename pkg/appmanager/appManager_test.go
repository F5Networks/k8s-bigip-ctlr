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
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	routeapi "github.com/openshift/origin/pkg/route/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func init() {
	workingDir, _ := os.Getwd()
	schemaUrl = "file://" + workingDir + "/../../schemas/bigip-virtual-server_v0.1.6.json"
	DEFAULT_PARTITION = "velcro"
}

var schemaUrl string

var configmapFoo string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 80,
      "healthMonitors": [ {
        "interval": 30,
        "timeout": 20,
        "send": "GET /",
        "recv": "Hello from",
        "protocol": "tcp"
        }
      ]
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      },
      "sslProfile": {
        "f5ProfileName": "velcro/testcert"
      }
    }
  }
}`)

var configmapFoo8080 string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 8080
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      }
    }
  }
}`)

var configmapFoo9090 string = string(`{
	"virtualServer": {
		"backend": {
			"serviceName": "foo",
			"servicePort": 9090
		},
		"frontend": {
			"balance": "round-robin",
			"mode": "tcp",
			"partition": "velcro",
			"virtualAddress": {
				"bindAddr": "10.128.10.200",
				"port": 4041
			}
		}
	}
}`)

var configmapFooTcp string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 80
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "tcp",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      }
    }
  }
}`)

var configmapFooUdp string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 80,
      "healthMonitors": [ {
        "interval": 30,
        "timeout": 20,
        "send": "GET /",
        "recv": "Hello from",
        "protocol": "udp"
        }
      ]
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "udp",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      }
    }
  }
}`)

var configmapFooInvalid string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "",
      "servicePort": 0
    },
    "frontend": {
      "balance": "super-duper-mojo",
      "mode": "udp",
      "partition": "",
      "virtualAddress": {
        "bindAddr": "10.128.10.260",
        "port": 500000
      },
      "sslProfile": {
        "f5ProfileName": ""
      }
    }
  }
}`)

var configmapBar string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "bar",
      "servicePort": 80
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 6051
      }
    }
  }
}`)

var configmapNoModeBalance string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "bar",
      "servicePort": 80
    },
    "frontend": {
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 80
      }
    }
  }
}`)

var configmapIApp1 string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "iapp1",
      "servicePort": 80
    },
    "frontend": {
      "partition": "velcro",
      "iapp": "/Common/f5.http",
      "iappPoolMemberTable": {
        "name": "pool__members",
        "columns": [
          {"name": "IPAddress", "kind": "IPAddress"},
          {"name": "Port", "kind": "Port"},
          {"name": "ConnectionLimit", "value": "0"},
          {"name": "SomeOtherValue", "value": "value-1"}
        ]
      },
      "iappOptions": {
        "description": "iApp 1"
      },
      "iappVariables": {
        "monitor__monitor": "/#create_new#",
        "monitor__resposne": "none",
        "monitor__uri": "/",
        "net__client_mode": "wan",
        "net__server_mode": "lan",
        "pool__addr": "127.0.0.1",
        "pool__pool_to_use": "/#create_new#",
        "pool__port": "8080"
      }
    }
  }
}`)

var configmapIApp2 string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "iapp2",
      "servicePort": 80
    },
    "frontend": {
      "partition": "velcro",
      "iapp": "/Common/f5.http",
      "iappOptions": {
        "description": "iApp 2"
      },
      "iappTables": {
        "pool__Pools": {
          "columns": ["Index", "Name", "Description", "LbMethod", "Monitor",
                      "AdvOptions"],
          "rows": [["0", "", "", "round-robin", "0", "none"]]
        },
        "monitor__Monitors": {
          "columns": ["Index", "Name", "Type", "Options"],
          "rows": [["0", "/Common/tcp", "none", "none"]]
        }
      },
      "iappPoolMemberTable": {
        "name": "pool__members",
        "columns": [
          {"name": "IPAddress", "kind": "IPAddress"},
          {"name": "Port", "kind": "Port"},
          {"name": "ConnectionLimit", "value": "0"},
          {"name": "SomeOtherValue", "value": "value-1"}
        ]
      },
      "iappVariables": {
        "monitor__monitor": "/#create_new#",
        "monitor__resposne": "none",
        "monitor__uri": "/",
        "net__client_mode": "wan",
        "net__server_mode": "lan",
        "pool__addr": "127.0.0.2",
        "pool__pool_to_use": "/#create_new#",
        "pool__port": "4430"
      }
    }
  }
}`)

var emptyConfig string = string(`{"resources":{}}`)

var twoSvcsFourPortsThreeNodesConfig string = string(`{"resources":{"velcro":{"virtualServers":[{"name":"default_barmap","pool":"/velcro/cfgmap_default_barmap_bar","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:6051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]},{"name":"default_foomap","pool":"/velcro/cfgmap_default_foomap_foo","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:5051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"},{"partition":"velcro","name":"testcert","context":"clientside"}]},{"name":"default_foomap8080","pool":"/velcro/cfgmap_default_foomap8080_foo","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:5051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]},{"name":"default_foomap9090","pool":"/velcro/cfgmap_default_foomap9090_foo","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.200:4041","profiles":[{"partition":"Common","name":"tcp","context":"all"}]}],"pools":[{"name":"cfgmap_default_barmap_bar","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.1","port":37001,"session":"user-enabled"},{"address":"127.0.0.2","port":37001,"session":"user-enabled"},{"address":"127.0.0.3","port":37001,"session":"user-enabled"}],"monitors":null},{"name":"cfgmap_default_foomap_foo","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.1","port":30001,"session":"user-enabled"},{"address":"127.0.0.2","port":30001,"session":"user-enabled"},{"address":"127.0.0.3","port":30001,"session":"user-enabled"}],"monitors":["/velcro/cfgmap_default_foomap_foo_0_tcp"]},{"name":"cfgmap_default_foomap8080_foo","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.1","port":38001,"session":"user-enabled"},{"address":"127.0.0.2","port":38001,"session":"user-enabled"},{"address":"127.0.0.3","port":38001,"session":"user-enabled"}],"monitors":null},{"name":"cfgmap_default_foomap9090_foo","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.1","port":39001,"session":"user-enabled"},{"address":"127.0.0.2","port":39001,"session":"user-enabled"},{"address":"127.0.0.3","port":39001,"session":"user-enabled"}],"monitors":null}],"monitors":[{"name":"cfgmap_default_foomap_foo_0_tcp","interval":30,"type":"tcp","send":"GET /","recv":"Hello from","timeout":20}]}}}`)

var twoSvcsTwoNodesConfig string = string(`{"resources":{"velcro":{"virtualServers":[{"name":"default_barmap","pool":"/velcro/cfgmap_default_barmap_bar","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:6051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]},{"name":"default_foomap","pool":"/velcro/cfgmap_default_foomap_foo","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:5051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"},{"partition":"velcro","name":"testcert","context":"clientside"}]}],"pools":[{"name":"cfgmap_default_barmap_bar","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.1","port":37001,"session":"user-enabled"},{"address":"127.0.0.2","port":37001,"session":"user-enabled"}]},{"name":"cfgmap_default_foomap_foo","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.1","port":30001,"session":"user-enabled"},{"address":"127.0.0.2","port":30001,"session":"user-enabled"}],"monitors":["/velcro/cfgmap_default_foomap_foo_0_tcp"]}],"monitors":[{"name":"cfgmap_default_foomap_foo_0_tcp","interval":30,"type":"tcp","send":"GET /","recv":"Hello from","timeout":20}]}}}`)

var twoSvcsOneNodeConfig string = string(`{"resources":{"velcro":{"virtualServers":[{"name":"default_barmap","pool":"/velcro/cfgmap_default_barmap_bar","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:6051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]},{"name":"default_foomap","pool":"/velcro/cfgmap_default_foomap_foo","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:5051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"},{"partition":"velcro","name":"testcert","context":"clientside"}]}],"pools":[{"name":"cfgmap_default_barmap_bar","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.3","port":37001,"session":"user-enabled"}]},{"name":"cfgmap_default_foomap_foo","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.3","port":30001,"session":"user-enabled"}],"monitors":["/velcro/cfgmap_default_foomap_foo_0_tcp"]}],"monitors":[{"name":"cfgmap_default_foomap_foo_0_tcp","interval":30,"type":"tcp","send":"GET /","recv":"Hello from","timeout":20}]}}}`)

var oneSvcOneNodeConfig string = string(`{"resources":{"velcro":{"virtualServers":[{"name":"default_barmap","pool":"/velcro/cfgmap_default_barmap_bar","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:6051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]}],"pools":[{"name":"cfgmap_default_barmap_bar","loadBalancingMode":"round-robin","members":[{"address":"127.0.0.3","port":37001,"session":"user-enabled"}]}]}}}`)

var twoIappsThreeNodesConfig string = string(`{"resources":{"velcro":{"virtualServers":[],"pools":[],"iapps":[{"name":"default_iapp1map","template":"/Common/f5.http","options":{"description":"iApp 1"},"poolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}],"members":[{"address":"192.168.0.1","port":10101,"session":"user-enabled"},{"address":"192.168.0.2","port":10101,"session":"user-enabled"},{"address":"192.168.0.4","port":10101,"session":"user-enabled"}]},"variables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}},{"name":"default_iapp2map","template":"/Common/f5.http","options":{"description":"iApp 2"},"tables":{"pool__Pools":{"columns":["Index","Name","Description","LbMethod","Monitor","AdvOptions"],"rows":[["0","","","round-robin","0","none"]]},"monitor__Monitors":{"columns":["Index","Name","Type","Options"],"rows":[["0","/Common/tcp","none","none"]]}},"poolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}],"members":[{"address":"192.168.0.1","port":20202,"session":"user-enabled"},{"address":"192.168.0.2","port":20202,"session":"user-enabled"},{"address":"192.168.0.4","port":20202,"session":"user-enabled"}]},"variables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}]}}}`)

var twoIappsOneNodeConfig string = string(`{"resources":{"velcro":{"virtualServers":[],"pools":[],"iapps":[{"name":"default_iapp1map","template":"/Common/f5.http","options":{"description":"iApp 1"},"poolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}],"members":[{"address":"192.168.0.4","port":10101,"session":"user-enabled"}]},"variables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}},{"name":"default_iapp2map","template":"/Common/f5.http","options":{"description":"iApp 2"},"tables":{"pool__Pools":{"columns":["Index","Name","Description","LbMethod","Monitor","AdvOptions"],"rows":[["0","","","round-robin","0","none"]]},"monitor__Monitors":{"columns":["Index","Name","Type","Options"],"rows":[["0","/Common/tcp","none","none"]]}},"poolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}],"members":[{"address":"192.168.0.4","port":20202,"session":"user-enabled"}]},"variables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}]}}}`)

var oneIappOneNodeConfig string = string(`{"resources":{"velcro":{"virtualServers":[],"pools":[],"iapps":[{"name":"default_iapp2map","template":"/Common/f5.http","options":{"description":"iApp 2"},"tables":{"pool__Pools":{"columns":["Index","Name","Description","LbMethod","Monitor","AdvOptions"],"rows":[["0","","","round-robin","0","none"]]},"monitor__Monitors":{"columns":["Index","Name","Type","Options"],"rows":[["0","/Common/tcp","none","none"]]}},"poolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}],"members":[{"address":"192.168.0.4","port":20202,"session":"user-enabled"}]},"variables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}]}}}`)

var twoSvcTwoPodsConfig string = string(`{"resources":{"velcro":{"virtualServers":[{"name":"default_barmap","pool":"/velcro/cfgmap_default_barmap_bar","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:6051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]},{"name":"default_foomap","pool":"/velcro/cfgmap_default_foomap_foo","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:5051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]}],"pools":[{"name":"cfgmap_default_barmap_bar","loadBalancingMode":"round-robin","members":[{"address":"10.2.96.0","port":80,"session":"user-enabled"},{"address":"10.2.96.3","port":80,"session":"user-enabled"}]},{"name":"cfgmap_default_foomap_foo","loadBalancingMode":"round-robin","members":[{"address":"10.2.96.1","port":8080,"session":"user-enabled"},{"address":"10.2.96.2","port":8080,"session":"user-enabled"}]}]}}}`)

var oneSvcTwoPodsConfig string = string(`{"resources":{"velcro":{"virtualServers":[{"name":"default_barmap","pool":"/velcro/cfgmap_default_barmap_bar","ipProtocol":"tcp","enabled":true,"sourceAddressTranslation":{"type":"automap"},"destination":"/velcro/10.128.10.240:6051","profiles":[{"partition":"Common","name":"http","context":"all"},{"partition":"Common","name":"tcp","context":"all"}]}],"pools":[{"name":"cfgmap_default_barmap_bar","loadBalancingMode":"round-robin","members":[{"address":"10.2.96.0","port":80,"session":"user-enabled"},{"address":"10.2.96.3","port":80,"session":"user-enabled"}]}]}}}`)

type mockAppManager struct {
	appMgr  *Manager
	mutex   sync.Mutex
	vsMutex map[serviceQueueKey]*sync.Mutex
	nsLabel string
}

func newMockAppManager(params *Params) *mockAppManager {
	return &mockAppManager{
		appMgr:  NewManager(params),
		mutex:   sync.Mutex{},
		vsMutex: make(map[serviceQueueKey]*sync.Mutex),
	}
}

func (m *mockAppManager) startNonLabelMode(namespaces []string) error {
	ls, err := labels.Parse(DefaultConfigMapLabel)
	if err != nil {
		return fmt.Errorf("failed to parse Label Selector string: %v", err)
	}
	for _, ns := range namespaces {
		err = m.appMgr.AddNamespace(ns, ls, 0)
		if nil != err {
			return fmt.Errorf(
				"Failed to add informers for namespace %v: %v", ns, err)
		}
	}
	return nil
}

func (m *mockAppManager) startLabelMode(nsLabel string) error {
	m.nsLabel = nsLabel
	nsSelector, err := labels.Parse(m.nsLabel)
	if nil != err {
		return fmt.Errorf(
			"Failed to create namespace selector for label %v", nsLabel, err)
	}
	err = m.appMgr.AddNamespaceLabelInformer(nsSelector, 0)
	if nil != err {
		return fmt.Errorf(
			"Failed to add namespace label informer with selector %v: %v",
			nsSelector, err)
	}
	return nil
}

func (m *mockAppManager) shutdown() error {
	m.appMgr.stopAppInformers()
	return nil
}

func (m *mockAppManager) resources() *Resources {
	return m.appMgr.resources
}

func (m *mockAppManager) customProfiles() map[secretKey]CustomProfile {
	return m.appMgr.customProfiles.profs
}

func (m *mockAppManager) getVsMutex(sKey serviceQueueKey) *sync.Mutex {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	mtx, ok := m.vsMutex[sKey]
	if !ok {
		mtx = &sync.Mutex{}
		m.vsMutex[sKey] = mtx
	}
	return mtx
}

func (m *mockAppManager) processNodeUpdate(obj interface{}, err error) {
	m.appMgr.ProcessNodeUpdate(obj, err)
	// Consume all of the work queue entries added by ProcessNodeUpdate
	queueLen := m.appMgr.vsQueue.Len()
	for i := 0; i < queueLen; i++ {
		m.appMgr.processNextVirtualServer()
	}
}

func (m *mockAppManager) addConfigMap(cm *v1.ConfigMap) bool {
	ok, keys := m.appMgr.checkValidConfigMap(cm)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(cm.ObjectMeta.Namespace)
		appInf.cfgMapInformer.GetStore().Add(cm)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) updateConfigMap(cm *v1.ConfigMap) bool {
	ok, keys := m.appMgr.checkValidConfigMap(cm)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(cm.ObjectMeta.Namespace)
		appInf.cfgMapInformer.GetStore().Update(cm)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) deleteConfigMap(cm *v1.ConfigMap) bool {
	ok, keys := m.appMgr.checkValidConfigMap(cm)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(cm.ObjectMeta.Namespace)
		appInf.cfgMapInformer.GetStore().Delete(cm)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) addService(svc *v1.Service) bool {
	ok, keys := m.appMgr.checkValidService(svc)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(svc.ObjectMeta.Namespace)
		appInf.svcInformer.GetStore().Add(svc)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) updateService(svc *v1.Service) bool {
	ok, keys := m.appMgr.checkValidService(svc)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(svc.ObjectMeta.Namespace)
		appInf.svcInformer.GetStore().Update(svc)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) deleteService(svc *v1.Service) bool {
	ok, keys := m.appMgr.checkValidService(svc)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(svc.ObjectMeta.Namespace)
		appInf.svcInformer.GetStore().Delete(svc)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) addEndpoints(ep *v1.Endpoints) bool {
	ok, keys := m.appMgr.checkValidEndpoints(ep)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(ep.ObjectMeta.Namespace)
		appInf.endptInformer.GetStore().Add(ep)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) updateEndpoints(ep *v1.Endpoints) bool {
	ok, keys := m.appMgr.checkValidEndpoints(ep)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(ep.ObjectMeta.Namespace)
		appInf.endptInformer.GetStore().Update(ep)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) deleteEndpoints(ep *v1.Endpoints) bool {
	ok, keys := m.appMgr.checkValidEndpoints(ep)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(ep.ObjectMeta.Namespace)
		appInf.endptInformer.GetStore().Delete(ep)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) addIngress(ing *v1beta1.Ingress) bool {
	ok, keys := m.appMgr.checkValidIngress(ing)
	if ok {
		ns := ing.ObjectMeta.Namespace
		m.appMgr.kubeClient.ExtensionsV1beta1().Ingresses(ns).Create(ing)
		appInf, _ := m.appMgr.getNamespaceInformer(ns)
		appInf.ingInformer.GetStore().Add(ing)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) updateIngress(ing *v1beta1.Ingress) bool {
	ok, keys := m.appMgr.checkValidIngress(ing)
	if ok {
		ns := ing.ObjectMeta.Namespace
		_, err := m.appMgr.kubeClient.ExtensionsV1beta1().Ingresses(ns).Update(ing)
		if nil != err {
			// This can happen when an ingress is ignored by checkValidIngress
			// before, but now has been updated to be accepted.
			m.appMgr.kubeClient.ExtensionsV1beta1().Ingresses(ns).Create(ing)
		}
		appInf, _ := m.appMgr.getNamespaceInformer(ns)
		appInf.ingInformer.GetStore().Update(ing)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) deleteIngress(ing *v1beta1.Ingress) bool {
	ok, keys := m.appMgr.checkValidIngress(ing)
	if ok {
		name := ing.ObjectMeta.Name
		ns := ing.ObjectMeta.Namespace
		m.appMgr.kubeClient.ExtensionsV1beta1().Ingresses(ns).Delete(name, nil)
		appInf, _ := m.appMgr.getNamespaceInformer(ns)
		appInf.ingInformer.GetStore().Delete(ing)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) addRoute(route *routeapi.Route) bool {
	ok, keys := m.appMgr.checkValidRoute(route)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(route.ObjectMeta.Namespace)
		appInf.routeInformer.GetStore().Add(route)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) updateRoute(route *routeapi.Route) bool {
	ok, keys := m.appMgr.checkValidRoute(route)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(route.ObjectMeta.Namespace)
		appInf.routeInformer.GetStore().Update(route)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) deleteRoute(route *routeapi.Route) bool {
	ok, keys := m.appMgr.checkValidRoute(route)
	if ok {
		appInf, _ := m.appMgr.getNamespaceInformer(route.ObjectMeta.Namespace)
		appInf.routeInformer.GetStore().Delete(route)
		for _, vsKey := range keys {
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) addNamespace(ns *v1.Namespace) bool {
	if "" == m.nsLabel {
		return false
	}
	_, found := ns.ObjectMeta.Labels[m.nsLabel]
	if found {
		m.appMgr.nsInformer.GetStore().Add(ns)
		m.appMgr.syncNamespace(ns.ObjectMeta.Name)
	}
	return found
}

func (m *mockAppManager) getFakeEvents(ns string) []FakeEvent {
	nen := m.appMgr.eventNotifier.getNotifierForNamespace(ns)
	if nil != nen {
		fakeRecorder := nen.recorder.(*FakeEventRecorder)
		return fakeRecorder.Events
	}
	return []FakeEvent{}
}

func generateExpectedAddrs(port int32, ips []string) []Member {
	var ret []Member
	for _, ip := range ips {
		member := Member{
			Address: ip,
			Port:    port,
			Session: "user-enabled",
		}
		ret = append(ret, member)
	}
	return ret
}

func convertSvcPortsToEndpointPorts(svcPorts []v1.ServicePort) []v1.EndpointPort {
	eps := make([]v1.EndpointPort, len(svcPorts))
	for i, v := range svcPorts {
		eps[i].Name = v.Name
		eps[i].Port = v.Port
	}
	return eps
}

func newServicePort(name string, svcPort int32) v1.ServicePort {
	return v1.ServicePort{
		Port: svcPort,
		Name: name,
	}
}

func compareVirtuals(vs, expected Virtual) {
	Expect(vs.Name).To(Equal(expected.Name))
	Expect(vs.PoolName).To(Equal(expected.PoolName))
	Expect(vs.Destination).To(Equal(expected.Destination))
	Expect(vs.Enabled).To(Equal(expected.Enabled))
	Expect(vs.IpProtocol).To(Equal(expected.IpProtocol))
	Expect(vs.SourceAddrTranslation).To(Equal(expected.SourceAddrTranslation))
	Expect(vs.Policies).To(Equal(expected.Policies))
	Expect(vs.IRules).To(Equal(expected.IRules))
	Expect(vs.Profiles).To(Equal(expected.Profiles))
	Expect(vs.Description).To(Equal(expected.Description))
}

func comparePools(pool, expected Pool) {
	Expect(pool.Name).To(Equal(expected.Name))
	Expect(pool.Balance).To(Equal(expected.Balance))
	Expect(pool.Members).To(Equal(expected.Members))
	Expect(pool.MonitorNames).To(Equal(expected.MonitorNames))
}

func compareMonitors(mon, expected Monitor) {
	Expect(mon.Name).To(Equal(expected.Name))
	Expect(mon.Interval).To(Equal(expected.Interval))
	Expect(mon.Type).To(Equal(expected.Type))
	Expect(mon.Send).To(Equal(expected.Send))
	Expect(mon.Recv).To(Equal(expected.Recv))
	Expect(mon.Timeout).To(Equal(expected.Timeout))
}

func validateConfig(mw *test.MockWriter, expected string) {
	mw.Lock()
	_, ok := mw.Sections["resources"].(PartitionMap)
	mw.Unlock()
	Expect(ok).To(BeTrue())

	resources := struct {
		Resources PartitionMap `json:"resources"`
	}{
		Resources: mw.Sections["resources"].(PartitionMap),
	}

	// Read JSON from exepectedOutput into array of structs
	expectedOutput := struct {
		Resources PartitionMap `json:"resources"`
	}{
		Resources: PartitionMap{},
	}

	err := json.Unmarshal([]byte(expected), &expectedOutput)
	if nil != err {
		Expect(err).To(BeNil())
		return
	}

	for partition, config := range resources.Resources {
		for expPartition, expCfg := range expectedOutput.Resources {
			if partition == expPartition {
				// Sort Resource Configs for comparison
				config.SortVirtuals()
				config.SortPools()
				config.SortMonitors()
				expCfg.SortVirtuals()
				expCfg.SortPools()
				expCfg.SortMonitors()

				for i, rs := range expCfg.Virtuals {
					ExpectWithOffset(1, i).To(BeNumerically("<", len(config.Virtuals)))
					compareVirtuals(rs, config.Virtuals[i])
				}
				for i, rs := range expCfg.Pools {
					ExpectWithOffset(1, i).To(BeNumerically("<", len(config.Pools)))
					comparePools(rs, config.Pools[i])
				}
				for i, rs := range expCfg.Monitors {
					ExpectWithOffset(1, i).To(BeNumerically("<", len(config.Monitors)))
					compareMonitors(rs, config.Monitors[i])
				}
			}
		}
	}
}

func validateServiceIps(serviceName, namespace string, svcPorts []v1.ServicePort,
	ips []string, resources *Resources) {
	for _, p := range svcPorts {
		cfgs := resources.GetAll(serviceKey{serviceName, p.Port, namespace})
		Expect(cfgs).ToNot(BeNil())
		for _, cfg := range cfgs {
			var expectedIps []Member
			if ips != nil {
				for _, ip := range ips {
					member := Member{
						Address: ip,
						Port:    p.Port,
						Session: "user-enabled",
					}
					expectedIps = append(expectedIps, member)
				}
			}
			Expect(cfg.Pools[0].Members).To(Equal(expectedIps))
		}
	}
}

var _ = Describe("AppManager Tests", func() {
	Describe("Output Config", func() {
		It("TestVirtualServerSendFail", func() {
			mw := &test.MockWriter{
				FailStyle: test.ImmediateFail,
				Sections:  make(map[string]interface{}),
			}
			appMgr := NewManager(&Params{ConfigWriter: mw})
			Expect(func() { appMgr.outputConfig() }).ToNot(Panic())
			Expect(mw.WrittenTimes).To(Equal(1))
		})

		It("TestVirtualServerSendFailAsync", func() {
			mw := &test.MockWriter{
				FailStyle: test.AsyncFail,
				Sections:  make(map[string]interface{}),
			}
			appMgr := NewManager(&Params{ConfigWriter: mw})
			Expect(func() { appMgr.outputConfig() }).ToNot(Panic())
			Expect(mw.WrittenTimes).To(Equal(1))
		})

		It("TestVirtualServerSendFailTimeout", func() {
			mw := &test.MockWriter{
				FailStyle: test.Timeout,
				Sections:  make(map[string]interface{}),
			}
			appMgr := NewManager(&Params{ConfigWriter: mw})
			Expect(func() { appMgr.outputConfig() }).ToNot(Panic())
			Expect(mw.WrittenTimes).To(Equal(1))
		})
	})

	Describe("Using Real Manager", func() {
		var appMgr *Manager
		var mw *test.MockWriter
		BeforeEach(func() {
			mw = &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			appMgr = NewManager(&Params{
				ConfigWriter: mw,
				IsNodePort:   true,
				initialState: true,
			})
		})

		It("should ignore unschedulable with node label", func() {
			// appMgr with node label
			appMgr = NewManager(&Params{
				ConfigWriter:      mw,
				IsNodePort:        true,
				initialState:      true,
				NodeLabelSelector: "label",
				UseNodeInternal:   false,
			})

			expectedNodes := []*v1.Node{
				test.NewNode("node0", "0", true, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.0"}}, []v1.Taint{}),
				test.NewNode("node1", "1", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.1"}},
					[]v1.Taint{
						{
							Key:    "node-role.kubernetes.io/worker",
							Effect: v1.TaintEffectPreferNoSchedule,
						},
					}),
				test.NewNode("node2", "2", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.2"}},
					[]v1.Taint{
						{
							Key:    "node-role.kubernetes.io/worker",
							Effect: v1.TaintEffectNoSchedule,
						},
					}),
				test.NewNode("node3", "3", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.3"}}, []v1.Taint{}),
			}

			expectedReturn := []string{
				"127.0.0.0",
				"127.0.0.1",
				"127.0.0.2",
				"127.0.0.3",
			}

			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			for _, expectedNode := range expectedNodes {
				node, err := fakeClient.Core().Nodes().Create(expectedNode)
				Expect(err).To(BeNil(), "Should not fail creating node.")
				Expect(node).To(Equal(expectedNode))
			}

			nodes, err := fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			addresses, err := appMgr.getNodeAddresses(nodes.Items)
			Expect(err).To(BeNil(), "Should not fail getting addresses.")
			Expect(addresses).To(Equal(expectedReturn))
		})

		It("should get addresses", func() {
			// Existing Node data
			expectedNodes := []*v1.Node{
				test.NewNode("node0", "0", true, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.0"}}, []v1.Taint{}),
				test.NewNode("node1", "1", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.1"}},
					[]v1.Taint{
						{
							Key:    "node-role.kubernetes.io/worker",
							Effect: v1.TaintEffectPreferNoSchedule,
						},
					}),
				test.NewNode("node2", "2", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.2"}}, []v1.Taint{}),
				test.NewNode("node3", "3", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.3"}}, []v1.Taint{}),
				test.NewNode("node4", "4", false, []v1.NodeAddress{
					{"InternalIP", "127.0.0.4"}}, []v1.Taint{}),
				test.NewNode("node5", "5", false, []v1.NodeAddress{
					{"Hostname", "127.0.0.5"}}, []v1.Taint{}),
				test.NewNode("node6", "6", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.6"}},
					[]v1.Taint{
						{
							Key:    "node-role.kubernetes.io/worker",
							Effect: v1.TaintEffectNoSchedule,
						},
					}),
			}

			expectedReturn := []string{
				"127.0.0.1",
				"127.0.0.2",
				"127.0.0.3",
			}

			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			for _, expectedNode := range expectedNodes {
				node, err := fakeClient.Core().Nodes().Create(expectedNode)
				Expect(err).To(BeNil(), "Should not fail creating node.")
				Expect(node).To(Equal(expectedNode))
			}

			appMgr.useNodeInternal = false
			nodes, err := fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			addresses, err := appMgr.getNodeAddresses(nodes.Items)
			Expect(err).To(BeNil(), "Should not fail getting addresses.")
			Expect(addresses).To(Equal(expectedReturn))

			// test filtering
			expectedInternal := []string{
				"127.0.0.4",
			}

			appMgr.useNodeInternal = true
			addresses, err = appMgr.getNodeAddresses(nodes.Items)
			Expect(err).To(BeNil(), "Should not fail getting internal addresses.")
			Expect(addresses).To(Equal(expectedInternal))

			for _, node := range expectedNodes {
				err := fakeClient.Core().Nodes().Delete(node.ObjectMeta.Name,
					&metav1.DeleteOptions{})
				Expect(err).To(BeNil(), "Should not fail deleting node.")
			}

			expectedReturn = []string{}
			appMgr.useNodeInternal = false
			nodes, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			addresses, err = appMgr.getNodeAddresses(nodes.Items)
			Expect(err).To(BeNil(), "Should not fail getting empty addresses.")
			Expect(addresses).To(Equal(expectedReturn), "Should get no addresses.")
		})

		It("should process node updates", func() {
			originalSet := []v1.Node{
				*test.NewNode("node0", "0", true, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.0"}}, []v1.Taint{}),
				*test.NewNode("node1", "1", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.1"}}, []v1.Taint{}),
				*test.NewNode("node2", "2", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.2"}}, []v1.Taint{}),
				*test.NewNode("node3", "3", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.3"}}, []v1.Taint{}),
				*test.NewNode("node4", "4", false, []v1.NodeAddress{
					{"InternalIP", "127.0.0.4"}}, []v1.Taint{}),
				*test.NewNode("node5", "5", false, []v1.NodeAddress{
					{"Hostname", "127.0.0.5"}}, []v1.Taint{}),
				*test.NewNode("node6", "6", false, []v1.NodeAddress{
					{"ExternalIP", "127.0.0.6"}},
					[]v1.Taint{
						{
							Key:    "node-role.kubernetes.io/worker",
							Effect: v1.TaintEffectNoSchedule,
						},
					}),
			}

			expectedOgSet := []string{
				"127.0.0.1",
				"127.0.0.2",
				"127.0.0.3",
			}

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{Items: originalSet})
			Expect(fakeClient).ToNot(BeNil())

			appMgr.useNodeInternal = false
			nodes, err := fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			appMgr.ProcessNodeUpdate(nodes.Items, err)
			Expect(appMgr.oldNodes).To(Equal(expectedOgSet))

			cachedNodes := appMgr.getNodesFromCache()
			Expect(cachedNodes).To(Equal(appMgr.oldNodes))
			Expect(cachedNodes).To(Equal(expectedOgSet))

			// test filtering
			expectedInternal := []string{
				"127.0.0.4",
			}

			appMgr.useNodeInternal = true
			nodes, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			appMgr.ProcessNodeUpdate(nodes.Items, err)
			Expect(appMgr.oldNodes).To(Equal(expectedInternal))

			cachedNodes = appMgr.getNodesFromCache()
			Expect(cachedNodes).To(Equal(appMgr.oldNodes))
			Expect(cachedNodes).To(Equal(expectedInternal))

			// add some nodes
			_, err = fakeClient.Core().Nodes().Create(test.NewNode("nodeAdd", "nodeAdd", false,
				[]v1.NodeAddress{{"ExternalIP", "127.0.0.6"}}, []v1.Taint{}))
			Expect(err).To(BeNil(), "Create should not return err.")

			_, err = fakeClient.Core().Nodes().Create(test.NewNode("nodeExclude", "nodeExclude",
				true, []v1.NodeAddress{{"InternalIP", "127.0.0.7"}}, []v1.Taint{}))

			appMgr.useNodeInternal = false
			nodes, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			appMgr.ProcessNodeUpdate(nodes.Items, err)
			expectedAddSet := append(expectedOgSet, "127.0.0.6")

			Expect(appMgr.oldNodes).To(Equal(expectedAddSet))

			cachedNodes = appMgr.getNodesFromCache()
			Expect(cachedNodes).To(Equal(appMgr.oldNodes))
			Expect(cachedNodes).To(Equal(expectedAddSet))

			// make no changes and re-run process
			appMgr.useNodeInternal = false
			nodes, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			appMgr.ProcessNodeUpdate(nodes.Items, err)
			expectedAddSet = append(expectedOgSet, "127.0.0.6")

			Expect(appMgr.oldNodes).To(Equal(expectedAddSet))

			cachedNodes = appMgr.getNodesFromCache()
			Expect(cachedNodes).To(Equal(appMgr.oldNodes))
			Expect(cachedNodes).To(Equal(expectedAddSet))

			// remove nodes
			err = fakeClient.Core().Nodes().Delete("node1", &metav1.DeleteOptions{})
			Expect(err).To(BeNil())
			fakeClient.Core().Nodes().Delete("node2", &metav1.DeleteOptions{})
			Expect(err).To(BeNil())
			fakeClient.Core().Nodes().Delete("node3", &metav1.DeleteOptions{})
			Expect(err).To(BeNil())

			expectedDelSet := []string{"127.0.0.6"}

			appMgr.useNodeInternal = false
			nodes, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
			Expect(err).To(BeNil(), "Should not fail listing nodes.")
			appMgr.ProcessNodeUpdate(nodes.Items, err)

			Expect(appMgr.oldNodes).To(Equal(expectedDelSet))

			cachedNodes = appMgr.getNodesFromCache()
			Expect(cachedNodes).To(Equal(appMgr.oldNodes))
			Expect(cachedNodes).To(Equal(expectedDelSet))
		})
	})

	Describe("Using Mock Manager", func() {
		var mockMgr *mockAppManager
		var mw *test.MockWriter
		BeforeEach(func() {
			RegisterBigIPSchemaTypes()

			mw = &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			mockMgr = newMockAppManager(&Params{
				KubeClient:      fakeClient,
				ConfigWriter:    mw,
				restClient:      test.CreateFakeHTTPClient(),
				RouteClientV1:   test.CreateFakeHTTPClient(),
				IsNodePort:      true,
				broadcasterFunc: NewFakeEventBroadcaster,
			})
		})
		AfterEach(func() {
			mockMgr.shutdown()
		})

		Context("non-namespace related", func() {
			var namespace string
			BeforeEach(func() {
				namespace = "default"
				err := mockMgr.startNonLabelMode([]string{namespace})
				Expect(err).To(BeNil())
			})

			testOverwriteAddImpl := func(isNodePort bool) {
				mockMgr.appMgr.isNodePort = isNodePort
				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})

				r := mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1),
					"Virtual servers should have entry.")
				_, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())

				// ConfigMap with TCP
				cfgFoo = test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFooTcp})

				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1),
					"Virtual servers should have entry.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())

				// ConfigMap with UDP
				cfgFoo = test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFooUdp})

				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1),
					"Virtual servers should have entry.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
			}

			It("should overwrite add - NodePort", func() {
				testOverwriteAddImpl(true)
			})

			It("should overwrite add - Cluster", func() {
				testOverwriteAddImpl(false)
			})

			testServiceChangeUpdateImpl := func(isNodePort bool) {
				mockMgr.appMgr.isNodePort = isNodePort
				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})

				r := mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1),
					"Virtual servers should have entry.")

				cfgFoo8080 := test.NewConfigMap("foomap", "2", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})

				r = mockMgr.updateConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(Equal(1),
					"Virtual servers should have entry.")
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(0),
					"Virtual servers should have old config removed.")
			}

			It("updates when service changes - NodePort", func() {
				testServiceChangeUpdateImpl(true)
			})

			It("updates when service changes - Cluster", func() {
				testServiceChangeUpdateImpl(false)
			})

			It("handles service ports being removed - NodePort", func() {
				mockMgr.appMgr.useNodeInternal = true

				nodeSet := []v1.Node{
					*test.NewNode("node0", "0", false, []v1.NodeAddress{
						{"InternalIP", "127.0.0.0"}}, []v1.Taint{}),
					*test.NewNode("node1", "1", false, []v1.NodeAddress{
						{"InternalIP", "127.0.0.1"}}, []v1.Taint{}),
					*test.NewNode("node2", "2", false, []v1.NodeAddress{
						{"InternalIP", "127.0.0.2"}}, []v1.Taint{}),
				}

				mockMgr.processNodeUpdate(nodeSet, nil)

				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				cfgFoo8080 := test.NewConfigMap("foomap8080", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})
				cfgFoo9090 := test.NewConfigMap("foomap9090", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo9090})

				foo := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 30001},
						{Port: 8080, NodePort: 38001},
						{Port: 9090, NodePort: 39001}})
				r := mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addConfigMap(cfgFoo9090)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(3))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 9090, namespace})).To(Equal(1))

				// Create a new service with less ports and update
				newFoo := test.NewService("foo", "2", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 30001}})

				r = mockMgr.updateService(newFoo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				Expect(resources.PoolCount()).To(Equal(3))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 9090, namespace})).To(Equal(1))

				addrs := []string{
					"127.0.0.0",
					"127.0.0.1",
					"127.0.0.2",
				}
				rs, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(30001, addrs)),
					"Existing NodePort should be set on address.")
				rs, ok = resources.Get(
					serviceKey{"foo", 8080, namespace}, formatConfigMapVSName(cfgFoo8080))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeFalse())
				rs, ok = resources.Get(
					serviceKey{"foo", 9090, namespace}, formatConfigMapVSName(cfgFoo9090))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeFalse())

				// Re-add port in new service
				newFoo2 := test.NewService("foo", "3", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 20001},
						{Port: 8080, NodePort: 45454}})

				r = mockMgr.updateService(newFoo2)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(3))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 9090, namespace})).To(Equal(1))

				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(20001, addrs)),
					"Existing NodePort should be set on address.")
				rs, ok = resources.Get(
					serviceKey{"foo", 8080, namespace}, formatConfigMapVSName(cfgFoo8080))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(45454, addrs)),
					"Existing NodePort should be set on address.")
				rs, ok = resources.Get(
					serviceKey{"foo", 9090, namespace}, formatConfigMapVSName(cfgFoo9090))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeFalse())
			})

			It("handles concurrent updates - NodePort", func() {
				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				cfgBar := test.NewConfigMap("barmap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapBar})
				foo := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 30001}})
				bar := test.NewService("bar", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				nodes := []*v1.Node{
					test.NewNode("node0", "0", true, []v1.NodeAddress{
						{"ExternalIP", "127.0.0.0"}}, []v1.Taint{}),
					test.NewNode("node1", "1", false, []v1.NodeAddress{
						{"ExternalIP", "127.0.0.1"}}, []v1.Taint{}),
					test.NewNode("node2", "2", false, []v1.NodeAddress{
						{"ExternalIP", "127.0.0.2"}}, []v1.Taint{}),
				}
				extraNode := test.NewNode("node3", "3", false,
					[]v1.NodeAddress{{"ExternalIP", "127.0.0.3"}}, []v1.Taint{})

				nodeCh := make(chan struct{})
				mapCh := make(chan struct{})
				serviceCh := make(chan struct{})

				go func() {
					defer GinkgoRecover()
					for _, node := range nodes {
						n, err := mockMgr.appMgr.kubeClient.Core().Nodes().Create(node)
						Expect(err).To(BeNil(), "Should not fail creating node.")
						Expect(n).To(Equal(node))

						nodes, err := mockMgr.appMgr.kubeClient.Core().Nodes().List(metav1.ListOptions{})
						Expect(err).To(BeNil(), "Should not fail listing nodes.")
						mockMgr.processNodeUpdate(nodes.Items, err)
					}

					nodeCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.addConfigMap(cfgFoo)
					Expect(r).To(BeTrue(), "ConfigMap should be processed.")

					r = mockMgr.addConfigMap(cfgBar)
					Expect(r).To(BeTrue(), "ConfigMap should be processed.")

					mapCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.addService(foo)
					Expect(r).To(BeTrue(), "Service should be processed.")

					r = mockMgr.addService(bar)
					Expect(r).To(BeTrue(), "Service should be processed.")

					serviceCh <- struct{}{}
				}()

				select {
				case <-nodeCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting node channel notification.")
				}
				select {
				case <-mapCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting node channel notification.")
				}
				select {
				case <-serviceCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting node channel notification.")
				}

				validateConfig(mw, twoSvcsTwoNodesConfig)
				resources := mockMgr.resources()

				go func() {
					defer GinkgoRecover()
					err := mockMgr.appMgr.kubeClient.Core().Nodes().Delete("node1", &metav1.DeleteOptions{})
					Expect(err).To(BeNil())
					err = mockMgr.appMgr.kubeClient.Core().Nodes().Delete("node2", &metav1.DeleteOptions{})
					Expect(err).To(BeNil())
					_, err = mockMgr.appMgr.kubeClient.Core().Nodes().Create(extraNode)
					Expect(err).To(BeNil())
					nodes, err := mockMgr.appMgr.kubeClient.Core().Nodes().List(metav1.ListOptions{})
					Expect(err).To(BeNil(), "Should not fail listing nodes.")
					mockMgr.processNodeUpdate(nodes.Items, err)

					nodeCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.deleteConfigMap(cfgFoo)
					Expect(r).To(BeTrue(), "ConfigMap should be processed.")
					Expect(resources.PoolCount()).To(Equal(1))

					mapCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.deleteService(foo)
					Expect(r).To(BeTrue(), "Service should be processed.")

					serviceCh <- struct{}{}
				}()

				select {
				case <-nodeCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting node channel notification.")
				}
				select {
				case <-mapCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting node channel notification.")
				}
				select {
				case <-serviceCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting node channel notification.")
				}

				validateConfig(mw, oneSvcOneNodeConfig)
			})

			It("handles concurrent updates - Cluster", func() {
				mockMgr.appMgr.isNodePort = false
				fooIps := []string{"10.2.96.1", "10.2.96.2"}
				fooPorts := []v1.ServicePort{newServicePort("port0", 8080)}
				barIps := []string{"10.2.96.0", "10.2.96.3"}
				barPorts := []v1.ServicePort{newServicePort("port1", 80)}

				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})
				cfgBar := test.NewConfigMap("barmap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapBar})

				foo := test.NewService("foo", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
				bar := test.NewService("bar", "1", namespace, v1.ServiceTypeClusterIP, barPorts)

				fooEndpts := test.NewEndpoints("foo", "1", namespace, fooIps, barIps,
					convertSvcPortsToEndpointPorts(fooPorts))
				barEndpts := test.NewEndpoints("bar", "1", namespace, barIps, fooIps,
					convertSvcPortsToEndpointPorts(barPorts))
				cfgCh := make(chan struct{})
				endptCh := make(chan struct{})
				svcCh := make(chan struct{})
				resources := mockMgr.resources()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.addEndpoints(fooEndpts)
					Expect(r).To(BeTrue(), "Endpoints should be processed.")
					r = mockMgr.addEndpoints(barEndpts)
					Expect(r).To(BeTrue(), "Endpoints should be processed.")

					endptCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.addConfigMap(cfgFoo)
					Expect(r).To(BeTrue(), "ConfigMap should be processed.")

					r = mockMgr.addConfigMap(cfgBar)
					Expect(r).To(BeTrue(), "ConfigMap should be processed.")

					cfgCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					r := mockMgr.addService(foo)
					Expect(r).To(BeTrue(), "Service should be processed.")

					r = mockMgr.addService(bar)
					Expect(r).To(BeTrue(), "Service should be processed.")

					svcCh <- struct{}{}
				}()

				select {
				case <-endptCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting endpoints channel notification.")
				}
				select {
				case <-cfgCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting configmap channel notification.")
				}
				select {
				case <-svcCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting service channel notification.")
				}

				validateConfig(mw, twoSvcTwoPodsConfig)

				go func() {
					defer GinkgoRecover()
					// delete endpoints for foo
					r := mockMgr.deleteEndpoints(fooEndpts)
					Expect(r).To(BeTrue(), "Endpoints should be processed.")

					endptCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					// delete cfgmap for foo
					r := mockMgr.deleteConfigMap(cfgFoo)
					Expect(r).To(BeTrue(), "ConfigMap should be processed.")

					cfgCh <- struct{}{}
				}()

				go func() {
					defer GinkgoRecover()
					// Delete service for foo
					r := mockMgr.deleteService(foo)
					Expect(r).To(BeTrue(), "Service should be processed.")

					svcCh <- struct{}{}
				}()

				select {
				case <-endptCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting endpoints channel notification.")
				}
				select {
				case <-cfgCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting configmap channel notification.")
				}
				select {
				case <-svcCh:
				case <-time.After(time.Second * 30):
					Fail("Timed out expecting service channel notification.")
				}
				Expect(resources.PoolCount()).To(Equal(1))
				validateConfig(mw, oneSvcTwoPodsConfig)
			})

			It("processes updates - NodePort", func() {
				// Create a test env with two ConfigMaps, two Services, and three Nodes
				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				cfgFoo8080 := test.NewConfigMap("foomap8080", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})
				cfgFoo9090 := test.NewConfigMap("foomap9090", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo9090})
				cfgBar := test.NewConfigMap("barmap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapBar})
				foo := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 30001},
						{Port: 8080, NodePort: 38001},
						{Port: 9090, NodePort: 39001}})
				bar := test.NewService("bar", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				nodes := []v1.Node{
					*test.NewNode("node0", "0", true, []v1.NodeAddress{
						{"ExternalIP", "127.0.0.0"}}, []v1.Taint{}),
					*test.NewNode("node1", "1", false, []v1.NodeAddress{
						{"ExternalIP", "127.0.0.1"}}, []v1.Taint{}),
					*test.NewNode("node2", "2", false, []v1.NodeAddress{
						{"ExternalIP", "127.0.0.2"}}, []v1.Taint{}),
				}
				extraNode := test.NewNode("node3", "3", false,
					[]v1.NodeAddress{{"ExternalIP", "127.0.0.3"}}, []v1.Taint{})

				addrs := []string{"127.0.0.1", "127.0.0.2"}

				fakeClient := fake.NewSimpleClientset(&v1.NodeList{Items: nodes})
				Expect(fakeClient).ToNot(BeNil())
				mockMgr.appMgr.kubeClient = fakeClient

				n, err := fakeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(n.Items)).To(Equal(3))

				mockMgr.processNodeUpdate(n.Items, err)

				// ConfigMap added
				r := mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))
				rs, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())

				// Second ConfigMap added
				r = mockMgr.addConfigMap(cfgBar)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeFalse())
				rs, ok = resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(cfgBar))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeFalse())

				// Service ADDED
				r = mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(30001, addrs)))

				// Second Service ADDED
				r = mockMgr.addService(bar)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(cfgBar))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, addrs)))

				// ConfigMap ADDED second foo port
				r = mockMgr.addConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(3))
				rs, ok = resources.Get(
					serviceKey{"foo", 8080, namespace}, formatConfigMapVSName(cfgFoo8080))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(38001, addrs)))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(30001, addrs)))
				rs, ok = resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(cfgBar))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, addrs)))

				// ConfigMap ADDED third foo port
				r = mockMgr.addConfigMap(cfgFoo9090)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(4))
				rs, ok = resources.Get(
					serviceKey{"foo", 9090, namespace}, formatConfigMapVSName(cfgFoo9090))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(39001, addrs)))
				rs, ok = resources.Get(
					serviceKey{"foo", 8080, namespace}, formatConfigMapVSName(cfgFoo8080))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(38001, addrs)))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(30001, addrs)))
				rs, ok = resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(cfgBar))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, addrs)))

				// Nodes ADDED
				_, err = fakeClient.Core().Nodes().Create(extraNode)
				Expect(err).To(BeNil())
				n, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)
				Expect(resources.PoolCount()).To(Equal(4))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(30001, append(addrs, "127.0.0.3"))))
				rs, ok = resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(cfgBar))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(37001, append(addrs, "127.0.0.3"))))
				rs, ok = resources.Get(
					serviceKey{"foo", 8080, namespace}, formatConfigMapVSName(cfgFoo8080))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(38001, append(addrs, "127.0.0.3"))))
				rs, ok = resources.Get(
					serviceKey{"foo", 9090, namespace}, formatConfigMapVSName(cfgFoo9090))
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(39001, append(addrs, "127.0.0.3"))))
				validateConfig(mw, twoSvcsFourPortsThreeNodesConfig)

				// ConfigMap DELETED third foo port
				r = mockMgr.deleteConfigMap(cfgFoo9090)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(3))
				Expect(resources.CountOf(serviceKey{"foo", 9090, namespace})).To(
					Equal(0), "Virtual servers should not contain removed port.")
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")
				Expect(resources.CountOf(serviceKey{"bar", 80, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")

				// ConfigMap UPDATED second foo port
				r = mockMgr.updateConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(3))
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")
				Expect(resources.CountOf(serviceKey{"bar", 80, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")

				// ConfigMap DELETED second foo port
				r = mockMgr.deleteConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				Expect(resources.CountOf(serviceKey{"foo", 8080, namespace})).To(
					Equal(0), "Virtual servers should not contain removed port.")
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")
				Expect(resources.CountOf(serviceKey{"bar", 80, namespace})).To(
					Equal(1), "Virtual servers should contain remaining ports.")

				// Nodes DELETED
				err = fakeClient.Core().Nodes().Delete("node1", &metav1.DeleteOptions{})
				Expect(err).To(BeNil())
				err = fakeClient.Core().Nodes().Delete("node2", &metav1.DeleteOptions{})
				Expect(err).To(BeNil())
				n, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(30001, []string{"127.0.0.3"})))
				rs, ok = resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(cfgBar))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(37001, []string{"127.0.0.3"})))
				validateConfig(mw, twoSvcsOneNodeConfig)

				// ConfigMap DELETED
				r = mockMgr.deleteConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(
					Equal(0), "Config map should be removed after delete.")
				validateConfig(mw, oneSvcOneNodeConfig)

				// Service deleted
				r = mockMgr.deleteService(bar)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				validateConfig(mw, emptyConfig)
			})

			testConfigMapKeysImpl := func(isNodePort bool) {
				mockMgr.appMgr.isNodePort = isNodePort

				// Config map with no schema key
				noschemakey := test.NewConfigMap("noschema", "1", namespace,
					map[string]string{"data": configmapFoo})
				cfg, err := parseConfigMap(noschemakey)
				Expect(err.Error()).To(Equal("configmap noschema does not contain schema key"),
					"Should receive 'no schema' error.")
				r := mockMgr.addConfigMap(noschemakey)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(0))

				// Config map with no data key
				nodatakey := test.NewConfigMap("nodata", "1", namespace, map[string]string{
					"schema": schemaUrl,
				})
				cfg, err = parseConfigMap(nodatakey)
				Expect(cfg).To(BeNil(), "Should not have parsed bad configmap.")
				Expect(err.Error()).To(Equal("configmap nodata does not contain data key"),
					"Should receive 'no data' error.")
				r = mockMgr.addConfigMap(nodatakey)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				Expect(resources.PoolCount()).To(Equal(0))

				// Config map with bad json
				badjson := test.NewConfigMap("badjson", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   "///// **invalid json** /////",
				})
				cfg, err = parseConfigMap(badjson)
				Expect(cfg).To(BeNil(), "Should not have parsed bad configmap.")
				Expect(err.Error()).To(Equal(
					"invalid character '/' looking for beginning of value"))
				r = mockMgr.addConfigMap(badjson)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				Expect(resources.PoolCount()).To(Equal(0))

				// Config map with extra keys
				extrakeys := test.NewConfigMap("extrakeys", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo,
					"key1":   "value1",
					"key2":   "value2",
				})
				cfg, err = parseConfigMap(extrakeys)
				Expect(cfg).ToNot(BeNil(), "Config map should parse with extra keys.")
				Expect(err).To(BeNil(), "Should not receive errors.")
				r = mockMgr.addConfigMap(extrakeys)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				resources.Delete(serviceKey{"foo", 80, namespace},
					formatConfigMapVSName(extrakeys))

				// Config map with no mode or balance
				defaultModeAndBalance := test.NewConfigMap("mode_balance", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapNoModeBalance,
				})
				cfg, err = parseConfigMap(defaultModeAndBalance)
				Expect(cfg).ToNot(BeNil(), "Config map should exist and contain default mode and balance.")
				Expect(err).To(BeNil(), "Should not receive errors.")
				r = mockMgr.addConfigMap(defaultModeAndBalance)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))

				rs, ok := resources.Get(
					serviceKey{"bar", 80, namespace}, formatConfigMapVSName(defaultModeAndBalance))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs).ToNot(BeNil(), "Config map should be object.")

				Expect(rs.Pools[0].Balance).To(Equal("round-robin"))
				Expect(rs.Virtual.Partition).To(Equal("velcro"))
				Expect(rs.Virtual.VirtualAddress.BindAddr).To(Equal("10.128.10.240"))
				Expect(rs.Virtual.VirtualAddress.Port).To(Equal(int32(80)))
			}

			It("properly handles ConfigMap keys - NodePort", func() {
				testConfigMapKeysImpl(true)
			})

			It("properly handles ConfigMap keys - Cluster", func() {
				testConfigMapKeysImpl(false)
			})

			It("isolates namespaces", func() {
				mockMgr.appMgr.useNodeInternal = true
				wrongNamespace := "wrongnamespace"

				node := test.NewNode("node3", "3", false,
					[]v1.NodeAddress{{"InternalIP", "127.0.0.3"}}, []v1.Taint{})
				_, err := mockMgr.appMgr.kubeClient.Core().Nodes().Create(node)
				Expect(err).To(BeNil())
				n, err := mockMgr.appMgr.kubeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)

				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				cfgBar := test.NewConfigMap("foomap", "1", wrongNamespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				servFoo := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				servBar := test.NewService("foo", "1", wrongNamespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 50000}})

				r := mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				resources := mockMgr.resources()
				_, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")

				r = mockMgr.addConfigMap(cfgBar)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, wrongNamespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeFalse(), "Config map should not be added if namespace does not match flag.")
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(
					Equal(1), "Virtual servers should contain original config.")
				Expect(resources.PoolCount()).To(Equal(1))

				r = mockMgr.updateConfigMap(cfgBar)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, wrongNamespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeFalse(), "Config map should not be added if namespace does not match flag.")
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(
					Equal(1), "Virtual servers should contain original config.")
				Expect(resources.PoolCount()).To(Equal(1))

				r = mockMgr.deleteConfigMap(cfgBar)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, wrongNamespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeFalse(), "Config map should not be added if namespace does not match flag.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue(), "Config map should be accessible after delete called on incorrect namespace.")

				r = mockMgr.addService(servFoo)
				Expect(r).To(BeTrue(), "Service should be processed.")
				rs, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue(), "Service should be accessible.")
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, []string{"127.0.0.3"})))

				r = mockMgr.addService(servBar)
				Expect(r).To(BeFalse(), "Service should not be processed.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, wrongNamespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeFalse(), "Service should not be added if namespace does not match flag.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue(), "Service should be accessible.")
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, []string{"127.0.0.3"})))

				r = mockMgr.updateService(servBar)
				Expect(r).To(BeFalse(), "Service should not be processed.")
				_, ok = resources.Get(
					serviceKey{"foo", 80, wrongNamespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeFalse(), "Service should not be added if namespace does not match flag.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue(), "Service should be accessible.")
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, []string{"127.0.0.3"})))

				r = mockMgr.deleteService(servBar)
				Expect(r).To(BeFalse(), "Service should not be processed.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
				Expect(ok).To(BeTrue(), "Service should not have been deleted.")
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, []string{"127.0.0.3"})))
			})

			It("processes Iapp updates - NodePort", func() {
				mockMgr.appMgr.useNodeInternal = true
				// Create a test env with two ConfigMaps, two Services, and three Nodes
				cfgIapp1 := test.NewConfigMap("iapp1map", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapIApp1})
				cfgIapp2 := test.NewConfigMap("iapp2map", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapIApp2})
				iapp1 := test.NewService("iapp1", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 10101}})
				iapp2 := test.NewService("iapp2", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 20202}})
				nodes := []v1.Node{
					*test.NewNode("node0", "0", true, []v1.NodeAddress{
						{"InternalIP", "192.168.0.0"}}, []v1.Taint{}),
					*test.NewNode("node1", "1", false, []v1.NodeAddress{
						{"InternalIP", "192.168.0.1"}}, []v1.Taint{}),
					*test.NewNode("node2", "2", false, []v1.NodeAddress{
						{"InternalIP", "192.168.0.2"}}, []v1.Taint{}),
					*test.NewNode("node3", "3", false, []v1.NodeAddress{
						{"ExternalIP", "192.168.0.3"}}, []v1.Taint{}),
				}
				extraNode := test.NewNode("node4", "4", false, []v1.NodeAddress{{"InternalIP",
					"192.168.0.4"}}, []v1.Taint{})

				addrs := []string{"192.168.0.1", "192.168.0.2"}

				fakeClient := fake.NewSimpleClientset(&v1.NodeList{Items: nodes})
				Expect(fakeClient).ToNot(BeNil(), "Mock client cannot be nil.")

				n, err := fakeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(n.Items)).To(Equal(4))

				mockMgr.processNodeUpdate(n.Items, err)

				// ConfigMap ADDED
				r := mockMgr.addConfigMap(cfgIapp1)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))
				rs, ok := resources.Get(
					serviceKey{"iapp1", 80, namespace}, formatConfigMapVSName(cfgIapp1))
				Expect(ok).To(BeTrue())

				// Second ConfigMap ADDED
				r = mockMgr.addConfigMap(cfgIapp2)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"iapp1", 80, namespace}, formatConfigMapVSName(cfgIapp1))
				Expect(ok).To(BeTrue())

				// Service ADDED
				r = mockMgr.addService(iapp1)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"iapp1", 80, namespace}, formatConfigMapVSName(cfgIapp1))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(10101, addrs)))

				// Second Service ADDED
				r = mockMgr.addService(iapp2)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"iapp1", 80, namespace}, formatConfigMapVSName(cfgIapp1))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(10101, addrs)))
				rs, ok = resources.Get(
					serviceKey{"iapp2", 80, namespace}, formatConfigMapVSName(cfgIapp2))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(20202, addrs)))

				// ConfigMap UPDATED
				r = mockMgr.updateConfigMap(cfgIapp1)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))

				// Service UPDATED
				r = mockMgr.updateService(iapp1)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))

				// Nodes ADDED
				_, err = fakeClient.Core().Nodes().Create(extraNode)
				Expect(err).To(BeNil())
				n, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"iapp1", 80, namespace}, formatConfigMapVSName(cfgIapp1))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(10101, append(addrs, "192.168.0.4"))))
				rs, ok = resources.Get(
					serviceKey{"iapp2", 80, namespace}, formatConfigMapVSName(cfgIapp2))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(20202, append(addrs, "192.168.0.4"))))
				validateConfig(mw, twoIappsThreeNodesConfig)

				// Nodes DELETED
				err = fakeClient.Core().Nodes().Delete("node1", &metav1.DeleteOptions{})
				Expect(err).To(BeNil())
				err = fakeClient.Core().Nodes().Delete("node2", &metav1.DeleteOptions{})
				Expect(err).To(BeNil())
				n, err = fakeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"iapp1", 80, namespace}, formatConfigMapVSName(cfgIapp1))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(10101, []string{"192.168.0.4"})))
				rs, ok = resources.Get(
					serviceKey{"iapp2", 80, namespace}, formatConfigMapVSName(cfgIapp2))
				Expect(ok).To(BeTrue())
				Expect(rs.Pools[0].Members).To(
					Equal(generateExpectedAddrs(20202, []string{"192.168.0.4"})))
				validateConfig(mw, twoIappsOneNodeConfig)

				// ConfigMap DELETED
				r = mockMgr.deleteConfigMap(cfgIapp1)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"iapp1", 80, namespace})).To(
					Equal(0), "Config map should be removed after delete.")
				validateConfig(mw, oneIappOneNodeConfig)

				// Service DELETED
				r = mockMgr.deleteService(iapp2)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				validateConfig(mw, emptyConfig)
			})

			testNoBindAddr := func(isNodePort bool) {
				mockMgr.appMgr.isNodePort = isNodePort
				var configmapNoBindAddr string = string(`{
				"virtualServer": {
				    "backend": {
				      "serviceName": "foo",
				      "servicePort": 80
				    },
				    "frontend": {
				      "balance": "round-robin",
				      "mode": "http",
				      "partition": "velcro",
				      "virtualAddress": {
				        "port": 10000
				      },
				      "sslProfile": {
				        "f5ProfileName": "velcro/testcert"
				      }
				    }
				  }
				}`)
				noBindAddr := test.NewConfigMap("noBindAddr", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapNoBindAddr,
				})
				_, err := parseConfigMap(noBindAddr)
				Expect(err).To(BeNil(), "Missing bindAddr should be valid.")
				r := mockMgr.addConfigMap(noBindAddr)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))

				rs, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(noBindAddr))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs).ToNot(BeNil(), "Config map should be object.")

				Expect(rs.Pools[0].Balance).To(Equal("round-robin"))
				Expect(rs.Virtual.Partition).To(Equal("velcro"))
				Expect(rs.Virtual.VirtualAddress.BindAddr).To(Equal(""))
				Expect(rs.Virtual.VirtualAddress.Port).To(Equal(int32(10000)))

				mockMgr.deleteConfigMap(noBindAddr)
			}

			testNoVirtualAddress := func(isNodePort bool) {
				mockMgr.appMgr.isNodePort = isNodePort
				var configmapNoVirtualAddress string = string(`{
				  "virtualServer": {
				    "backend": {
				      "serviceName": "foo",
				      "servicePort": 80
				    },
				    "frontend": {
				      "balance": "round-robin",
				      "mode": "http",
				      "partition": "velcro",
				      "sslProfile": {
				        "f5ProfileName": "velcro/testcert"
				      }
				    }
				  }
				}`)
				noVirtualAddress := test.NewConfigMap("noVirtualAddress", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapNoVirtualAddress,
				})
				_, err := parseConfigMap(noVirtualAddress)
				Expect(err).To(BeNil(), "Missing virtualAddress should be valid.")
				r := mockMgr.addConfigMap(noVirtualAddress)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))

				rs, ok := resources.Get(
					serviceKey{"foo", 80, namespace}, formatConfigMapVSName(noVirtualAddress))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs).ToNot(BeNil(), "Config map should be object.")

				Expect(rs.Pools[0].Balance).To(Equal("round-robin"))
				Expect(rs.Virtual.Partition).To(Equal("velcro"))
				Expect(rs.Virtual.VirtualAddress).To(BeNil())

				mockMgr.deleteConfigMap(noVirtualAddress)
			}

			It("supports pool only mode", func() {
				testNoVirtualAddress(true)
				testNoBindAddr(true)
				testNoVirtualAddress(false)
				testNoBindAddr(false)
			})

			It("doesn't manage ConfigMap in wrong partition", func() {
				//Config map with wrong partition
				DEFAULT_PARTITION = "k8s" //partition the controller has been asked to watch
				wrongPartition := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				_, err := parseConfigMap(wrongPartition)
				Expect(err).ToNot(BeNil(), "Config map with wrong partition should throw an error.")
				DEFAULT_PARTITION = "velcro"
			})

			It("configures virtual servers without endpoints", func() {
				mockMgr.appMgr.isNodePort = false
				svcName := "foo"
				emptyIps := []string{}
				readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
				notReadyIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5", "10.2.96.6"}
				svcPorts := []v1.ServicePort{
					newServicePort("port0", 80),
				}

				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})

				foo := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)

				endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
				goodEndpts := test.NewEndpoints(svcName, "1", namespace, emptyIps, emptyIps,
					endptPorts)

				r := mockMgr.addEndpoints(goodEndpts)
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				// this is for another service
				badEndpts := test.NewEndpoints("wrongSvc", "1", namespace, []string{"10.2.96.7"},
					[]string{}, endptPorts)
				r = mockMgr.addEndpoints(badEndpts)
				Expect(r).To(BeTrue(), "Endpoints should be processed.")

				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				r = mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(len(svcPorts)))
				for _, p := range svcPorts {
					Expect(resources.CountOf(serviceKey{"foo", p.Port, namespace})).To(Equal(1))
					rs, ok := resources.Get(
						serviceKey{"foo", 80, namespace}, formatConfigMapVSName(cfgFoo))
					Expect(ok).To(BeTrue())
					Expect(rs.Pools[0].Members).To(Equal([]Member(nil)))
				}

				validateServiceIps(svcName, namespace, svcPorts, nil, resources)

				// Move it back to ready from not ready and make sure it is re-added
				r = mockMgr.updateEndpoints(test.NewEndpoints(
					svcName, "2", namespace, readyIps, notReadyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, readyIps, resources)

				// Remove all endpoints make sure they are removed but virtual server exists
				r = mockMgr.updateEndpoints(test.NewEndpoints(svcName, "3", namespace, emptyIps,
					emptyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, nil, resources)

				// Move it back to ready from not ready and make sure it is re-added
				r = mockMgr.updateEndpoints(test.NewEndpoints(svcName, "4", namespace, readyIps,
					notReadyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, readyIps, resources)
			})

			It("configures virtual servers when endpoints change", func() {
				mockMgr.appMgr.isNodePort = false
				svcName := "foo"
				emptyIps := []string{}
				readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
				notReadyIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5", "10.2.96.6"}
				svcPorts := []v1.ServicePort{
					newServicePort("port0", 80),
					newServicePort("port1", 8080),
					newServicePort("port2", 9090),
				}

				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				cfgFoo8080 := test.NewConfigMap("foomap8080", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})
				cfgFoo9090 := test.NewConfigMap("foomap9090", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo9090})

				foo := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)

				r := mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addConfigMap(cfgFoo9090)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(len(svcPorts)))
				for _, p := range svcPorts {
					Expect(resources.CountOf(serviceKey{"foo", p.Port, namespace})).To(Equal(1))
				}

				endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
				goodEndpts := test.NewEndpoints(svcName, "1", namespace, readyIps, notReadyIps,
					endptPorts)
				r = mockMgr.addEndpoints(goodEndpts)
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				// this is for another service
				badEndpts := test.NewEndpoints("wrongSvc", "1", namespace, []string{"10.2.96.7"},
					[]string{}, endptPorts)
				r = mockMgr.addEndpoints(badEndpts)
				Expect(r).To(BeTrue(), "Endpoints should be processed.")

				validateServiceIps(svcName, namespace, svcPorts, readyIps, resources)

				// Move an endpoint from ready to not ready and make sure it
				// goes away from virtual servers
				notReadyIps = append(notReadyIps, readyIps[len(readyIps)-1])
				readyIps = readyIps[:len(readyIps)-1]
				r = mockMgr.updateEndpoints(test.NewEndpoints(svcName, "2", namespace, readyIps,
					notReadyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, readyIps, resources)

				// Move it back to ready from not ready and make sure it is re-added
				readyIps = append(readyIps, notReadyIps[len(notReadyIps)-1])
				notReadyIps = notReadyIps[:len(notReadyIps)-1]
				r = mockMgr.updateEndpoints(test.NewEndpoints(svcName, "3", namespace, readyIps,
					notReadyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, readyIps, resources)

				// Remove all endpoints make sure they are removed but virtual server exists
				r = mockMgr.updateEndpoints(test.NewEndpoints(svcName, "4", namespace, emptyIps,
					emptyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, nil, resources)

				// Move it back to ready from not ready and make sure it is re-added
				r = mockMgr.updateEndpoints(test.NewEndpoints(svcName, "5", namespace, readyIps,
					notReadyIps, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")
				validateServiceIps(svcName, namespace, svcPorts, readyIps, resources)
			})

			It("configures virtual servers when service changes", func() {
				mockMgr.appMgr.isNodePort = false
				svcName := "foo"
				svcPorts := []v1.ServicePort{
					newServicePort("port0", 80),
					newServicePort("port1", 8080),
					newServicePort("port2", 9090),
				}
				svcPodIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}

				foo := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)

				endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
				r := mockMgr.addEndpoints(test.NewEndpoints(svcName, "1", namespace, svcPodIps,
					[]string{}, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")

				r = mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				cfgFoo8080 := test.NewConfigMap("foomap8080", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})
				cfgFoo9090 := test.NewConfigMap("foomap9090", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo9090})

				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				r = mockMgr.addConfigMap(cfgFoo9090)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(len(svcPorts)))
				validateServiceIps(svcName, namespace, svcPorts, svcPodIps, resources)

				// delete the service and make sure the IPs go away on the VS
				r = mockMgr.deleteService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(len(svcPorts)))
				validateServiceIps(svcName, namespace, svcPorts, nil, resources)

				// re-add the service
				foo.ObjectMeta.ResourceVersion = "2"
				r = mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(len(svcPorts)))
				validateServiceIps(svcName, namespace, svcPorts, svcPodIps, resources)
			})

			It("configures virtual servers when ConfigMap changes", func() {
				mockMgr.appMgr.isNodePort = false
				svcName := "foo"
				svcPorts := []v1.ServicePort{
					newServicePort("port0", 80),
					newServicePort("port1", 8080),
					newServicePort("port2", 9090),
				}
				svcPodIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}

				foo := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)

				endptPorts := convertSvcPortsToEndpointPorts(svcPorts)

				r := mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				r = mockMgr.addEndpoints(test.NewEndpoints(svcName, "1", namespace, svcPodIps,
					[]string{}, endptPorts))
				Expect(r).To(BeTrue(), "Endpoints should be processed.")

				// no virtual servers yet
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(0))

				// add a config map
				cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo})
				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				validateServiceIps(svcName, namespace, svcPorts[:1], svcPodIps, resources)

				// add another
				cfgFoo8080 := test.NewConfigMap("foomap8080", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   configmapFoo8080})
				r = mockMgr.addConfigMap(cfgFoo8080)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
				validateServiceIps(svcName, namespace, svcPorts[:2], svcPodIps, resources)

				// remove first one
				r = mockMgr.deleteConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				validateServiceIps(svcName, namespace, svcPorts[1:2], svcPodIps, resources)
			})

			It("handles non-NodePort service mode - NodePort", func() {
				cfgFoo := test.NewConfigMap(
					"foomap",
					"1",
					namespace,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					},
				)
				svcName := "foo"
				svcPorts := []v1.ServicePort{
					newServicePort("port0", 80),
				}
				foo := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)

				r := mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")

				r = mockMgr.addConfigMap(cfgFoo)
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1),
					"Virtual servers should have an entry.")

				foo = test.NewService(
					"foo",
					"1",
					namespace,
					"ClusterIP",
					[]v1.ServicePort{{Port: 80}},
				)

				r = mockMgr.addService(foo)
				Expect(r).To(BeTrue(), "Service should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(resources.CountOf(serviceKey{"foo", 80, namespace})).To(Equal(1),
					"Virtual servers should have an entry.")
			})

			It("properly configures multiple virtual servers for one backend", func() {
				mockMgr.appMgr.isNodePort = false
				svcPorts := []v1.ServicePort{
					newServicePort("port80", 80),
				}
				svc := test.NewService("app", "1", namespace, v1.ServiceTypeClusterIP, svcPorts)
				r := mockMgr.addService(svc)
				Expect(r).To(BeTrue(), "Service should be processed.")

				vsTemplate := `{
					"virtualServer": {
						"backend": {
							"serviceName": "app",
							"servicePort": 80,
							"healthMonitors": [
								{
									"interval": %d,
									"timeout": 20,
									"send": "GET /",
									"recv": "Hello from",
									"protocol": "tcp"
								}
							]
						},
						"frontend": {
							"balance": "round-robin",
							"mode": "http",
							"partition": "velcro",
							"virtualAddress": {
								"bindAddr": "10.128.10.240",
								"port": %d
							}
						}
					}
				}`

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(0))
				r = mockMgr.addConfigMap(test.NewConfigMap("cmap-1", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   fmt.Sprintf(vsTemplate, 5, 80),
				}))
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				r = mockMgr.updateConfigMap(test.NewConfigMap("cmap-1", "2", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   fmt.Sprintf(vsTemplate, 5, 80),
				}))
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				r = mockMgr.addConfigMap(test.NewConfigMap("cmap-2", "1", namespace, map[string]string{
					"schema": schemaUrl,
					"data":   fmt.Sprintf(vsTemplate, 5, 8080),
				}))
				Expect(r).To(BeTrue(), "ConfigMap should be processed.")
				Expect(resources.PoolCount()).To(Equal(2))
			})

			It("configures virtual servers via Ingress", func() {
				// Add a service
				fooSvc := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				r := mockMgr.addService(fooSvc)
				Expect(r).To(BeTrue(), "Service should be processed.")

				ingressConfig := v1beta1.IngressSpec{
					Backend: &v1beta1.IngressBackend{
						ServiceName: "foo",
						ServicePort: intstr.IntOrString{IntVal: 80},
					},
				}
				// Add a new Ingress
				ingress := test.NewIngress("ingress", "1", namespace, ingressConfig,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: "velcro",
					})
				r = mockMgr.addIngress(ingress)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				resources := mockMgr.resources()

				events := mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(1))
				Expect(resources.PoolCount()).To(Equal(1))
				Expect(events[0].Namespace).To(Equal(namespace))
				Expect(events[0].Name).To(Equal("ingress"))
				Expect(events[0].Reason).To(Equal("ResourceConfigured"))

				rs, ok := resources.Get(
					serviceKey{"foo", 80, "default"}, formatIngressVSName("1.2.3.4", 80))
				Expect(ok).To(BeTrue(), "Ingress should be accessible.")
				Expect(rs).ToNot(BeNil(), "Ingress should be object.")
				Expect(rs.MetaData.Active).To(BeTrue())

				Expect(rs.Pools[0].Balance).To(Equal("round-robin"))
				Expect(rs.Virtual.Partition).To(Equal("velcro"))
				Expect(rs.Virtual.VirtualAddress.BindAddr).To(Equal("1.2.3.4"))
				Expect(rs.Virtual.VirtualAddress.Port).To(Equal(int32(80)))
				// Update the Ingress resource
				ingress2 := test.NewIngress("ingress", "1", namespace, ingressConfig,
					map[string]string{
						f5VsBindAddrAnnotation:  "5.6.7.8",
						f5VsPartitionAnnotation: "velcro2",
						f5VsHttpPortAnnotation:  "443",
					})
				r = mockMgr.updateIngress(ingress2)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				Expect(resources.PoolCount()).To(Equal(1))
				events = mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(2))
				Expect(events[1].Namespace).To(Equal(namespace))
				Expect(events[1].Name).To(Equal("ingress"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))

				rs, ok = resources.Get(
					serviceKey{"foo", 80, "default"}, formatIngressVSName("5.6.7.8", 443))
				Expect(ok).To(BeTrue(), "Ingress should be accessible.")
				Expect(rs).ToNot(BeNil(), "Ingress should be object.")

				Expect(rs.Virtual.Partition).To(Equal("velcro2"))
				Expect(rs.Virtual.VirtualAddress.BindAddr).To(Equal("5.6.7.8"))
				Expect(rs.Virtual.VirtualAddress.Port).To(Equal(int32(443)))
				// Delete the Ingress resource
				r = mockMgr.deleteIngress(ingress2)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				Expect(resources.PoolCount()).To(Equal(0))
				events = mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(2))

				// Shouldn't process Ingress with non-F5 class
				// https://github.com/F5Networks/k8s-bigip-ctlr/issues/311
				ingressNotf5 := test.NewIngress("ingress-bad", "1", namespace, ingressConfig,
					map[string]string{
						k8sIngressClass: "notf5",
					})
				r = mockMgr.addIngress(ingressNotf5)
				Expect(r).To(BeFalse(), "Ingress resource should not be processed.")
				Expect(resources.PoolCount()).To(Equal(0))
				ingressNotf5.Annotations[k8sIngressClass] = "f5"
				r = mockMgr.updateIngress(ingressNotf5)
				Expect(r).To(BeTrue(), "Ingress resource should be processed when flipping from notf5 to f5.")
				Expect(resources.PoolCount()).To(Equal(1))
				events = mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(3))
				ingressNotf5.Annotations[k8sIngressClass] = "notf5again"
				r = mockMgr.updateIngress(ingressNotf5)
				Expect(r).To(BeFalse(), "Ingress resource should be destroyed when flipping from f5 to notf5again.")
				Expect(resources.PoolCount()).To(Equal(0))
				events = mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(3))

				// Multi-service Ingress
				ingressConfig = v1beta1.IngressSpec{
					Rules: []v1beta1.IngressRule{
						{Host: "host1",
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &v1beta1.HTTPIngressRuleValue{
									Paths: []v1beta1.HTTPIngressPath{
										{Path: "/foo",
											Backend: v1beta1.IngressBackend{
												ServiceName: "foo",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
										{Path: "/bar",
											Backend: v1beta1.IngressBackend{
												ServiceName: "bar",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
									},
								},
							},
						},
						{Host: "host2",
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &v1beta1.HTTPIngressRuleValue{
									Paths: []v1beta1.HTTPIngressPath{
										{Path: "/foo",
											Backend: v1beta1.IngressBackend{
												ServiceName: "foo",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
										{Path: "/foobar",
											Backend: v1beta1.IngressBackend{
												ServiceName: "foobar",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
									},
								},
							},
						},
					},
				}
				barSvc := test.NewService("bar", "2", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37002}})
				r = mockMgr.addService(barSvc)
				Expect(r).To(BeTrue(), "Service should be processed.")
				foobarSvc := test.NewService("foobar", "3", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37003}})
				r = mockMgr.addService(foobarSvc)
				Expect(r).To(BeTrue(), "Service should be processed.")

				ingress3 := test.NewIngress("ingress", "2", namespace, ingressConfig,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: "velcro",
					})
				r = mockMgr.addIngress(ingress3)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				events = mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(4))
				// 4 rules, but only 3 backends specified. We should have 3 keys stored, one for
				// each backend
				Expect(resources.PoolCount()).To(Equal(3))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, "default"}, formatIngressVSName("1.2.3.4", 80))
				Expect(len(rs.Policies[0].Rules)).To(Equal(4))
				mockMgr.deleteService(fooSvc)
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"bar", 80, "default"}, formatIngressVSName("1.2.3.4", 80))
				Expect(len(rs.Policies[0].Rules)).To(Equal(2))

				mockMgr.deleteIngress(ingress3)
				mockMgr.addService(fooSvc)
				ingressConfig = v1beta1.IngressSpec{
					Rules: []v1beta1.IngressRule{
						{Host: "",
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &v1beta1.HTTPIngressRuleValue{
									Paths: []v1beta1.HTTPIngressPath{
										{Path: "/foo",
											Backend: v1beta1.IngressBackend{
												ServiceName: "foo",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
										{Path: "/bar",
											Backend: v1beta1.IngressBackend{
												ServiceName: "bar",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
									},
								},
							},
						},
					},
				}
				ingress4 := test.NewIngress("ingress", "3", namespace, ingressConfig,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: "velcro",
					})
				// Add ingress with same ip (should use shared virtual)
				ingress5 := test.NewIngress("ingressShared", "3", namespace,
					v1beta1.IngressSpec{
						Backend: &v1beta1.IngressBackend{
							ServiceName: "foobar",
							ServicePort: intstr.IntOrString{IntVal: 80},
						},
					},
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: "velcro",
					})
				r = mockMgr.addIngress(ingress4)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				r = mockMgr.addIngress(ingress5)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				Expect(resources.VirtualCount()).To(Equal(1))
				Expect(resources.PoolCount()).To(Equal(3))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, "default"}, formatIngressVSName("1.2.3.4", 80))
				Expect(len(rs.Policies[0].Rules)).To(Equal(2))
				events = mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(7))

				mockMgr.deleteIngress(ingress5)
				Expect(resources.VirtualCount()).To(Equal(1))
				Expect(resources.PoolCount()).To(Equal(2))
				mockMgr.deleteService(fooSvc)
				Expect(resources.PoolCount()).To(Equal(1))
			})

			It("properly uses the default Ingress IP", func() {
				mockMgr.appMgr.defaultIngIP = "10.1.2.3"

				fooSvc := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				barSvc := test.NewService("bar", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37002}})
				mockMgr.addService(fooSvc)
				mockMgr.addService(barSvc)

				ingCfg1 := v1beta1.IngressSpec{
					Backend: &v1beta1.IngressBackend{
						ServiceName: "foo",
						ServicePort: intstr.IntOrString{IntVal: 80},
					},
				}
				ingCfg2 := v1beta1.IngressSpec{
					Backend: &v1beta1.IngressBackend{
						ServiceName: "bar",
						ServicePort: intstr.IntOrString{IntVal: 80},
					},
				}
				ingress1 := test.NewIngress("ingress1", "1", namespace, ingCfg1,
					map[string]string{
						f5VsBindAddrAnnotation:  "controller-default",
						f5VsPartitionAnnotation: "velcro",
					})
				ingress2 := test.NewIngress("ingress2", "2", namespace, ingCfg2,
					map[string]string{
						f5VsBindAddrAnnotation:  "controller-default",
						f5VsPartitionAnnotation: "velcro",
					})
				mockMgr.addIngress(ingress1)
				mockMgr.addIngress(ingress2)
				resources := mockMgr.resources()
				Expect(resources.VirtualCount()).To(Equal(1))
				Expect(resources.PoolCount()).To(Equal(2))
				_, ok := resources.Get(
					serviceKey{"foo", 80, "default"}, formatIngressVSName("10.1.2.3", 80))
				Expect(ok).To(BeTrue())

				ingress2.Annotations[f5VsBindAddrAnnotation] = "1.2.3.4"
				mockMgr.updateIngress(ingress2)
				Expect(resources.VirtualCount()).To(Equal(2))
				Expect(resources.PoolCount()).To(Equal(2))
			})

			It("properly configures redirect data group for ingress", func() {
				ns1 := "ns1"
				ns2 := "ns2"
				host := "foo.com"
				svcName := "foo"
				fooPath := "/foo"
				barPath := "/bar"
				err := mockMgr.startNonLabelMode([]string{ns1, ns2})
				Expect(err).To(BeNil())
				httpFoo := v1beta1.HTTPIngressRuleValue{
					Paths: []v1beta1.HTTPIngressPath{
						{Path: fooPath,
							Backend: v1beta1.IngressBackend{
								ServiceName: svcName,
								ServicePort: intstr.IntOrString{IntVal: 80},
							},
						},
					},
				}
				httpBar := v1beta1.HTTPIngressRuleValue{
					Paths: []v1beta1.HTTPIngressPath{
						{Path: barPath,
							Backend: v1beta1.IngressBackend{
								ServiceName: svcName,
								ServicePort: intstr.IntOrString{IntVal: 80},
							},
						},
					},
				}
				tlsArray := []v1beta1.IngressTLS{
					{
						SecretName: "/Common/clientssl",
					},
				}
				specFoo := v1beta1.IngressSpec{
					Rules: []v1beta1.IngressRule{
						{Host: host,
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &httpFoo,
							},
						},
					},
					TLS: tlsArray,
				}
				specBar := v1beta1.IngressSpec{
					Rules: []v1beta1.IngressRule{
						{Host: host,
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &httpBar,
							},
						},
					},
					TLS: tlsArray,
				}

				// Create the first ingress and associate a service
				ing1a := test.NewIngress("ing1a", "1", ns1, specFoo,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: DEFAULT_PARTITION,
						ingressSslRedirect:      "true",
					})
				r := mockMgr.addIngress(ing1a)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				fooSvc1 := test.NewService(svcName, "1", ns1, "NodePort",
					[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
				r = mockMgr.addService(fooSvc1)
				Expect(r).To(BeTrue(), "Service should be processed.")

				// Create identical ingress and service in another namespace
				ing2 := test.NewIngress("ing2", "1", ns2, specFoo,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: DEFAULT_PARTITION,
						ingressSslRedirect:      "true",
					})
				r = mockMgr.addIngress(ing2)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				fooSvc2 := test.NewService(svcName, "1", ns2, "NodePort",
					[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
				r = mockMgr.addService(fooSvc2)
				Expect(r).To(BeTrue(), "Service should be processed.")

				// Make sure the entry isn't duplicated in the dg
				grpRef := nameRef{
					Partition: DEFAULT_PARTITION,
					Name:      httpsRedirectDgName,
				}
				nsMap, found := mockMgr.appMgr.intDgMap[grpRef]
				Expect(found).To(BeTrue(), "redirect group not found")
				flatDg := nsMap.FlattenNamespaces()
				Expect(flatDg).ToNot(BeNil(), "should have data")
				Expect(len(flatDg.Records)).To(Equal(1))
				Expect(flatDg.Records[0].Name).To(Equal(host))
				Expect(flatDg.Records[0].Data).To(Equal(fooPath))

				// Add a route for the same host but different path
				ing1b := test.NewIngress("ing1b", "1", ns1, specBar,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: "velcro",
						ingressSslRedirect:      "true",
					})
				r = mockMgr.addIngress(ing1b)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
				Expect(found).To(BeTrue(), "redirect group not found")
				flatDg = nsMap.FlattenNamespaces()
				Expect(flatDg).ToNot(BeNil(), "should have data")
				Expect(len(flatDg.Records)).To(Equal(1))
				Expect(flatDg.Records[0].Name).To(Equal(host))
				fooAndBarPath := fmt.Sprintf("%s|%s", barPath, fooPath)
				Expect(flatDg.Records[0].Data).To(Equal(fooAndBarPath))

				// Delete one of the duplicates for foo.com/foo, should not change dg
				r = mockMgr.deleteIngress(ing2)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
				Expect(found).To(BeTrue(), "redirect group not found")
				flatDg = nsMap.FlattenNamespaces()
				Expect(flatDg).ToNot(BeNil(), "should have data")
				Expect(len(flatDg.Records)).To(Equal(1))
				Expect(flatDg.Records[0].Name).To(Equal(host))
				Expect(flatDg.Records[0].Data).To(Equal(fooAndBarPath))

				// Delete the second duplicate for foo.com/foo, should change dg
				r = mockMgr.deleteIngress(ing1a)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
				Expect(found).To(BeTrue(), "redirect group not found")
				flatDg = nsMap.FlattenNamespaces()
				Expect(flatDg).ToNot(BeNil(), "should have data")
				Expect(len(flatDg.Records)).To(Equal(1))
				Expect(flatDg.Records[0].Name).To(Equal(host))
				Expect(flatDg.Records[0].Data).To(Equal(barPath))

				// Delete last route, should produce a nil dg
				r = mockMgr.deleteIngress(ing1b)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				flatDg = nsMap.FlattenNamespaces()
				Expect(flatDg).To(BeNil(), "should not have data")

				// Re-create the first ingress without ssl-redirect = true, should not
				// be in the dg
				ing1a = test.NewIngress("ing1a", "1", ns1, specFoo,
					map[string]string{
						f5VsBindAddrAnnotation:  "1.2.3.4",
						f5VsPartitionAnnotation: DEFAULT_PARTITION,
						ingressSslRedirect:      "false",
					})
				r = mockMgr.addIngress(ing1a)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")
				nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
				Expect(found).To(BeTrue(), "redirect group not found")
				flatDg = nsMap.FlattenNamespaces()
				Expect(flatDg).To(BeNil(), "should not have data")
			})

			Context("Routes", func() {
				BeforeEach(func() {
					mockMgr.appMgr.routeConfig = RouteConfig{
						HttpVs:  "ose-vserver",
						HttpsVs: "https-ose-vserver",
					}
				})

				It("configures virtual servers via Routes", func() {
					spec := routeapi.RouteSpec{
						Host: "foobar.com",
						Path: "/foo",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "foo",
						},
						Port: &routeapi.RoutePort{
							TargetPort: intstr.FromString("foo-80"),
						},
						TLS: &routeapi.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
							Key:         "key",
						},
					}
					route := test.NewRoute("route", "1", namespace, spec, nil)
					r := mockMgr.addRoute(route)
					Expect(r).To(BeTrue(), "Route resource should be processed.")

					resources := mockMgr.resources()
					// Associate a service
					fooSvc := test.NewService("foo", "1", namespace, "NodePort",
						[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
					r = mockMgr.addService(fooSvc)
					Expect(r).To(BeTrue(), "Service should be processed.")
					Expect(resources.PoolCount()).To(Equal(2))

					rs, ok := resources.Get(
						serviceKey{"foo", 80, "default"}, "https-ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(rs.MetaData.Active).To(BeTrue())
					Expect(len(rs.Policies[0].Rules)).To(Equal(1))

					customProfiles := mockMgr.customProfiles()
					// Should be 1 profile from Spec, and 1 default clientssl
					Expect(len(customProfiles)).To(Equal(2))

					spec = routeapi.RouteSpec{
						Host: "barfoo.com",
						Path: "/bar",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "bar",
						},
						TLS: &routeapi.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
							Key:         "key",
						},
					}
					route2 := test.NewRoute("route2", "1", namespace, spec, nil)
					r = mockMgr.addRoute(route2)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					resources = mockMgr.resources()
					// Associate a service
					barSvc := test.NewService("bar", "1", namespace, "NodePort",
						[]v1.ServicePort{{Port: 80, NodePort: 37001}})
					mockMgr.addService(barSvc)
					Expect(r).To(BeTrue(), "Service should be processed.")
					Expect(resources.PoolCount()).To(Equal(4))

					rs, ok = resources.Get(
						serviceKey{"bar", 80, "default"}, "https-ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(rs.MetaData.Active).To(BeTrue())
					Expect(len(rs.Policies[0].Rules)).To(Equal(2))

					customProfiles = mockMgr.customProfiles()
					// Should be 2 profile from Spec, and 1 default clientssl
					Expect(len(customProfiles)).To(Equal(3))

					// Delete a Route resource
					r = mockMgr.deleteRoute(route2)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					Expect(resources.PoolCount()).To(Equal(2))
					rs, ok = resources.Get(
						serviceKey{"foo", 80, "default"}, "https-ose-vserver")
					Expect(len(rs.Policies[0].Rules)).To(Equal(1))
					Expect(len(customProfiles)).To(Equal(2))

					// Update Route1 port
					route.Spec.Port.TargetPort = intstr.IntOrString{IntVal: 443}
					mockMgr.updateRoute(route)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					rs, ok = resources.Get(
						serviceKey{"foo", 443, "default"}, "https-ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(rs.Pools[0].ServicePort).To(Equal(int32(443)))
				})

				It("configures passthrough routes", func() {
					// create 2 services and routes
					hostName1 := "foobar.com"
					svcName1 := "foo"
					spec := routeapi.RouteSpec{
						Host: hostName1,
						Path: "/foo",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: svcName1,
						},
						TLS: &routeapi.TLSConfig{
							Termination: routeapi.TLSTerminationPassthrough,
						},
					}
					route1 := test.NewRoute("rt1", "1", namespace, spec, nil)
					r := mockMgr.addRoute(route1)
					Expect(r).To(BeTrue(), "Route resource should be processed.")

					resources := mockMgr.resources()
					fooSvc := test.NewService(svcName1, "1", namespace, "NodePort",
						[]v1.ServicePort{{Port: 443, NodePort: 37001}})
					r = mockMgr.addService(fooSvc)
					Expect(r).To(BeTrue(), "Service should be processed.")
					Expect(resources.PoolCount()).To(Equal(2))

					hostName2 := "barfoo.com"
					svcName2 := "bar"
					spec = routeapi.RouteSpec{
						Host: hostName2,
						Path: "/bar",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: svcName2,
						},
						TLS: &routeapi.TLSConfig{
							Termination:                   routeapi.TLSTerminationPassthrough,
							InsecureEdgeTerminationPolicy: routeapi.InsecureEdgeTerminationPolicyRedirect,
						},
					}
					route2 := test.NewRoute("rt2", "1", namespace, spec, nil)
					r = mockMgr.addRoute(route2)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					resources = mockMgr.resources()
					barSvc := test.NewService(svcName2, "1", namespace, "NodePort",
						[]v1.ServicePort{{Port: 443, NodePort: 37001}})
					mockMgr.addService(barSvc)
					Expect(r).To(BeTrue(), "Service should be processed.")
					Expect(resources.PoolCount()).To(Equal(4))

					// Check state.
					rs, ok := resources.Get(
						serviceKey{svcName1, 443, namespace}, "https-ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(rs.MetaData.Active).To(BeTrue())
					Expect(len(rs.Policies)).To(Equal(0))
					Expect(len(rs.Virtual.IRules)).To(Equal(1))
					expectedIRuleName := fmt.Sprintf("/%s/%s",
						DEFAULT_PARTITION, sslPassthroughIRuleName)
					Expect(rs.Virtual.IRules[0]).To(Equal(expectedIRuleName))

					hostDgKey := nameRef{
						Name:      passthroughHostsDgName,
						Partition: DEFAULT_PARTITION,
					}
					hostDg, found := mockMgr.appMgr.intDgMap[hostDgKey]
					Expect(found).To(BeTrue())
					Expect(len(hostDg[namespace].Records)).To(Equal(2))
					Expect(hostDg[namespace].Records[1].Name).To(Equal(hostName1))
					Expect(hostDg[namespace].Records[0].Name).To(Equal(hostName2))
					Expect(hostDg[namespace].Records[1].Data).To(Equal(formatRoutePoolName(
						route1, getRouteCanonicalServiceName(route1))))
					Expect(hostDg[namespace].Records[0].Data).To(Equal(formatRoutePoolName(
						route2, getRouteCanonicalServiceName(route2))))

					rs, ok = resources.Get(
						serviceKey{svcName2, 443, namespace}, "ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(rs.MetaData.Active).To(BeTrue())
					Expect(len(rs.Virtual.IRules)).To(Equal(0))
					Expect(len(rs.Policies)).To(Equal(0))

					// Delete a Route resource and make sure the data groups are cleaned up.
					r = mockMgr.deleteRoute(route2)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					Expect(resources.PoolCount()).To(Equal(2))
					hostDg, found = mockMgr.appMgr.intDgMap[hostDgKey]
					Expect(found).To(BeTrue())
					Expect(len(hostDg[namespace].Records)).To(Equal(1))
					Expect(hostDg[namespace].Records[0].Name).To(Equal(hostName1))
					Expect(hostDg[namespace].Records[0].Data).To(Equal(formatRoutePoolName(
						route1, getRouteCanonicalServiceName(route1))))
				})

				It("configures reencrypt routes", func() {
					hostName := "foobar.com"
					spec := routeapi.RouteSpec{
						Host: hostName,
						Path: "/foo",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "foo",
						},
						TLS: &routeapi.TLSConfig{
							Termination: "reencrypt",
							Certificate: "cert",
							Key:         "key",
							DestinationCACertificate: "destCaCert",
						},
					}
					route := test.NewRoute("route", "1", namespace, spec, nil)
					r := mockMgr.addRoute(route)
					Expect(r).To(BeTrue(), "Route resource should be processed.")

					resources := mockMgr.resources()
					// Associate a service
					fooSvc := test.NewService("foo", "1", namespace, "NodePort",
						[]v1.ServicePort{{Port: 443, NodePort: 37001}})
					r = mockMgr.addService(fooSvc)
					Expect(r).To(BeTrue(), "Service should be processed.")
					Expect(resources.PoolCount()).To(Equal(2))

					rs, ok := resources.Get(
						serviceKey{"foo", 443, "default"}, "https-ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(rs.MetaData.Active).To(BeTrue())
					Expect(len(rs.Policies[0].Rules)).To(Equal(1))
					Expect(len(rs.Virtual.IRules)).To(Equal(1))
					expectedIRuleName := fmt.Sprintf("/%s/%s",
						DEFAULT_PARTITION, sslPassthroughIRuleName)
					Expect(rs.Virtual.IRules[0]).To(Equal(expectedIRuleName))
					hostDgKey := nameRef{
						Name:      reencryptHostsDgName,
						Partition: DEFAULT_PARTITION,
					}
					hostDg, found := mockMgr.appMgr.intDgMap[hostDgKey]
					Expect(found).To(BeTrue())
					Expect(len(hostDg[namespace].Records)).To(Equal(1))
					Expect(hostDg[namespace].Records[0].Name).To(Equal(hostName))
					Expect(hostDg[namespace].Records[0].Data).To(Equal(formatRoutePoolName(
						route, getRouteCanonicalServiceName(route))))

					customProfiles := mockMgr.customProfiles()
					// Should be 2 profiles from Spec, 2 defaults (clientssl and serverssl)
					Expect(len(customProfiles)).To(Equal(4))
					// should have 2 client ssl custom profile and 2 server ssl custom profile
					// should have 1 client ssl custom profile and 1 server ssl custom profile
					haveClientSslProfile := false
					haveServerSslProfile := false
					for _, prof := range customProfiles {
						switch prof.Context {
						case customProfileClient:
							haveClientSslProfile = true
						case customProfileServer:
							haveServerSslProfile = true
						}
					}
					Expect(haveClientSslProfile).To(BeTrue())
					Expect(haveServerSslProfile).To(BeTrue())

					// and both should be referenced by the virtual
					Expect(rs.Virtual.GetProfileCountByContext(customProfileClient)).To(Equal(2))
					Expect(rs.Virtual.GetProfileCountByContext(customProfileServer)).To(Equal(2))
				})

				It("doesn't update stored route configs during processing", func() {
					spec1 := routeapi.RouteSpec{
						Host: "foo.com",
						Path: "/foo",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "foo",
						},
						TLS: &routeapi.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
							Key:         "key",
						},
					}
					spec2 := routeapi.RouteSpec{
						Host: "foo.com",
						Path: "/bar",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "foo",
						},
						TLS: &routeapi.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
							Key:         "key",
						},
					}
					route := test.NewRoute("route", "1", namespace, spec1, nil)
					mockMgr.addRoute(route)

					fooSvc := test.NewService("foo", "1", namespace, "NodePort",
						[]v1.ServicePort{{Port: 80, NodePort: 37001}})
					mockMgr.addService(fooSvc)

					resources := mockMgr.resources()
					rs, ok := resources.Get(
						serviceKey{"foo", 80, "default"}, "https-ose-vserver")
					Expect(ok).To(BeTrue(), "Route should be accessible.")
					Expect(rs).ToNot(BeNil(), "Route should be object.")
					Expect(len(rs.Policies[0].Rules)).To(Equal(1))

					// Add a new route, our stored config (rs), should not have been
					// updated locally. It should only update when we get it again.
					// This confirms that we aren't updating a pointer.
					route2 := test.NewRoute("route2", "1", namespace, spec2, nil)
					mockMgr.addRoute(route2)
					Expect(len(rs.Policies[0].Rules)).To(Equal(1))
					rs, _ = resources.Get(
						serviceKey{"foo", 80, "default"}, "https-ose-vserver")
					Expect(len(rs.Policies[0].Rules)).To(Equal(2))
				})

				It("properly configures redirect data group for routes", func() {
					ns1 := "ns1"
					ns2 := "ns2"
					host := "foo.com"
					svcName := "foo"
					fooPath := "/foo"
					barPath := "/bar"
					err := mockMgr.startNonLabelMode([]string{ns1, ns2})
					Expect(err).To(BeNil())
					spec := routeapi.RouteSpec{
						Host: host,
						Path: fooPath,
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: svcName,
						},
						Port: &routeapi.RoutePort{
							TargetPort: intstr.FromInt(80),
						},
						TLS: &routeapi.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
							Key:         "key",
							InsecureEdgeTerminationPolicy: routeapi.InsecureEdgeTerminationPolicyRedirect,
						},
					}

					// Create the first route and associate a service
					route1a := test.NewRoute("route1a", "1", ns1, spec, nil)
					r := mockMgr.addRoute(route1a)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					fooSvc1 := test.NewService(svcName, "1", ns1, "NodePort",
						[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
					r = mockMgr.addService(fooSvc1)
					Expect(r).To(BeTrue(), "Service should be processed.")

					// Create identical route and service in another namespace
					route2 := test.NewRoute("route", "1", ns2, spec, nil)
					r = mockMgr.addRoute(route2)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					fooSvc2 := test.NewService(svcName, "1", ns2, "NodePort",
						[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
					r = mockMgr.addService(fooSvc2)
					Expect(r).To(BeTrue(), "Service should be processed.")

					// Make sure the entry isn't duplicated in the dg
					grpRef := nameRef{
						Partition: DEFAULT_PARTITION,
						Name:      httpsRedirectDgName,
					}
					nsMap, found := mockMgr.appMgr.intDgMap[grpRef]
					Expect(found).To(BeTrue(), "redirect group not found")
					flatDg := nsMap.FlattenNamespaces()
					Expect(flatDg).ToNot(BeNil(), "should have data")
					Expect(len(flatDg.Records)).To(Equal(1))
					Expect(flatDg.Records[0].Name).To(Equal(host))
					Expect(flatDg.Records[0].Data).To(Equal(fooPath))

					// Add a route for the same host but different path
					route1b := test.NewRoute("route1b", "1", ns1, spec, nil)
					route1b.Spec.Path = barPath
					r = mockMgr.addRoute(route1b)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
					Expect(found).To(BeTrue(), "redirect group not found")
					flatDg = nsMap.FlattenNamespaces()
					Expect(flatDg).ToNot(BeNil(), "should have data")
					Expect(len(flatDg.Records)).To(Equal(1))
					Expect(flatDg.Records[0].Name).To(Equal(host))
					fooAndBarPath := fmt.Sprintf("%s|%s", barPath, fooPath)
					Expect(flatDg.Records[0].Data).To(Equal(fooAndBarPath))

					// Delete one of the duplicates for foo.com/foo, should not change dg
					r = mockMgr.deleteRoute(route2)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
					Expect(found).To(BeTrue(), "redirect group not found")
					flatDg = nsMap.FlattenNamespaces()
					Expect(flatDg).ToNot(BeNil(), "should have data")
					Expect(len(flatDg.Records)).To(Equal(1))
					Expect(flatDg.Records[0].Name).To(Equal(host))
					Expect(flatDg.Records[0].Data).To(Equal(fooAndBarPath))

					// Delete the second duplicate for foo.com/foo, should change dg
					r = mockMgr.deleteRoute(route1a)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
					Expect(found).To(BeTrue(), "redirect group not found")
					flatDg = nsMap.FlattenNamespaces()
					Expect(flatDg).ToNot(BeNil(), "should have data")
					Expect(len(flatDg.Records)).To(Equal(1))
					Expect(flatDg.Records[0].Name).To(Equal(host))
					Expect(flatDg.Records[0].Data).To(Equal(barPath))

					// Delete last route, should produce a nil dg
					r = mockMgr.deleteRoute(route1b)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
					Expect(found).To(BeTrue(), "redirect group not found")
					flatDg = nsMap.FlattenNamespaces()
					Expect(flatDg).To(BeNil(), "should not have data")

					// Re-create the first route without redirect, should not be in dg
					spec.TLS.InsecureEdgeTerminationPolicy = routeapi.InsecureEdgeTerminationPolicyAllow
					route1a = test.NewRoute("route1a", "1", ns1, spec, nil)
					r = mockMgr.addRoute(route1a)
					Expect(r).To(BeTrue(), "Route resource should be processed.")
					nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
					Expect(found).To(BeTrue(), "redirect group not found")
					flatDg = nsMap.FlattenNamespaces()
					Expect(flatDg).To(BeNil(), "should not have data")
				})
			})

			// Check that the provided host resolves into the expected addr.
			// update parameter is only used to tell function to update an empty host
			hostResolution := func(host string, expAddr, update bool) {
				ingressConfig := v1beta1.IngressSpec{
					Rules: []v1beta1.IngressRule{
						{Host: host,
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &v1beta1.HTTPIngressRuleValue{
									Paths: []v1beta1.HTTPIngressPath{
										{Path: "/foo",
											Backend: v1beta1.IngressBackend{
												ServiceName: "foo",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
									},
								},
							},
						},
						{Host: "shouldBeIgnored",
							IngressRuleValue: v1beta1.IngressRuleValue{
								HTTP: &v1beta1.HTTPIngressRuleValue{
									Paths: []v1beta1.HTTPIngressPath{
										{Path: "/foo",
											Backend: v1beta1.IngressBackend{
												ServiceName: "foo",
												ServicePort: intstr.IntOrString{IntVal: 80},
											},
										},
									},
								},
							},
						},
					},
				}
				ingress := test.NewIngress("ingress", "1", namespace, ingressConfig,
					map[string]string{
						f5VsPartitionAnnotation: "velcro",
					})
				r := mockMgr.addIngress(ingress)
				Expect(r).To(BeTrue(), "Ingress resource should be processed.")

				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(1))
				var bindAddr string
				for _, cfg := range resources.GetAllResources() {
					bindAddr = cfg.Virtual.VirtualAddress.BindAddr
				}
				if expAddr {
					Expect(len(bindAddr)).To(BeNumerically(">", 0))
				} else {
					Expect(len(bindAddr)).To(Equal(0))
				}
				// Verify addition of host name works as expected
				if update {
					ingress.Spec.Rules[0].Host = "f5.com"
					mockMgr.updateIngress(ingress)
					Expect(resources.PoolCount()).To(Equal(1))
					for _, cfg := range resources.GetAllResources() {
						bindAddr = cfg.Virtual.VirtualAddress.BindAddr
					}
					Expect(len(bindAddr)).To(BeNumerically(">", 0))
				}
				mockMgr.deleteIngress(ingress)
			}

			It("resolves ingress host names", func() {
				fooSvc := test.NewService("foo", "1", namespace, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				r := mockMgr.addService(fooSvc)
				Expect(r).To(BeTrue(), "Service should be processed.")

				// Set to LOOKUP mode, using local DNS
				mockMgr.appMgr.resolveIng = "LOOKUP"
				// Empty host (then add one)
				hostResolution("", false, true)
				expectedEventCt := 4 // # expected events
				events := mockMgr.getFakeEvents(namespace)
				Expect(len(events)).To(Equal(expectedEventCt))
				Expect(events[0].Reason).To(Equal("DNSResolutionError"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
				Expect(events[2].Reason).To(Equal("HostResolvedSuccessfully"))
				Expect(events[3].Reason).To(Equal("ResourceConfigured"))
				// each following test will skip events handled here
				ignoreEventCt := expectedEventCt

				// Bad host
				hostResolution("doesn't.exist", false, false)
				expectedEventCt = 2
				events = mockMgr.getFakeEvents(namespace)
				events = events[ignoreEventCt:]
				Expect(events[0].Reason).To(Equal("DNSResolutionError"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
				ignoreEventCt += expectedEventCt

				// Good host
				hostResolution("f5.com", true, false)
				expectedEventCt = 2
				events = mockMgr.getFakeEvents(namespace)
				events = events[ignoreEventCt:]
				Expect(events[0].Reason).To(Equal("HostResolvedSuccessfully"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
				ignoreEventCt += expectedEventCt

				// Use a non-existent custom DNS server
				mockMgr.appMgr.resolveIng = "BadCustomDNS"
				// Good host; bad DNS
				hostResolution("google.com", false, false)
				events = mockMgr.getFakeEvents(namespace)
				events = events[ignoreEventCt:]
				ignoreEventCt += expectedEventCt
				Expect(events[0].Reason).To(Equal("DNSResolutionError"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
				expectedEventCt = 2

				// Use a valid custom DNS server (hostname)
				mockMgr.appMgr.resolveIng = "pdns130.f5.com."
				hostResolution("f5.com", true, false)
				events = mockMgr.getFakeEvents(namespace)
				events = events[ignoreEventCt:]
				ignoreEventCt += expectedEventCt
				Expect(events[0].Reason).To(Equal("HostResolvedSuccessfully"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
				expectedEventCt = 2

				// Use a valid custom DNS server (ip address)
				mockMgr.appMgr.resolveIng = "193.221.113.53"
				hostResolution("msn.com", true, false)
				events = mockMgr.getFakeEvents(namespace)
				events = events[ignoreEventCt:]
				ignoreEventCt += expectedEventCt
				Expect(events[0].Reason).To(Equal("HostResolvedSuccessfully"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
				expectedEventCt = 2

				// Good DNS, bad host
				hostResolution("doesn't.exist", false, false)
				events = mockMgr.getFakeEvents(namespace)
				events = events[ignoreEventCt:]
				ignoreEventCt += expectedEventCt
				Expect(events[0].Reason).To(Equal("DNSResolutionError"))
				Expect(events[1].Reason).To(Equal("ResourceConfigured"))
			})
		})

		Context("namespace related", func() {
			It("handles multiple namespaces", func() {
				// Add config maps and services to 3 namespaces and ensure they only
				// are processed in the 2 namespaces we are configured to watch.
				ns1 := "ns1"
				ns2 := "ns2"
				nsDefault := "default"
				err := mockMgr.startNonLabelMode([]string{ns1, ns2})
				Expect(err).To(BeNil())
				node := test.NewNode("node1", "1", false,
					[]v1.NodeAddress{{"InternalIP", "127.0.0.3"}}, []v1.Taint{})
				_, err = mockMgr.appMgr.kubeClient.Core().Nodes().Create(node)
				Expect(err).To(BeNil())
				n, err := mockMgr.appMgr.kubeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)

				cfgNs1 := test.NewConfigMap("foomap", "1", ns1,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					})
				cfgNs2 := test.NewConfigMap("foomap", "1", ns2,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					})
				cfgNsDefault := test.NewConfigMap("foomap", "1", nsDefault,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					})

				svcNs1 := test.NewService("foo", "1", ns1, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				svcNs2 := test.NewService("foo", "1", ns2, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 38001}})
				svcNsDefault := test.NewService("foo", "1", nsDefault, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 39001}})

				resources := mockMgr.resources()
				r := mockMgr.addConfigMap(cfgNs1)
				Expect(r).To(BeTrue(), "Config map should be processed.")
				rs, ok := resources.Get(
					serviceKey{"foo", 80, ns1}, formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs.MetaData.Active).To(BeFalse())
				r = mockMgr.addService(svcNs1)
				Expect(r).To(BeTrue(), "Service should be processed.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, ns1}, formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs.MetaData.Active).To(BeTrue())

				r = mockMgr.addConfigMap(cfgNs2)
				Expect(r).To(BeTrue(), "Config map should be processed.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, ns2}, formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs.MetaData.Active).To(BeFalse())
				r = mockMgr.addService(svcNs2)
				Expect(r).To(BeTrue(), "Service should be processed.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, ns2}, formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs.MetaData.Active).To(BeTrue())

				r = mockMgr.addConfigMap(cfgNsDefault)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, nsDefault}, formatConfigMapVSName(cfgNsDefault))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				r = mockMgr.addService(svcNsDefault)
				Expect(r).To(BeFalse(), "Service should not be processed.")
				rs, ok = resources.Get(
					serviceKey{"foo", 80, nsDefault}, formatConfigMapVSName(cfgNsDefault))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
			})

			It("handles added and removed namespaces", func() {
				cfgMapSelector, err := labels.Parse(DefaultConfigMapLabel)
				Expect(err).To(BeNil())

				// Add "" to watch all namespaces.
				err = mockMgr.appMgr.AddNamespace("", cfgMapSelector, 0)
				Expect(err).To(BeNil())

				// Try to add "default" namespace, which should fail as it is covered
				// by the "" namespace.
				err = mockMgr.appMgr.AddNamespace("default", cfgMapSelector, 0)
				Expect(err).ToNot(BeNil())

				// Remove "" namespace and try re-adding "default", which should work.
				err = mockMgr.appMgr.removeNamespace("")
				Expect(err).To(BeNil())
				err = mockMgr.appMgr.AddNamespace("default", cfgMapSelector, 0)
				Expect(err).To(BeNil())

				// Try to re-add "" namespace, which should fail.
				err = mockMgr.appMgr.AddNamespace("", cfgMapSelector, 0)
				Expect(err).ToNot(BeNil())

				// Add another non-conflicting namespace, which should work.
				err = mockMgr.appMgr.AddNamespace("myns", cfgMapSelector, 0)
				Expect(err).To(BeNil())
			})

			It("properly manage a namespace informer", func() {
				cfgMapSelector, err := labels.Parse(DefaultConfigMapLabel)
				Expect(err).To(BeNil())
				nsSelector, err := labels.Parse("watching")
				Expect(err).To(BeNil())

				// Add a namespace to appMgr, which should prevent a namespace label
				// informer from being added.
				err = mockMgr.appMgr.AddNamespace("default", cfgMapSelector, 0)
				Expect(err).To(BeNil())
				// Try adding a namespace label informer, which should fail
				err = mockMgr.appMgr.AddNamespaceLabelInformer(nsSelector, 0)
				Expect(err).ToNot(BeNil())
				// Remove namespace added previously and retry, which should work.
				err = mockMgr.appMgr.removeNamespace("default")
				Expect(err).To(BeNil())
				err = mockMgr.appMgr.AddNamespaceLabelInformer(nsSelector, 0)
				Expect(err).To(BeNil())
				// Re-adding it should fail
				err = mockMgr.appMgr.AddNamespaceLabelInformer(nsSelector, 0)
				Expect(err).ToNot(BeNil())
			})

			It("watches namespace labels", func() {
				nsLabel := "watching"
				err := mockMgr.startLabelMode(nsLabel)
				Expect(err).To(BeNil())

				ns1 := test.NewNamespace("ns1", "1", map[string]string{})
				ns2 := test.NewNamespace("ns2", "1", map[string]string{"notwatching": "no"})
				ns3 := test.NewNamespace("ns3", "1", map[string]string{nsLabel: "yes"})

				node := test.NewNode("node1", "1", false,
					[]v1.NodeAddress{{"InternalIP", "127.0.0.3"}}, []v1.Taint{})
				_, err = mockMgr.appMgr.kubeClient.Core().Nodes().Create(node)
				Expect(err).To(BeNil())
				n, err := mockMgr.appMgr.kubeClient.Core().Nodes().List(metav1.ListOptions{})
				Expect(err).To(BeNil(), "Should not fail listing nodes.")
				mockMgr.processNodeUpdate(n.Items, err)

				cfgNs1 := test.NewConfigMap("foomap", "1", ns1.ObjectMeta.Name,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					})
				cfgNs2 := test.NewConfigMap("foomap", "1", ns2.ObjectMeta.Name,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					})
				cfgNs3 := test.NewConfigMap("foomap", "1", ns3.ObjectMeta.Name,
					map[string]string{
						"schema": schemaUrl,
						"data":   configmapFoo,
					})

				// Using label selectors with no matching namespaces, all adds should
				// not create any vserver entries.
				resources := mockMgr.resources()
				r := mockMgr.addConfigMap(cfgNs1)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs2)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs3)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				_, ok := resources.Get(serviceKey{"foo", 80, ns1.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns2.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns3.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs3))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")

				// Add a namespace with no label, should still not create any resources.
				r = mockMgr.addNamespace(ns1)
				Expect(r).To(BeFalse())
				r = mockMgr.addConfigMap(cfgNs1)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs2)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs3)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns1.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns2.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns3.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs3))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")

				// Add a namespace with a mismatched label, should still not create any
				// resources.
				r = mockMgr.addNamespace(ns2)
				Expect(r).To(BeFalse())
				r = mockMgr.addConfigMap(cfgNs1)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs2)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs3)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns1.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns2.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns3.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs3))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")

				// Add a namespace with a matching label and make sure the config map that
				// references that namespace is added to resources.
				r = mockMgr.addNamespace(ns3)
				Expect(r).To(BeTrue())
				r = mockMgr.addConfigMap(cfgNs1)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs2)
				Expect(r).To(BeFalse(), "Config map should not be processed.")
				r = mockMgr.addConfigMap(cfgNs3)
				Expect(r).To(BeTrue(), "Config map should be processed.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns1.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns2.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				rs, ok := resources.Get(serviceKey{"foo", 80, ns3.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs3))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs.MetaData.Active).To(BeFalse())

				// Add services corresponding to the config maps. The only change expected
				// is the service in ns3 should become active.
				svcNs1 := test.NewService("foo", "1", ns1.ObjectMeta.Name, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				svcNs2 := test.NewService("foo", "1", ns2.ObjectMeta.Name, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 38001}})
				svcNs3 := test.NewService("foo", "1", ns3.ObjectMeta.Name, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 39001}})
				r = mockMgr.addService(svcNs1)
				Expect(r).To(BeFalse(), "Service should not be processed.")
				r = mockMgr.addService(svcNs2)
				Expect(r).To(BeFalse(), "Service should not be processed.")
				r = mockMgr.addService(svcNs3)
				Expect(r).To(BeTrue(), "Service should be processed.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns1.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs1))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				_, ok = resources.Get(serviceKey{"foo", 80, ns2.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs2))
				Expect(ok).To(BeFalse(), "Config map should be accessible.")
				rs, ok = resources.Get(serviceKey{"foo", 80, ns3.ObjectMeta.Name},
					formatConfigMapVSName(cfgNs3))
				Expect(ok).To(BeTrue(), "Config map should be accessible.")
				Expect(rs.MetaData.Active).To(BeTrue())
			})

			It("handles routes and services in multiple namespaces", func() {
				mockMgr.appMgr.routeConfig = RouteConfig{
					HttpVs:  "ose-vserver",
					HttpsVs: "https-ose-vserver",
				}
				ns1 := "default"
				ns2 := "kube-system"

				cfgMapSelector, err := labels.Parse(DefaultConfigMapLabel)
				Expect(err).To(BeNil())
				err = mockMgr.appMgr.AddNamespace("", cfgMapSelector, 0)
				Expect(err).To(BeNil())

				mockMgr.appMgr.useNodeInternal = true
				nodeSet := []v1.Node{
					*test.NewNode("node0", "0", false, []v1.NodeAddress{
						{"InternalIP", "127.0.0.0"}}, []v1.Taint{}),
				}
				mockMgr.processNodeUpdate(nodeSet, nil)

				// Create two services with same name in different namespaces
				svcNs1 := test.NewService("foo", "1", ns1, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 37001}})
				svcNs2 := test.NewService("foo", "2", ns2, "NodePort",
					[]v1.ServicePort{{Port: 80, NodePort: 38001}})
				mockMgr.addService(svcNs1)
				mockMgr.addService(svcNs2)

				spec1 := routeapi.RouteSpec{
					Host: "foobar.com",
					Path: "/foo",
					Port: &routeapi.RoutePort{
						TargetPort: intstr.IntOrString{IntVal: 80},
					},
					To: routeapi.RouteTargetReference{
						Kind: "Service",
						Name: "foo",
					},
					TLS: &routeapi.TLSConfig{
						Termination: "edge",
						Certificate: "cert",
						Key:         "key",
					},
				}
				spec2 := routeapi.RouteSpec{
					Host: "foobar.com",
					Path: "/bar",
					Port: &routeapi.RoutePort{
						TargetPort: intstr.IntOrString{IntVal: 80},
					},
					To: routeapi.RouteTargetReference{
						Kind: "Service",
						Name: "foo",
					},
					TLS: &routeapi.TLSConfig{
						Termination: "edge",
						Certificate: "cert",
						Key:         "key",
					},
				}
				// Create two routes with same name in different namespaces
				route := test.NewRoute("route", "1", ns1, spec1, nil)
				r := mockMgr.addRoute(route)
				Expect(r).To(BeTrue(), "Route resource should be processed.")
				route2 := test.NewRoute("route", "2", ns2, spec2, nil)
				r = mockMgr.addRoute(route2)
				Expect(r).To(BeTrue(), "Route resource should be processed.")
				resources := mockMgr.resources()
				Expect(resources.PoolCount()).To(Equal(4))

				rs, ok := resources.Get(
					serviceKey{"foo", 80, ns1}, "https-ose-vserver")
				Expect(ok).To(BeTrue(), "Route should be accessible.")
				Expect(rs).ToNot(BeNil(), "Route should be object.")
				Expect(len(rs.Policies[0].Rules)).To(Equal(2))
				Expect(rs.Virtual.GetProfileCountByContext(customProfileClient)).To(Equal(3))
				addr := []string{"127.0.0.0"}
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, addr)))
				Expect(rs.Pools[1].Members).To(Equal(generateExpectedAddrs(38001, addr)))

				rs, ok = resources.Get(
					serviceKey{"foo", 80, ns2}, "https-ose-vserver")
				Expect(ok).To(BeTrue(), "Route should be accessible.")
				Expect(rs).ToNot(BeNil(), "Route should be object.")
				Expect(len(rs.Policies[0].Rules)).To(Equal(2))
				Expect(len(rs.Pools)).To(Equal(2))
				Expect(rs.Virtual.GetProfileCountByContext(customProfileClient)).To(Equal(3))
				addr = []string{"127.0.0.0"}
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, addr)))
				Expect(rs.Pools[1].Members).To(Equal(generateExpectedAddrs(38001, addr)))

				// Delete a route
				mockMgr.deleteRoute(route2)
				Expect(resources.PoolCount()).To(Equal(2))
				rs, ok = resources.Get(
					serviceKey{"foo", 80, ns1}, "https-ose-vserver")
				Expect(ok).To(BeTrue(), "Route should be accessible.")
				Expect(rs).ToNot(BeNil(), "Route should be object.")
				Expect(len(rs.Policies[0].Rules)).To(Equal(1))
				Expect(len(rs.Pools)).To(Equal(1))
				Expect(rs.Virtual.GetProfileCountByContext(customProfileClient)).To(Equal(2))
				addr = []string{"127.0.0.0"}
				Expect(rs.Pools[0].Members).To(Equal(generateExpectedAddrs(37001, addr)))
			})
		})
	})
})
