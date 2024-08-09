package cccl

import (
	"fmt"
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Agent AS3 Tests", func() {
	var cm *CCCLManager
	var cfg *ResourceConfig
	var agentresources *AgentResources
	var mw *test.MockWriter
	BeforeEach(func() {
		mw = &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		cm = NewCCCLManager(&Params{ConfigWriter: mw,
			EventChan: make(chan interface{}, 1)})
		cm.Profs = make(map[SecretKey]CustomProfile)
		clientSecret := SecretKey{Name: "test-client-secret", ResourceName: "test_virtual_secure"}
		serverSecret := SecretKey{Name: "test-server-secret", ResourceName: "test_virtual_secure"}
		cm.Profs[clientSecret] = CustomProfile{
			Name:         "test-clientssl",
			Partition:    DEFAULT_PARTITION,
			Context:      "clientside",
			Cert:         "cert",
			Key:          "key",
			ServerName:   "foo.com",
			SNIDefault:   true,
			PeerCertMode: PeerCertRequired,
			CAFile:       "ca-file",
			ChainCA:      "ca-chain",
		}
		cm.Profs[serverSecret] = CustomProfile{
			Name:         "test-serverssl",
			Partition:    DEFAULT_PARTITION,
			Context:      "serverside",
			Cert:         "cert",
			Key:          "",
			ServerName:   "foo.com",
			SNIDefault:   true,
			PeerCertMode: PeerCertRequired,
			CAFile:       "ca-file",
			ChainCA:      "ca-chain",
		}
		cm.IrulesMap = IRulesMap{}
		cm.IrulesMap[NameRef{Name: "test_irule", Partition: DEFAULT_PARTITION}] = &IRule{Name: "test_irule", Partition: DEFAULT_PARTITION, Code: "Dummy Code"}
		idg := InternalDataGroup{Name: "test_datagroup", Partition: DEFAULT_PARTITION, Records: InternalDataGroupRecords{InternalDataGroupRecord{Name: "test_record", Data: "test-data"}}}
		dgnm := DataGroupNamespaceMap{}
		dgnm[ReencryptServerSslDgName] = &idg
		cm.IntDgMap = InternalDataGroupMap{}
		cm.IntDgMap[NameRef{Name: ReencryptServerSslDgName, Partition: DEFAULT_PARTITION}] = dgnm
		cfg = &ResourceConfig{
			MetaData: MetaData{
				Active: true,
			},
			Pools:    []Pool{{Name: "test", Partition: DEFAULT_PARTITION, ServiceName: "test-svc", ServicePort: 80, MonitorNames: []string{"test_monitor"}, Members: []Member{{Port: 80, Address: "192.168.1.2"}}}},
			Monitors: []Monitor{{Name: "test_monitor", Partition: DEFAULT_PARTITION, Type: "tcp", Interval: 10, Send: "GET /", Recv: ""}},
			Policies: []Policy{{Name: "test_policy1", Partition: DEFAULT_PARTITION, Controls: []string{"forwarding"}, Rules: Rules{},
				Requires: []string{}},
				{Name: "test_policy2", Partition: DEFAULT_PARTITION, Controls: []string{"forwarding"}, Rules: Rules{},
					Requires: []string{}}},
		}
		agentresources = &AgentResources{
			RsMap: ResourceConfigMap{},
		}
	})
	AfterEach(func() {
		close(cm.eventChan)
		mw.Stop()
	})
	Context("Mock Writer Success", func() {
		It("CCCL Agent function OutputConfigLocked with iapp", func() {
			cfg.IApp = IApp{Name: "test",
				Partition:           DEFAULT_PARTITION,
				IAppPoolMemberTable: &IappPoolMemberTable{}}
			cfg.MetaData.ResourceType = "iapp"
			agentresources.RsMap[NameRef{Name: "test", Partition: DEFAULT_PARTITION}] = cfg
			cm.Resources = agentresources
			Expect(len(mw.Sections)).To(Equal(0), "Section map should not have any entry")
			cm.OutputConfigLocked()
			msg := <-cm.eventChan
			Expect(msg).ToNot(BeNil(), "Channel should not be empty")
			member := msg.([]Member)
			Expect(member[0].Address).To(Equal("192.168.1.2"), "Member address should be 192.168.1.2")
			Expect(mw.WrittenTimes).To(Equal(1), "Should write one time only")
			out, ok := mw.Sections["resources"]
			Expect(ok).To(BeTrue(), "Section map should not be empty")
			partitionMap := out.(PartitionMap)
			bigipConfig, ok2 := partitionMap[DEFAULT_PARTITION]
			Expect(ok2).To(BeTrue(), "resource map should not be empty")
			Expect(len(bigipConfig.IRules)).ToNot(Equal(0), "iRules should not be zero")
			Expect(len(bigipConfig.Policies)).ToNot(Equal(0), "Policy should not be zero")
			Expect(len(bigipConfig.Monitors)).ToNot(Equal(0), "Monitors should not be zero")
			Expect(len(bigipConfig.Virtuals)).To(Equal(0), "Virtuals should be zero")
			Expect(len(bigipConfig.IApps)).ToNot(Equal(0), "iApps should not be zero")
			Expect(len(bigipConfig.IApps[0].IAppPoolMemberTable.Members)).ToNot(Equal(0), "iApps pool members should not be zero")
			Expect(len(bigipConfig.Pools)).To(Equal(0), "Pools should be zero")
			Expect(len(bigipConfig.CustomProfiles)).ToNot(Equal(0), "custom profiles should not be zero")
			Expect(len(bigipConfig.InternalDataGroups)).ToNot(Equal(0), "internal data groups should not be zero")
		})
		It("CCCL Agent function OutputConfigLocked with virtual", func() {
			cfg.Virtual = Virtual{Name: "test",
				Partition:   DEFAULT_PARTITION,
				Destination: fmt.Sprintf("/%s/%s%s%s:%d", DEFAULT_PARTITION, "192.168.1.3", "24", "0", 443),
				IRules:      []string{"test_irule", SslPassthroughIRuleName}}
			agentresources.RsMap[NameRef{Name: "test", Partition: DEFAULT_PARTITION}] = cfg
			cm.Resources = agentresources
			Expect(len(mw.Sections)).To(Equal(0), "Section map should not have any entry")
			cm.OutputConfigLocked()
			msg := <-cm.eventChan
			Expect(msg).ToNot(BeNil(), "Channel should not be empty")
			member := msg.([]Member)
			Expect(member[0].Address).To(Equal("192.168.1.2"), "Member address should be 192.168.1.2")
			Expect(mw.WrittenTimes).To(Equal(1), "Should write one time only")
			out, ok := mw.Sections["resources"]
			Expect(ok).To(BeTrue(), "Section map should not be empty")
			partitionMap := out.(PartitionMap)
			bigipConfig, ok2 := partitionMap[DEFAULT_PARTITION]
			Expect(ok2).To(BeTrue(), "resource map should not be empty")
			Expect(len(bigipConfig.IRules)).ToNot(Equal(0), "iRules should not be zero")
			Expect(len(bigipConfig.Policies)).ToNot(Equal(0), "Policy should not be zero")
			Expect(len(bigipConfig.Monitors)).ToNot(Equal(0), "Monitors should not be zero")
			Expect(len(bigipConfig.Virtuals)).ToNot(Equal(0), "Virtuals should not be zero")
			Expect(len(bigipConfig.IApps)).To(Equal(0), "iApps should be zero")
			Expect(len(bigipConfig.Pools)).ToNot(Equal(0), "Pools should not be zero")
			Expect(len(bigipConfig.CustomProfiles)).ToNot(Equal(0), "custom profiles should not be zero")
			Expect(len(bigipConfig.InternalDataGroups)).ToNot(Equal(0), "internal data groups should not be zero")
		})
	})
})
