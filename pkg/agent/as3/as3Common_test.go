package as3

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AS3Common Tests", func() {
	It("Creates AS3 monitor declaration", func() {
		// HTTPS health monitor
		healthMonitor := "test_https_hm"
		cfg := &ResourceConfig{
			MetaData: MetaData{
				ResourceType: ResourceTypeIngress,
			},
			Monitors: []Monitor{
				{Name: healthMonitor, Partition: "test", Interval: 2, Type: "https", Send: "HTTPS GET /test1",
					Timeout: 3, SslProfile: "/Common/serverssl"},
			},
		}
		sharedApp := as3Application{}
		sharedApp = make(map[string]interface{})
		createMonitorDecl(cfg, sharedApp)
		hm, ok := sharedApp[as3FormattedString(healthMonitor, cfg.MetaData.ResourceType)]
		Expect(ok).To(Equal(true), "Health monitor not created for AS3 declaration.")
		targetAddr := ""
		targetPort := 0
		dscp := 0
		timeUnitilUp := 0
		expectedHM := &as3Monitor{
			Class:         "Monitor",
			Dscp:          &dscp,
			Interval:      2,
			MonitorType:   "https",
			TargetAddress: &targetAddr,
			TimeUnitilUp:  &timeUnitilUp,
			Timeout:       3,
			Adaptive:      false,
			Send:          "HTTPS GET /test1",
			Receive:       "none",
			TargetPort:    &targetPort,
			ClientTLS: &as3ResourcePointer{
				BigIP: "/Common/serverssl",
			},
		}
		Expect(hm).To(Equal(expectedHM), "Incorrect Health monitor created for AS3 declaration.")

		// Http health monitor
		healthMonitor = "test_http_hm"
		cfg = &ResourceConfig{
			MetaData: MetaData{
				ResourceType: ResourceTypeIngress,
			},
			Monitors: []Monitor{
				{Name: healthMonitor, Partition: "test", Interval: 2, Recv: "/test3", Type: "http", Send: "HTTP GET /test2",
					Timeout: 3},
			},
		}
		sharedApp = make(map[string]interface{})
		createMonitorDecl(cfg, sharedApp)
		hm, ok = sharedApp[as3FormattedString(healthMonitor, cfg.MetaData.ResourceType)]
		Expect(ok).To(Equal(true), "Health monitor not created for AS3 declaration.")
		expectedHM = &as3Monitor{
			Class:         "Monitor",
			Dscp:          &dscp,
			Interval:      2,
			MonitorType:   "http",
			Receive:       "/test3",
			TargetAddress: &targetAddr,
			Timeout:       3,
			TimeUnitilUp:  &timeUnitilUp,
			Adaptive:      false,
			Send:          "HTTP GET /test2",
			TargetPort:    &targetPort,
		}
		Expect(hm).To(Equal(expectedHM), "Incorrect Health monitor created for AS3 declaration.")
	})
})
