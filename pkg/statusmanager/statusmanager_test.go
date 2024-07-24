package statusmanager

import (
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned/fake"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
)

var _ = Describe("Status Manager Tests", func() {
	var sm *StatusManager
	bigIPAddress := "192.168.1.1"
	Describe("Update Status", func() {
		Context("when update status is successful", func() {
			BeforeEach(func() {
				configCR := &cisapiv1.DeployConfig{
					ObjectMeta: metaV1.ObjectMeta{
						Name:      "sampleConfigCR",
						Namespace: "default",
					},
					Spec:   cisapiv1.DeployConfigSpec{},
					Status: cisapiv1.DeployConfigStatus{},
				}
				var kubeCRClient versioned.Interface
				kubeCRClient = crdfake.NewSimpleClientset(configCR)
				sm = NewStatusManager(&kubeCRClient, configCR.Namespace, configCR.Name)
				go sm.Start()
			})
			AfterEach(func() {
				sm.Stop()
			})

			It("Update the controller status", func() {
				// update the ok status
				timeStamp := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.ControllerStatus{
					Message:     Ok,
					LastUpdated: timeStamp,
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.ControllerStatus.Type).To(Equal(SingleCluster), "Controller status type should be single cluster")
				Expect(cr.Status.ControllerStatus.Message).To(Equal(Ok), "Controller status should be Ok")
				Expect(cr.Status.ControllerStatus.LastUpdated).To(Equal(timeStamp), "Last updated time should be equal")

				// update the error status
				timeStamp = metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.ControllerStatus{
					Message:     "error",
					Error:       fmt.Sprintf("Error: %s", "Error message"),
					LastUpdated: timeStamp,
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.ControllerStatus.Type).To(Equal(SingleCluster), "Controller should be of type singlecluster")
				Expect(cr.Status.ControllerStatus.Message).To(Equal("error"), "Controller status should be Ok")
				Expect(cr.Status.ControllerStatus.Error).To(Equal(fmt.Sprintf("Error: %s", "Error message")), "incorrect error for controller status")
				Expect(cr.Status.ControllerStatus.LastUpdated).To(Equal(timeStamp), "Last updated time should be equal")
			})

			It("Update the CM status", func() {
				// update the ok status
				timeStamp := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.CMStatus{
					Message:     Ok,
					LastUpdated: timeStamp,
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.CMStatus.Message).To(Equal(Ok), "CM status should be Ok")
				Expect(cr.Status.CMStatus.LastUpdated).To(Equal(timeStamp), "Last updated time should be equal")

				// update the error status
				timeStamp = metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.CMStatus{
					Message:     "error",
					Error:       fmt.Sprintf("Error: %s", "Error message"),
					LastUpdated: timeStamp,
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.CMStatus.Message).To(Equal("error"), "CM status message should be error")
				Expect(cr.Status.CMStatus.Error).To(Equal(fmt.Sprintf("Error: %s", "Error message")), "Incorrect error of cm status")
				Expect(cr.Status.CMStatus.LastUpdated).To(Equal(timeStamp), "Last updated time should be equal")
			})

			It("Update the BigIP AS3 status", func() {
				// update the ok status
				timeStamp := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: bigIPAddress,
					AS3Status: &cisapiv1.AS3Status{
						Message:       Ok,
						LastSubmitted: timeStamp,
					},
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[0].AS3Status.Message).To(Equal(Ok), "Incorrect BigIP AS3 status message")
				Expect(cr.Status.BigIPStatus[0].AS3Status.LastSubmitted).To(Equal(timeStamp), "Incorrect BigIP AS3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[0].AS3Status.LastSuccessful).To(Equal(timeStamp), "Incorrect BigIP AS3 status LastSuccessful")

				timeStamp2 := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: bigIPAddress,
					AS3Status: &cisapiv1.AS3Status{
						Message:       "error",
						Error:         fmt.Sprintf("Error: %s", "Error message"),
						LastSubmitted: timeStamp2,
					},
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[0].AS3Status.Message).To(Equal("error"), "Incorrect BigIP AS3 status message")
				Expect(cr.Status.BigIPStatus[0].AS3Status.LastSubmitted).To(Equal(timeStamp2), "Incorrect BigIP AS3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[0].AS3Status.LastSuccessful).To(Equal(timeStamp), "Incorrect BigIP AS3 status LastSuccessful")
				Expect(cr.Status.BigIPStatus[0].AS3Status.Error).To(Equal(fmt.Sprintf("Error: %s", "Error message")), "Incorrect error")

				// update the accepted status
				// update the ok status
				timeStamp3 := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: bigIPAddress,
					AS3Status: &cisapiv1.AS3Status{
						Message:       Accepted,
						LastSubmitted: timeStamp3,
					},
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[0].AS3Status.Message).To(Equal(Accepted), "Incorrect BigIP AS3 status message")
				Expect(cr.Status.BigIPStatus[0].AS3Status.Error).To(Equal(""), "Incorrect BigIP AS3 status message")
				Expect(cr.Status.BigIPStatus[0].AS3Status.LastSubmitted).To(Equal(timeStamp3), "Incorrect BigIP AS3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[0].AS3Status.LastSuccessful).To(Equal(timeStamp3), "Incorrect BigIP AS3 status LastSuccessful")

				// add another bigip status
				timeStamp4 := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: "192.168.1.2",
					AS3Status: &cisapiv1.AS3Status{
						Message:       Ok,
						LastSubmitted: timeStamp4,
					},
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[1].AS3Status.Message).To(Equal(Ok), "Incorrect BigIP AS3 status message")
				Expect(cr.Status.BigIPStatus[1].AS3Status.LastSubmitted).To(Equal(timeStamp4), "Incorrect BigIP AS3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[1].AS3Status.LastSuccessful).To(Equal(timeStamp4), "Incorrect BigIP AS3 status LastSuccessful")

				// let's delete this new bigip status
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", true, &cisapiv1.BigIPStatus{
					BigIPAddress: "192.168.1.2",
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(len(cr.Status.BigIPStatus)).To(Equal(1), "Incorrect no of BigIP status")

			})

			It("Update the BigIP L3 status", func() {
				// update the ok status
				timeStamp := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: bigIPAddress,
					L3Status: &cisapiv1.L3Status{
						Message:       Ok,
						LastSubmitted: timeStamp,
					},
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[0].L3Status.Message).To(Equal(Ok), "BigIP L3 status should be Ok")
				Expect(cr.Status.BigIPStatus[0].L3Status.LastSubmitted).To(Equal(timeStamp), "Incorrect BigIP L3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[0].L3Status.LastSuccessful).To(Equal(timeStamp), "Incorrect BigIP L3 status LastSuccessful")

				timeStamp2 := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: bigIPAddress,
					L3Status: &cisapiv1.L3Status{
						Message:       "error",
						Error:         fmt.Sprintf("Error: %s", "Error message"),
						LastSubmitted: timeStamp2,
					},
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[0].L3Status.Message).To(Equal("error"), "Incorrect BigIP L3 status message")
				Expect(cr.Status.BigIPStatus[0].L3Status.LastSubmitted).To(Equal(timeStamp2), "Incorrect BigIP L3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[0].L3Status.LastSuccessful).To(Equal(timeStamp), "Incorrect BigIP L3 status LastSuccessful")
				Expect(cr.Status.BigIPStatus[0].L3Status.Error).To(Equal(fmt.Sprintf("Error: %s", "Error message")), "Incorrect error")

				// update the Accepted status
				timeStamp3 := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.BigIPStatus{
					BigIPAddress: bigIPAddress,
					L3Status: &cisapiv1.L3Status{
						Message:       Accepted,
						LastSubmitted: timeStamp3,
					},
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.BigIPStatus[0].L3Status.Message).To(Equal(Accepted), "BigIP L3 status should be Ok")
				Expect(cr.Status.BigIPStatus[0].L3Status.Error).To(Equal(""), "BigIP L3 status should be Ok")
				Expect(cr.Status.BigIPStatus[0].L3Status.LastSubmitted).To(Equal(timeStamp3), "Incorrect BigIP L3 status LastSubmitted")
				Expect(cr.Status.BigIPStatus[0].L3Status.LastSuccessful).To(Equal(timeStamp3), "Incorrect BigIP L3 status LastSuccessful")

			})

			It("Update the NetworkConfig status", func() {
				// update the ok status
				timeStamp := metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.NetworkConfigStatus{
					Message:     Ok,
					LastUpdated: timeStamp,
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.NetworkConfigStatus.Message).To(Equal(Ok), "NetworkConfig status should be Ok")
				Expect(cr.Status.NetworkConfigStatus.LastUpdated).To(Equal(timeStamp), "Last updated time should be equal")

				// update the error status
				timeStamp = metaV1.Now()
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.NetworkConfigStatus{
					Message:     "error",
					Error:       fmt.Sprintf("Error: %s", "Error message"),
					LastUpdated: timeStamp,
				})
				time.Sleep(1 * time.Second)
				cr = sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.NetworkConfigStatus.Message).To(Equal("error"), "NetworkConfig status should be Ok")
				Expect(cr.Status.NetworkConfigStatus.Error).To(Equal(fmt.Sprintf("Error: %s", "Error message")), "Incorrect Error message")
				Expect(cr.Status.NetworkConfigStatus.LastUpdated).To(Equal(timeStamp), "Last updated time should be equal")
			})

			It("Update the HA status", func() {
				// update the ok status
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.HAStatus{
					PrimaryEndPointStatus: Ok,
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.HAStatus[0].PrimaryEndPointStatus).To(Equal(Ok), "HA status should be Ok")
			})
			It("Update the Kubernetes status", func() {
				// update the ok status
				sm.AddRequest(DeployConfig, "sampleConfigCR", "default", false, &cisapiv1.K8SClusterStatus{
					Message: Ok,
				})
				time.Sleep(1 * time.Second)
				cr := sm.GetDeployConfigCR("sampleConfigCR", "default")
				Expect(cr).ToNot(BeNil(), "CR should not be nil")
				Expect(cr.Status.K8SClusterStatus[0].Message).To(Equal(Ok), "K8s Cluster status should be Ok")
			})
		})
	})
})
