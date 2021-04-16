/*-
* Copyright (c) 2021, F5 Networks, Inc.
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

package ipammachinery

import (
	"context"
	"fmt"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/client/clientset/versioned"
	log "github.com/F5Networks/f5-ipam-controller/pkg/vlogger"
	apiextensionv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (

	// F5IPAM is a F5 Custom Resource Kind.
	F5ipam     = "F5IPAM"
	F5IPAMCtlr = "F5 IPAM Controller"

	CRDPlural        string = "f5ipams"
	CRDGroup         string = "fic.f5.com"
	CRDVersion       string = "v1"
	FullCRDName      string = CRDPlural + "." + CRDGroup
	HostnamePattern  string = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$"
	IPADdressPattern string = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
)

var CRDVersions = []apiextensionv1beta1.CustomResourceDefinitionVersion{{Name: CRDVersion, Served: true, Storage: true}}

// NewIPAM creates a new IPAMClient Instance.
func NewIPAMClient(params Params) *IPAMClient {

	ipamCli := &IPAMClient{
		namespaces:    make(map[string]bool),
		ipamInformers: make(map[string]*IPAMInformer),
	}
	for _, ns := range params.Namespaces {
		ipamCli.namespaces[ns] = true
	}

	if err := ipamCli.setupClients(params.Config); err != nil {
		log.Error(err.Error())
		return nil
	}

	if err := ipamCli.setupInformersWithEventHandlers(params.EventHandlers); err != nil {
		log.Error("Failed to Setup Informers")
	}

	log.Debugf("Created New IPAM Client")

	return ipamCli
}

// setupClients sets Kubernetes Clients.
func (ipamCli *IPAMClient) setupClients(config *rest.Config) error {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create kubeClient: %v", err)
	}

	kubeCRClient, err := versioned.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create Custom Resource Client: %v", err)
	}

	restCli, err := NewRESTClient(config)
	if err != nil {
		return fmt.Errorf("Failed to create Kubernets REST Client: %v", err)
	}

	ipamCli.kubeCRClient = kubeCRClient
	ipamCli.kubeClient = kubeClient
	ipamCli.restClient = restCli

	return nil
}

func (ipamCli *IPAMClient) setupInformersWithEventHandlers(eventHandlers *cache.ResourceEventHandlerFuncs) error {
	for ns, _ := range ipamCli.namespaces {
		if err := ipamCli.addNamespacedInformer(ns, eventHandlers); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v, Error:%v", "default", err)
			return err
		}
	}

	return nil
}

// Start the Custom Resource Manager
func (ipamCli *IPAMClient) Start() {
	for _, inf := range ipamCli.ipamInformers {
		inf.start()
	}
}

func (ipamCli *IPAMClient) Stop() {
	for _, inf := range ipamCli.ipamInformers {
		inf.stop()
	}
}

// RegisterCRD creates schema of F5IPAM and registers it with Kubernetes/Openshift
func RegisterCRD(clientset extClient.Interface) error {
	crd := &apiextensionv1beta1.CustomResourceDefinition{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:          FullCRDName,
			ManagedFields: []meta_v1.ManagedFieldsEntry{{Manager: F5IPAMCtlr}},
		},

		Spec: apiextensionv1beta1.CustomResourceDefinitionSpec{
			Group:    CRDGroup,
			Versions: CRDVersions,
			Scope:    apiextensionv1beta1.NamespaceScoped,
			Names: apiextensionv1beta1.CustomResourceDefinitionNames{
				Plural: CRDPlural,
				Kind:   F5ipam,
			},
			Subresources: &apiextensionv1beta1.CustomResourceSubresources{
				Status: &apiextensionv1beta1.CustomResourceSubresourceStatus{},
				Scale:  nil,
			},
			Validation: &apiextensionv1beta1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionv1beta1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextensionv1beta1.JSONSchemaProps{
					"spec": {
						Type: "object",
						Properties: map[string]apiextensionv1beta1.JSONSchemaProps{
							"hostSpecs": {
								Type: "array",
								Items: &apiextensionv1beta1.JSONSchemaPropsOrArray{
									Schema: &apiextensionv1beta1.JSONSchemaProps{Type: "object", Properties: map[string]apiextensionv1beta1.JSONSchemaProps{
										"host":      {Type: "string", Format: "string", Pattern: HostnamePattern},
										"key":       {Type: "string", Format: "string"},
										"ipamLabel": {Type: "string", Format: "string"}},
									},
								},
							},
						},
					},
					"status": {
						Type: "object",
						Properties: map[string]apiextensionv1beta1.JSONSchemaProps{
							"IPStatus": {
								Type: "array",
								Items: &apiextensionv1beta1.JSONSchemaPropsOrArray{
									Schema: &apiextensionv1beta1.JSONSchemaProps{Type: "object", Properties: map[string]apiextensionv1beta1.JSONSchemaProps{
										"host":      {Type: "string", Format: "string", Pattern: HostnamePattern},
										"key":       {Type: "string", Format: "string"},
										"ip":        {Type: "string", Format: "string", Pattern: IPADdressPattern},
										"ipamLabel": {Type: "string", Format: "string"}},
									},
								},
							},
						},
					},
				},
			},
			},
		},
	}
	_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(context.TODO(), crd, meta_v1.CreateOptions{})
	if err != nil && apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}
