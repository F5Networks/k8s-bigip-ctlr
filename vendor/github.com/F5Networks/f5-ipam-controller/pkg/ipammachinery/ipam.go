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
	apiextensionv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (

	// IPAM is a F5 Custom Resource Kind.
	F5ipam     = "IPAM"
	F5IPAMCtlr = "F5 IPAM Controller"

	CRDPlural        string = "ipams"
	CRDGroup         string = "fic.f5.com"
	CRDVersion       string = "v1"
	FullCRDName      string = CRDPlural + "." + CRDGroup
	HostnamePattern  string = "^(([a-zA-Z0-9\\*]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$"
	IPAddressPattern string = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
)

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
		log.Errorf("Failed to Setup Informers %v", err)
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

// RegisterCRD creates schema of IPAM and registers it with Kubernetes/Openshift
func RegisterCRD(clientset extClient.Interface) error {
	var CRDVersions = []apiextensionv1.CustomResourceDefinitionVersion{
		{Name: CRDVersion, Served: true, Storage: true, Schema: ipamCRSchemaValidation(), Subresources: ipamCRSubresources()},
	}
	crd := &apiextensionv1.CustomResourceDefinition{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:          FullCRDName,
			ManagedFields: []meta_v1.ManagedFieldsEntry{{Manager: F5IPAMCtlr}},
		},

		Spec: apiextensionv1.CustomResourceDefinitionSpec{
			Group:    CRDGroup,
			Versions: CRDVersions,
			Scope:    apiextensionv1.NamespaceScoped,
			Names: apiextensionv1.CustomResourceDefinitionNames{
				Plural: CRDPlural,
				Kind:   F5ipam,
			},
		},
	}
	_, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), crd, meta_v1.CreateOptions{})
	if err != nil && apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func ipamCRSchemaValidation() *apiextensionv1.CustomResourceValidation {
	return &apiextensionv1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensionv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]apiextensionv1.JSONSchemaProps{
					"hostSpecs": {
						Type: "array",
						Items: &apiextensionv1.JSONSchemaPropsOrArray{
							Schema: &apiextensionv1.JSONSchemaProps{Type: "object", Properties: map[string]apiextensionv1.JSONSchemaProps{
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
				Properties: map[string]apiextensionv1.JSONSchemaProps{
					"IPStatus": {
						Type: "array",
						Items: &apiextensionv1.JSONSchemaPropsOrArray{
							Schema: &apiextensionv1.JSONSchemaProps{Type: "object", Properties: map[string]apiextensionv1.JSONSchemaProps{
								"host":      {Type: "string", Format: "string", Pattern: HostnamePattern},
								"key":       {Type: "string", Format: "string"},
								"ip":        {Type: "string", Format: "string", Pattern: IPAddressPattern},
								"ipamLabel": {Type: "string", Format: "string"}},
							},
						},
					},
				},
			},
		},
	},
	}
}

func ipamCRSubresources() *apiextensionv1.CustomResourceSubresources {
	return &apiextensionv1.CustomResourceSubresources{
		Status: &apiextensionv1.CustomResourceSubresourceStatus{},
		Scale:  nil,
	}
}
