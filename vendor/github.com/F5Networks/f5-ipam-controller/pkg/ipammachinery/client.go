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
	"bytes"
	"context"
	"encoding/json"
	v1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	log "github.com/F5Networks/f5-ipam-controller/pkg/vlogger"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	typesV1 "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"strings"
)

const MAX_RETRIES = 10

func (ipamCli *IPAMClient) Create(obj *v1.F5IPAM) (*v1.F5IPAM, error) {
	return ipamCli.kubeCRClient.K8sV1().F5IPAMs(obj.Namespace).Create(context.TODO(), obj, metaV1.CreateOptions{})
}

func (ipamCli *IPAMClient) Update(obj *v1.F5IPAM) (res *v1.F5IPAM, err error) {
	name := obj.Name
	namespace := obj.Namespace
	spec := obj.Spec

	for i := 0; i < MAX_RETRIES; i++ {
		res, err = ipamCli.kubeCRClient.K8sV1().F5IPAMs(namespace).Update(context.TODO(), obj, metaV1.UpdateOptions{})
		if err == nil {
			return
		}
		// For any other error, return the nil resource and error
		// For the below particular error try again
		if !strings.Contains(err.Error(), "please apply your changes to the latest version") {
			return
		}
		obj, err = ipamCli.Get(namespace, name)
		if err != nil {
			log.Errorf("Unable to find F5IPAM: %v/%v to update. Error: %v",
				namespace, name, err)
			return
		}
		obj.Spec = spec
	}
	return
}

func (ipamCli *IPAMClient) UpdateStatus(obj *v1.F5IPAM) (res *v1.F5IPAM, err error) {
	name := obj.Name
	namespace := obj.Namespace
	status := obj.Status

	for i := 0; i < MAX_RETRIES; i++ {
		res, err = ipamCli.kubeCRClient.K8sV1().F5IPAMs(namespace).UpdateStatus(context.TODO(), obj, metaV1.UpdateOptions{})
		if err == nil {
			return
		}
		// For any other error, return the nil resource and error
		// For the below particular error try again
		if !strings.Contains(err.Error(), "please apply your changes to the latest version") {
			return
		}
		obj, err = ipamCli.Get(namespace, name)
		if err != nil {
			log.Errorf("Unable to find F5IPAM: %v/%v to update status. Error: %v",
				namespace, name, err)
			return
		}
		obj.Status = status
	}
	return
}

func (ipamCli *IPAMClient) Patch(obj *v1.F5IPAM) (*v1.F5IPAM, error) {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(obj)

	return ipamCli.kubeCRClient.K8sV1().F5IPAMs(obj.Namespace).Patch(
		context.TODO(),
		obj.Name,
		typesV1.StrategicMergePatchType,
		buf.Bytes(),
		metaV1.PatchOptions{
			FieldManager: F5IPAMCtlr,
		},
		"spec")
}

func (ipamCli *IPAMClient) Delete(namespace, name string, options metaV1.DeleteOptions) error {
	return ipamCli.kubeCRClient.K8sV1().F5IPAMs(namespace).Delete(context.TODO(), name, options)
}

func (ipamCli *IPAMClient) Get(namespace, name string) (*v1.F5IPAM, error) {
	return ipamCli.kubeCRClient.K8sV1().F5IPAMs(namespace).Get(context.TODO(), name, metaV1.GetOptions{})
}

func addKnownTypes(scheme *runtime.Scheme) error {
	SchemeGroupVersion := schema.GroupVersion{Group: CRDGroup, Version: CRDVersion}
	scheme.AddKnownTypes(SchemeGroupVersion,
		&v1.F5IPAM{},
		&v1.F5IPAMList{},
	)
	metaV1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

func NewRESTClient(cfg *rest.Config) (rest.Interface, error) {
	scheme := runtime.NewScheme()
	SchemeBuilder := runtime.NewSchemeBuilder(addKnownTypes)
	if err := SchemeBuilder.AddToScheme(scheme); err != nil {
		return nil, err
	}
	SchemeGroupVersion := schema.GroupVersion{Group: CRDGroup, Version: CRDVersion}
	config := *cfg
	config.GroupVersion = &SchemeGroupVersion
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.NewCodecFactory(scheme)
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return client, nil
}
