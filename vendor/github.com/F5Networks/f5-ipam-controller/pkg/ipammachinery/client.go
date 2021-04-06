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
	v1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

func (ipamCli *IPAMClient) Create(namespace string, obj *v1.F5IPAM) (*v1.F5IPAM, error) {
	result := &v1.F5IPAM{}
	err := ipamCli.restClient.Post().
		Namespace(namespace).Resource("f5ipams").
		Body(obj).Do(context.TODO()).Into(result)
	return result, err
}

func (ipamCli *IPAMClient) Update(namespace string, obj *v1.F5IPAM) (*v1.F5IPAM, error) {
	result := &v1.F5IPAM{}
	err := ipamCli.restClient.Put().
		Namespace(namespace).Resource("f5ipams").
		Name(obj.Name).
		Body(obj).Do(context.TODO()).Into(result)
	return result, err
}

func (ipamCli *IPAMClient) Delete(namespace, name string, options *meta_v1.DeleteOptions) error {
	return ipamCli.restClient.Delete().
		Namespace(namespace).Resource("f5ipams").
		Name(name).Body(options).Do(context.TODO()).Error()
}

func (ipamCli *IPAMClient) Get(namespace, name string) (*v1.F5IPAM, error) {
	result := &v1.F5IPAM{}
	err := ipamCli.restClient.Get().
		Namespace(namespace).Resource("f5ipams").
		Name(name).Do(context.TODO()).Into(result)
	return result, err
}

func addKnownTypes(scheme *runtime.Scheme) error {
	SchemeGroupVersion := schema.GroupVersion{Group: CRDGroup, Version: CRDVersion}
	scheme.AddKnownTypes(SchemeGroupVersion,
		&v1.F5IPAM{},
		&v1.F5IPAMList{},
	)
	meta_v1.AddToGroupVersion(scheme, SchemeGroupVersion)
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
