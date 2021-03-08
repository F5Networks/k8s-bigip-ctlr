package ipammachinery

import (
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
		Body(obj).Do().Into(result)
	return result, err
}

func (ipamCli *IPAMClient) Update(namespace string, obj *v1.F5IPAM) (*v1.F5IPAM, error) {
	result := &v1.F5IPAM{}
	err := ipamCli.restClient.Put().
		Namespace(namespace).Resource("f5ipams").
		Name(obj.Name).
		Body(obj).Do().Into(result)
	return result, err
}

func (ipamCli *IPAMClient) Delete(namespace, name string, options *meta_v1.DeleteOptions) error {
	return ipamCli.restClient.Delete().
		Namespace(namespace).Resource("f5ipams").
		Name(name).Body(options).Do().Error()
}

func (ipamCli *IPAMClient) Get(namespace, name string) (*v1.F5IPAM, error) {
	result := &v1.F5IPAM{}
	err := ipamCli.restClient.Get().
		Namespace(namespace).Resource("f5ipams").
		Name(name).Do().Into(result)
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
