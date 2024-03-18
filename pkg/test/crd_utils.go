package test

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// VirtualServer is a F5 Custom Resource Kind.
	VirtualServer = "VirtualServer"
	// TLSProfile is a F5 Custom Resource Kind
	TLSProfile = "TLSProfile"
	// IngressLink is a Custom Resource used by both F5 and Nginx
	IngressLink = "IngressLink"
	// TransportServer is a F5 Custom Resource Kind
	TransportServer = "TransportServer"
	// ExternalDNS is a F5 Customr Resource Kind
	ExternalDNS = "ExternalDNS"
	// DeployConfig is a F5 Customr Resource Kind
	DeployConfig = "DeployConfig"
	// IPAM is a F5 Customr Resource Kind
	IPAM = "IPAM"
)

func NewVirtualServer(name, namespace string, spec cisapiv1.VirtualServerSpec) *cisapiv1.VirtualServer {
	return &cisapiv1.VirtualServer{
		TypeMeta: metav1.TypeMeta{
			Kind:       VirtualServer,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

func NewTLSProfile(name, namespace string, spec cisapiv1.TLSProfileSpec) *cisapiv1.TLSProfile {
	return &cisapiv1.TLSProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       TLSProfile,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

func NewTransportServer(name, namespace string, spec cisapiv1.TransportServerSpec) *cisapiv1.TransportServer {
	return &cisapiv1.TransportServer{
		TypeMeta: metav1.TypeMeta{
			Kind:       TransportServer,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

func NewPolicy(name, namespace string, spec cisapiv1.PolicySpec) *cisapiv1.Policy {
	return &cisapiv1.Policy{
		TypeMeta: metav1.TypeMeta{
			Kind:       TransportServer,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

func NewIngressLink(name, namespace, rv string, spec cisapiv1.IngressLinkSpec) *cisapiv1.IngressLink {
	return &cisapiv1.IngressLink{
		TypeMeta: metav1.TypeMeta{
			Kind:       IngressLink,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			ResourceVersion: rv,
		},
		Spec: spec,
	}
}

func NewExternalDNS(name, namespace string, spec cisapiv1.ExternalDNSSpec) *cisapiv1.ExternalDNS {
	return &cisapiv1.ExternalDNS{
		TypeMeta: metav1.TypeMeta{
			Kind:       ExternalDNS,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

func NewConfigCR(name, namespace string, spec cisapiv1.DeployConfigSpec) *cisapiv1.DeployConfig {
	return &cisapiv1.DeployConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       DeployConfig,
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}
