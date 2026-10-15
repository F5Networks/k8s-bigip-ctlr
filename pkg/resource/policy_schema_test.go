package resource_test

import (
	"io"
	"os"
	"regexp"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestPolicySchemaPaths(t *testing.T) {
	for _, path := range []string{
		"../../docs/config_examples/customResourceDefinitions/customresourcedefinitions.yml",
		"../../docs/config_examples/customResourceDefinitions/incubator/customresourcedefinitions.yml",
	} {
		t.Run(path, func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
			found := false
			for {
				var crd apiextensionsv1.CustomResourceDefinition
				if err := decoder.Decode(&crd); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if crd.Name != "policies.cis.f5.com" {
					continue
				}
				found = true
				for _, version := range crd.Spec.Versions {
					if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
						t.Fatalf("version %s has no OpenAPI schema", version.Name)
					}
					spec := version.Schema.OpenAPIV3Schema.Properties["spec"]
					for _, field := range []struct{ group, name string }{
						{"l7Policies", "waf"},
						{"ltmPolicies", "insecure"},
						{"ltmPolicies", "secure"},
					} {
						t.Run(version.Name+"/"+field.group+"/"+field.name, func(t *testing.T) {
							pattern := spec.Properties[field.group].Properties[field.name].Pattern
							if pattern == "" {
								t.Fatal("missing path validation pattern")
							}
							re, err := regexp.Compile(pattern)
							if err != nil {
								t.Fatal(err)
							}
							for _, value := range []string{
								"/Common/arcadia",
								"/Common/arcadia123",
								"/Common/arcadia_niki",
								"/Common/arcadia-niki",
								"/Common/arcadia--niki",
								"/Common/app-folder/arcadia--niki",
							} {
								if !re.MatchString(value) {
									t.Errorf("rejected valid path %q", value)
								}
							}
							for _, value := range []string{
								"",
								"Common/arcadia-niki",
								"/Common/arcadia niki",
								"/Common/arcadia@niki",
							} {
								if re.MatchString(value) {
									t.Errorf("accepted invalid path %q", value)
								}
							}
						})
					}
				}
			}
			if !found {
				t.Fatal("Policy CRD not found")
			}
		})
	}
}
