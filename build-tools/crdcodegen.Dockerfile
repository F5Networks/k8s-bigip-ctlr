FROM golang:1.17

ENV GO111MODULE on

ENV PKGPATH /go/src/github.com/F5Networks/k8s-bigip-ctlr/v3

RUN mkdir -p ${GOPATH}/src/github.com/F5Networks \
	&& mkdir -p ${GOPATH}/src/k8s.io \
	&& go get -d k8s.io/code-generator@v0.20.4 \
	&& go get -d k8s.io/apimachinery \
	&& go get -d k8s.io/apiextensions-apiserver \
	&& cp -r ${GOPATH}/pkg/mod/k8s.io/api@* ${GOPATH}/src/k8s.io/api \
	&& cp -r ${GOPATH}/pkg/mod/k8s.io/apiextensions-apiserver@* ${GOPATH}/src/k8s.io/apiextensions-apiserver \
	&& cp -r ${GOPATH}/pkg/mod/k8s.io/apimachinery@* ${GOPATH}/src/k8s.io/apimachinery \
	&& cp -r ${GOPATH}/pkg/mod/k8s.io/client-go@* ${GOPATH}/src/k8s.io/client-go \
	&& cp -r ${GOPATH}/pkg/mod/k8s.io/gengo@* ${GOPATH}/src/k8s.io/gengo \
	&& cp -r ${GOPATH}/pkg/mod/k8s.io/code-generator@* ${GOPATH}/src/k8s.io/code-generator \
	&& cp ${GOPATH}/src/k8s.io/code-generator/generate-groups.sh ${GOPATH}/src/k8s.io/code-generator/generate-groups-extra.sh \
	&& echo 'if [ "${GENS}" = "allcustom" ] || grep -qw "deepcopy" <<<"${GENS}"; then\necho "Generating deepcopy funcs"\n"${gobin}/deepcopy-gen" --input-dirs "$(codegen::join , "${FQ_APIS[@]}")" -O zz_generated.deepcopy --bounding-dirs "${APIS_PKG}" "$@"\nfi\nif [ "${GENS}" = "allcustom" ] || grep -qw "client" <<<"${GENS}"; then\necho "Generating clientset for ${GROUPS_WITH_VERSIONS} at ${OUTPUT_PKG}/${CLIENTSET_PKG_NAME:-clientset}"\n"${gobin}/client-gen" --clientset-name "${CLIENTSET_NAME_VERSIONED:-versioned}" --input-base "" --input "$(codegen::join , "${FQ_APIS[@]}")" --plural-exceptions="ExternalDNS:ExternalDNSes" --output-package "${OUTPUT_PKG}/${CLIENTSET_PKG_NAME:-clientset}" "$@"\nfi\nif [ "${GENS}" = "allcustom" ] || grep -qw "lister" <<<"${GENS}"; then\necho "Generating listers for ${GROUPS_WITH_VERSIONS} at ${OUTPUT_PKG}/listers"\n"${gobin}/lister-gen" --input-dirs "$(codegen::join , "${FQ_APIS[@]}")" --plural-exceptions="ExternalDNS:ExternalDNSes" --output-package "${OUTPUT_PKG}/listers" "$@"\nfi\n\nif [ "${GENS}" = "allcustom" ] || grep -qw "informer" <<<"${GENS}"; then\necho "Generating informers for ${GROUPS_WITH_VERSIONS} at ${OUTPUT_PKG}/informers"\n"${gobin}/informer-gen" \\\n--input-dirs "$(codegen::join , "${FQ_APIS[@]}")" \\\n--versioned-clientset-package "${OUTPUT_PKG}/${CLIENTSET_PKG_NAME:-clientset}/${CLIENTSET_NAME_VERSIONED:-versioned}" \\\n--listers-package "${OUTPUT_PKG}/listers" \\\n--plural-exceptions="ExternalDNS:ExternalDNSes" \\\n--output-package "${OUTPUT_PKG}/informers" \\\n"$@"\nfi' >> ${GOPATH}/src/k8s.io/code-generator/generate-groups-extra.sh \
	&& chmod +x ${GOPATH}/src/k8s.io/code-generator/generate-groups-extra.sh \
	&& mkdir -p ${PKGPATH}

WORKDIR ${PKGPATH}

ENTRYPOINT $GOPATH/src/k8s.io/code-generator/generate-groups-extra.sh allcustom "github.com/F5Networks/k8s-bigip-ctlr/v3/config/client" "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis" cis:v1
