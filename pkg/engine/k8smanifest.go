package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	shieldconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	"k8s.io/api/admission/v1beta1"
)

const DefaultAnnotationKeyDomain = "cosign.sigstore.dev/"

// This is common ignore fields for changes by k8s system
//go:embed resources/default-config.yaml
var defaultConfigBytes []byte

func VerifyManifest(policyContext *PolicyContext, ecdsaPub string, ignoreFields k8smanifest.ObjectFieldBindingList, skipUsers shieldconfig.ObjectUserBindingList, inScopeUsers shieldconfig.ObjectUserBindingList, subject string) (bool, string, error) {
	vo := &k8smanifest.VerifyResourceOption{}
	// adding default ignoreFields from github.com/sigstore/k8s-manifest-sigstore/blob/main/pkg/k8smanifest/resources/default-config.yaml
	vo = k8smanifest.AddDefaultConfig(vo)
	// kubectl mutates the manifet request before it reaches to kyverno.
	// adding default ignoreFields from ../resources/default-config.yaml
	vo = addDefaultConfig(vo)
	// appending user supplied ignoreFields.
	vo.IgnoreFields = append(vo.IgnoreFields, ignoreFields...)
	// call ishield:manifest verify
	mvconfig := shieldconfig.NewManifestVerifyConfig(config.KyvernoNamespace)
	manifestVerifyRule := &shieldconfig.ManifestVerifyRule{
		VerifyResourceOption: *vo,
		SkipUsers:            skipUsers,
		InScopeUsers:         inScopeUsers,
	}
	manifestVerifyRule.Signers = append(manifestVerifyRule.Signers, subject)
	key := shieldconfig.KeyConfig{
		Key: shieldconfig.Key{
			PEM:  ecdsaPub,
			Name: policyContext.Policy.Name,
		},
	}
	manifestVerifyRule.KeyConfigs = append(manifestVerifyRule.KeyConfigs, key)
	request, err := policyContext.JSONContext.Query("request")
	if err != nil {
		return false, fmt.Sprintf("failed to get a request from policyContext: %s", err.Error()), err
	}
	reqByte, _ := json.Marshal(request)
	var adreq *v1beta1.AdmissionRequest
	err = json.Unmarshal(reqByte, &adreq)
	if err != nil {
		return false, fmt.Sprintf("failed to unmarshal a request from requestByte: %s", err.Error()), err
	}
	return shield.VerifyResource(adreq, mvconfig, manifestVerifyRule)
}

func addConfig(vo, defaultConfig *k8smanifest.VerifyResourceOption) *k8smanifest.VerifyResourceOption {
	if vo == nil {
		return nil
	}
	ignoreFields := []k8smanifest.ObjectFieldBinding(vo.IgnoreFields)
	ignoreFields = append(ignoreFields, []k8smanifest.ObjectFieldBinding(defaultConfig.IgnoreFields)...)
	vo.IgnoreFields = ignoreFields
	return vo
}

func loadDefaultConfig() *k8smanifest.VerifyResourceOption {
	var defaultConfig *k8smanifest.VerifyResourceOption
	err := yaml.Unmarshal(defaultConfigBytes, &defaultConfig)
	if err != nil {
		return nil
	}
	return defaultConfig
}

func addDefaultConfig(vo *k8smanifest.VerifyResourceOption) *k8smanifest.VerifyResourceOption {
	dvo := loadDefaultConfig()
	return addConfig(vo, dvo)
}
