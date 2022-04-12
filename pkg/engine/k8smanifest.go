package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	kyverno "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/response"
	"github.com/kyverno/kyverno/pkg/engine/utils"

	"github.com/ghodss/yaml"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	"k8s.io/api/admission/v1beta1"

	shieldconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
)

const DefaultAnnotationKeyDomain = "cosign.sigstore.dev/"

//go:embed resources/default-config.yaml
var defaultConfigBytes []byte

func VerifyManifestSignature(ctx *PolicyContext, logger logr.Logger) *response.EngineResponse {
	resp := &response.EngineResponse{Policy: &ctx.Policy}
	if isDeleteRequest(ctx) {
		return resp
	}

	startTime := time.Now()
	defer func() {
		buildResponse(ctx, resp, startTime)
		logger.V(4).Info("finished policy processing", "processingTime", resp.PolicyResponse.ProcessingTime.String(), "rulesApplied", resp.PolicyResponse.RulesAppliedCount)
	}()

	for _, rule := range ctx.Policy.Spec.Rules {
		logger := logger.WithValues("rule", rule.Name)
		var excludeResource []string
		if len(ctx.ExcludeGroupRole) > 0 {
			excludeResource = ctx.ExcludeGroupRole
		}

		if err := MatchesResourceDescription(ctx.NewResource, rule, ctx.AdmissionInfo, excludeResource, ctx.NamespaceLabels, ctx.Policy.Namespace); err != nil {
			logger.V(4).Info("rule not matched", "reason", err.Error())
			continue
		}

		ruleResp := handleVerifyManifest(ctx, rule, logger)
		resp.Add(ruleResp)
	}

	return resp
}

func handleVerifyManifest(ctx *PolicyContext, rule kyverno.Rule, logger logr.Logger) *response.RuleResponse {
	verified, reason, err := verifyManifest(ctx, rule.Validation.Key, rule.Validation.IgnoreFields, rule.Validation.SkipUsers, rule.Validation.InScopeUsers, rule.Validation.Subject)
	if err != nil {
		return ruleError(&rule, utils.Validation, "failed to verify manifest", err)
	}

	if !verified {
		return ruleResponse(&rule, utils.Validation, reason, response.RuleStatusFail)
	}

	return ruleResponse(&rule, utils.Validation, "manifest verified", response.RuleStatusPass)
}

func verifyManifest(policyContext *PolicyContext, ecdsaPub string, ignoreFields k8smanifest.ObjectFieldBindingList, skipUsers shieldconfig.ObjectUserBindingList, inScopeUsers shieldconfig.ObjectUserBindingList, subject string) (bool, string, error) {
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
