package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
<<<<<<< HEAD
=======
	"github.com/go-logr/logr"
	kyverno "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/engine/response"
	"github.com/kyverno/kyverno/pkg/engine/utils"
	"github.com/pkg/errors"
	"io/ioutil"
	"strings"
	"time"
>>>>>>> 6723133c0c387d7bf663efd81d56d537e7f0b16e

	"github.com/ghodss/yaml"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	shieldconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	"k8s.io/api/admission/v1beta1"
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
	verified, diff, err := verifyManifest(ctx, rule.Validation.Key, rule.Validation.IgnoreFields)
	if err != nil {
		return ruleError(&rule, utils.Validation, "failed to verify manifest", err)
	}

	if !verified {
		return ruleResponse(&rule, utils.Validation, "manifest mismatch: diff: "+diff.String(), response.RuleStatusFail)
	}

	return ruleResponse(&rule, utils.Validation, "manifest verified", response.RuleStatusPass)
}

func verifyManifest(policyContext *PolicyContext, ecdsaPub string, ignoreFields k8smanifest.ObjectFieldBindingList) (bool, *mapnode.DiffResult, error) {
	vo := &k8smanifest.VerifyResourceOption{}

	// adding default ignoreFields from
	// github.com/sigstore/k8s-manifest-sigstore/blob/main/pkg/k8smanifest/resources/default-config.yaml
	vo = k8smanifest.AddDefaultConfig(vo)

	// adding default ignoreFields from pkg/engine/resources/default-config.yaml
	vo = addDefaultConfig(vo)

	objManifest, err := yaml.Marshal(policyContext.NewResource.Object)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to marshal YAML")
	}

	annotation := policyContext.NewResource.GetAnnotations()
	signatureAnnotationKey := DefaultAnnotationKeyDomain + "signature"
	messageAnnotationKey := DefaultAnnotationKeyDomain + "message"

	sig, _ := base64.StdEncoding.DecodeString(annotation[signatureAnnotationKey])

	gzipMsg, _ := base64.StdEncoding.DecodeString(annotation[messageAnnotationKey])
	// `gzipMsg` is a gzip compressed .tar.gz file, so getting a tar ball by decompressing it.
	message := k8smnfutil.GzipDecompress(gzipMsg)
	byteStream := bytes.NewBuffer(message)
	uncompressedStream, err := gzip.NewReader(byteStream)
	if err != nil {
		return false, nil, fmt.Errorf("unzip err: %v\n", err)
	}
	defer uncompressedStream.Close()

	// reading a tar ball, in-memory.
	byteSlice, err := ioutil.ReadAll(uncompressedStream)
	if err != nil {
		return false, nil, fmt.Errorf("read err :%v", err)
	}
	i := strings.Index(string(byteSlice), "apiVersion")
	byteSlice = byteSlice[i:]
	var foundManifest []byte
	for _, ch := range byteSlice {
		if ch != 0 {
			foundManifest = append(foundManifest, ch)
		} else {
			break
		}
	}

	var obj unstructured.Unstructured
	_ = yaml.Unmarshal(objManifest, &obj)
	// appending user supplied ignoreFields.
	vo.IgnoreFields = append(vo.IgnoreFields, ignoreFields...)
	// get ignore fields configuration for this resource if found.
	var ignore []string
	if vo != nil {
		if ok, fields := vo.IgnoreFields.Match(obj); ok {
			ignore = append(ignore, fields...)
		}
	}

	var mnfMatched bool
	var diff *mapnode.DiffResult
	var diffsForAllCandidates []*mapnode.DiffResult
	cndMatched, tmpDiff, err := matchManifest(objManifest, foundManifest, ignore)
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

