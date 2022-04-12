package engine

import (
	"testing"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	shieldconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"gotest.tools/assert"
)

var test_policy = `{}`

var signedResource = `{
	"apiVersion": "v1",
	"data": {
		"comment": "comment1",
		"key1": "val1",
		"key2": "val2"
	},
	"kind": "ConfigMap",
	"metadata": {
		"annotations": {
			"cosign.sigstore.dev/message": "H4sIAAAAAAAA/wD8AAP/H4sIAAAAAAAA/+zRu27DIBQGYGaeghdIOVzsNKydu1Vdq9MYW5Y54AKJmjx9leuYsVUlf8vPz2U4Qu4xyz6Fzuci41EqeJ7C19DpGj+BDNFHMGS/LQDAEOWb3Caasy9ljMOqYl4Nx2azMQBGyYI0B7/a0tMBKbC709vW2nOu2+acoC/9RDVrpqyGprXQasPAQKvWTAD7BbtSMTOAPO269OBeqdj3D86vs9zzn8B5fPe5jCk6sVd8GmPnxEuK/Ti84szJV+ywouNCRCTvxP2T+W1/8gflxB6DuhR9LpoLsU1EPlZ3Wyj+1+MuFovF4uonAAD//3weCWIACAAAAQAA//+Nc9ey/AAAAA==",
			"cosign.sigstore.dev/signature": "MEYCIQCTNFfObr0DiBCbDYEq0clxRw0FeoY35LhEiIFrGU7bZAIhAJR7AEYHIXkCPGlPIXA8ao0L99s3RWAjjzoxwcvOfmeT"
		},
		"name": "sample-cm",
		"namespace": "sample-ns"
	}
}`

var signed_adreq = `{
    "uid": "2529b894-5fca-4df9-a92b-7110f42bfa09",
    "kind": {
        "group": "",
        "version": "v1",
        "kind": "ConfigMap"
    },
    "resource": {
        "group": "",
        "version": "v1",
        "resource": "configmaps"
    },
    "requestKind": {
        "group": "",
        "version": "v1",
        "kind": "ConfigMap"
    },
    "requestResource": {
        "group": "",
        "version": "v1",
        "resource": "configmaps"
    },
    "name": "sample-cm",
    "namespace": "sample-ns",
    "operation": "CREATE",
    "userInfo": {
        "username": "kubernetes-admin",
        "groups": [
            "system:masters",
            "system:authenticated"
        ]
    },
    "object": {
        "apiVersion": "v1",
        "data": {
            "comment": "comment1",
            "key1": "val1",
            "key2": "val2"
        },
        "kind": "ConfigMap",
        "metadata": {
            "annotations": {
                "cosign.sigstore.dev/message": "H4sIAAAAAAAA/wD8AAP/H4sIAAAAAAAA/+zRu27DIBQGYGaeghdIOVzsNKydu1Vdq9MYW5Y54AKJmjx9leuYsVUlf8vPz2U4Qu4xyz6Fzuci41EqeJ7C19DpGj+BDNFHMGS/LQDAEOWb3Caasy9ljMOqYl4Nx2azMQBGyYI0B7/a0tMBKbC709vW2nOu2+acoC/9RDVrpqyGprXQasPAQKvWTAD7BbtSMTOAPO269OBeqdj3D86vs9zzn8B5fPe5jCk6sVd8GmPnxEuK/Ti84szJV+ywouNCRCTvxP2T+W1/8gflxB6DuhR9LpoLsU1EPlZ3Wyj+1+MuFovF4uonAAD//3weCWIACAAAAQAA//+Nc9ey/AAAAA==",
                "cosign.sigstore.dev/signature": "MEYCIQCTNFfObr0DiBCbDYEq0clxRw0FeoY35LhEiIFrGU7bZAIhAJR7AEYHIXkCPGlPIXA8ao0L99s3RWAjjzoxwcvOfmeT"
            },
            "creationTimestamp": "2022-03-04T07:43:10Z",
            "managedFields": [
                {
                    "apiVersion": "v1",
                    "fieldsType": "FieldsV1",
                    "fieldsV1": {
                        "f:data": {
                            ".": {},
                            "f:comment": {},
                            "f:key1": {},
                            "f:key2": {}
                        },
                        "f:metadata": {
                            "f:annotations": {
                                ".": {},
                                "f:integrityshield.io/message": {},
                                "f:integrityshield.io/signature": {}
                            }
                        }
                    },
                    "manager": "oc",
                    "operation": "Update",
                    "time": "2022-03-04T07:43:10Z"
                }
            ],
            "name": "sample-cm",
            "namespace": "sample-ns",
            "uid": "44725451-0fd5-47ec-98a1-f53f938e9b4d"
        }
    },
    "oldObject": null,
    "dryRun": false,
    "options": {
        "apiVersion": "meta.k8s.io/v1",
        "kind": "CreateOptions"
    }
}`

const ecdsaPub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyQfmL5YwHbn9xrrgG3vgbU0KJxMY
BibYLJ5L4VSMvGxeMLnBGdM48w5IE//6idUPj3rscigFdHs7GDMH4LLAng==
-----END PUBLIC KEY-----`

func Test_VerifyManifest(t *testing.T) {
	policyContext := buildContext(t, test_policy, signedResource)
	var diffVar *mapnode.DiffResult
	ignoreFields := k8smanifest.ObjectFieldBindingList{}
	skipUsers := shieldconfig.ObjectUserBindingList{}
	inScopeUsers := shieldconfig.ObjectUserBindingList{}
	subject := ""

	verified, diff, err := verifyManifest(policyContext, ecdsaPub, ignoreFields)
	assert.NilError(t, err)
	assert.Equal(t, verified, true)
	assert.Equal(t, msg, "Singed by a valid signer: ")
}

var unsignedResource = `{
	"apiVersion": "v1",
	"kind": "Pod",
	"metadata": {
		"name": "nginx"
	},
	"spec": {
		"containers": [
			{
				"image": "nginx:1.14.2",
				"name": "nginx"
			}
		]
	}
}`

func Test_VerifyManifest_no_signature(t *testing.T) {
	policyContext := buildContext(t, test_policy, unsignedResource)
	var diffVar *mapnode.DiffResult
	ignoreFields := k8smanifest.ObjectFieldBindingList{}

	verified, diff, err := verifyManifest(policyContext, "", ignoreFields)
	assert.ErrorContains(t, err, "")
	assert.Equal(t, verified, false)
	assert.Equal(t, diff, diffVar)
}
