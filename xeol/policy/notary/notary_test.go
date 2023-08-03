package notary

// func TestEvaluate(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		policyWrapper  PolicyWrapper
// 		imageReference string
// 		want           types.PolicyEvaluationResult
// 		wantFailBuild  bool
// 	}{
// 		// {
// 		// 	name: "unsigned image, deny",
// 		// 	policyWrapper: PolicyWrapper{
// 		// 		PolicyType: types.PolicyTypeNotary,
// 		// 		Policies: []Policy{
// 		// 			{
// 		// 				WarnDate: "",
// 		// 				DenyDate: "2023-01-01",
// 		// 				Policy:   "eyJ2ZXJzaW9uIjogIjEuMCIsICJ0cnVzdFBvbGljaWVzIjogW3sibmFtZSI6ICJ3YWJiaXQtbmV0\nd29ya3MtaW1hZ2VzIiwgInRydXN0U3RvcmVzIjogWyJjYTp3YWJidC1uZXR3b3Jrcy5pbyJdLCAi\ncmVnaXN0cnlTY29wZXMiOiBbIioiXSwgInRydXN0ZWRJZGVudGl0aWVzIjogWyIqIl0sICJzaWdu\nYXR1cmVWZXJpZmljYXRpb24iOiB7ImxldmVsIjogInN0cmljdCJ9fV19",
// 		// 			},
// 		// 		},
// 		// 	},
// 		// 	imageReference: "ubuntu:16.04",
// 		// 	want: types.NotaryEvaluationResult{
// 		// 		Action:         types.PolicyActionDeny,
// 		// 		Type:           types.PolicyTypeNotary,
// 		// 		ImageReference: "ubuntu:16.04",
// 		// 		Verified:       false,
// 		// 	},
// 		// 	wantFailBuild: true,
// 		// },
// 		{
// 			name: "signed image, allow",
// 			policyWrapper: PolicyWrapper{
// 				PolicyType: types.PolicyTypeNotary,
// 				Policies: []Policy{
// 					{
// 						WarnDate: "",
// 						DenyDate: "2023-01-01",
// 						Policy:   "eyJ2ZXJzaW9uIjogIjEuMCIsICJ0cnVzdFBvbGljaWVzIjogW3sibmFtZSI6ICJ4ZW9sLXRlc3Qt\naW1hZ2VzIiwgInRydXN0U3RvcmVzIjogWyJjYTp4ZW9sLXRlc3QuaW8iXSwgInJlZ2lzdHJ5U2Nv\ncGVzIjogWyIqIl0sICJ0cnVzdGVkSWRlbnRpdGllcyI6IFsiKiJdLCAic2lnbmF0dXJlVmVyaWZp\nY2F0aW9uIjogeyJsZXZlbCI6ICJzdHJpY3QifX1dfQ==",
// 					},
// 				},
// 			},
// 			imageReference: "xeolio.azurecr.io/signed:v1",
// 			want: types.NotaryEvaluationResult{
// 				Action:         types.PolicyActionAllow,
// 				Type:           types.PolicyTypeNotary,
// 				ImageReference: "xeolio.azurecr.io/signed:v1",
// 				Verified:       false,
// 			},
// 			wantFailBuild: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, result := tt.policyWrapper.Evaluate(match.Matches{}, "", tt.imageReference)
// 			if got != tt.wantFailBuild {
// 				t.Errorf("Evaluate() got = %v, wantFailBuild %v", got, tt.wantFailBuild)
// 			}
// 			if !reflect.DeepEqual(result, tt.want) {
// 				t.Errorf("Evaluate() got1 = %v, want %v", result, tt.want)
// 			}
// 		})
// 	}
// }
