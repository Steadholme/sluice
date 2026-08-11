package oidc

import "testing"

func TestAssuranceFromIDTokenClaimsExactShapes(t *testing.T) {
	legacy, err := assuranceFromIDTokenClaims(&idTokenClaims{})
	if err != nil || legacy.AAL != SessionAALNone || legacy.SessionBinding != "" {
		t.Fatalf("legacy normalization failed: value=%+v err=%v", legacy, err)
	}

	zero := int64(0)
	noneACR := "hf-aal-none"
	emptyAMR := []string{}
	none, err := assuranceFromIDTokenClaims(&idTokenClaims{
		AuthTime: &zero,
		ACR:      &noneACR,
		AMR:      &emptyAMR,
		MFA:      &idTokenMFAClaims{AAL: SessionAALNone},
	})
	if err != nil || none.AAL != SessionAALNone || none.AuthTime != 0 || none.FactorEpoch != 0 {
		t.Fatalf("bound AAL_NONE normalization failed: value=%+v err=%v", none, err)
	}

	strongTime := int64(1_754_400_000)
	strongACR := "hf-aal-strong"
	strongAMR := []string{"pwd", "otp"}
	strong, err := assuranceFromIDTokenClaims(&idTokenClaims{
		AuthTime: &strongTime,
		ACR:      &strongACR,
		AMR:      &strongAMR,
		MFA: &idTokenMFAClaims{
			AAL: SessionMFAStrong,
			UV:  true,
			SB:  "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f",
			FE:  7,
		},
	})
	if err != nil || strong.AAL != SessionMFAStrong || !strong.UV || strong.FactorEpoch != 7 ||
		strong.AuthTime != strongTime {
		t.Fatalf("strong assurance parse failed: value=%+v err=%v", strong, err)
	}
}

func TestAssuranceFromIDTokenClaimsRejectsPartialAndMalformedShapes(t *testing.T) {
	zero := int64(0)
	strongTime := int64(1_754_400_000)
	noneACR := "hf-aal-none"
	strongACR := "hf-aal-strong"
	emptyAMR := []string{}
	badAMR := []string{"otp", "pwd"}
	tests := map[string]*idTokenClaims{
		"partial": {
			AuthTime: &zero,
		},
		"none with binding": {
			AuthTime: &zero,
			ACR:      &noneACR,
			AMR:      &emptyAMR,
			MFA: &idTokenMFAClaims{
				AAL: SessionAALNone,
				SB:  "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f",
			},
		},
		"strong bad amr order": {
			AuthTime: &strongTime,
			ACR:      &strongACR,
			AMR:      &badAMR,
			MFA: &idTokenMFAClaims{
				AAL: SessionMFAStrong,
				UV:  true,
				SB:  "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f",
			},
		},
		"strong uppercase binding": {
			AuthTime: &strongTime,
			ACR:      &strongACR,
			AMR:      &[]string{"hwk", "user"},
			MFA: &idTokenMFAClaims{
				AAL: SessionMFAStrong,
				UV:  true,
				SB:  "1E0007C3BBA79F5C4F0C6F61E4081ED08ED2E1698268A86EAF96EBE903DD4B7F",
			},
		},
		"strong negative epoch": {
			AuthTime: &strongTime,
			ACR:      &strongACR,
			AMR:      &[]string{"pwd", "otp"},
			MFA: &idTokenMFAClaims{
				AAL: SessionMFAStrong,
				UV:  true,
				SB:  "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f",
				FE:  -1,
			},
		},
	}
	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := assuranceFromIDTokenClaims(claims); err == nil {
				t.Fatal("expected assurance shape rejection")
			}
		})
	}
}
