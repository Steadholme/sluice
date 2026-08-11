package auth

import "context"

type mfaAssertionContextKey struct{}

type trustedMFAAssertion struct {
	value     MFAAssertion
	signature string
}

// ContextWithMFAAssertion stores a Sluice-minted assertion in a process-local,
// unforgeable context slot. Callers must only store values returned by
// SignMFAAssertion; browser-provided headers are never consulted.
func ContextWithMFAAssertion(ctx context.Context, value MFAAssertion, signature string) context.Context {
	return context.WithValue(ctx, mfaAssertionContextKey{}, trustedMFAAssertion{
		value:     value,
		signature: signature,
	})
}

// MFAAssertionFromContext returns the assertion minted for this exact request.
func MFAAssertionFromContext(ctx context.Context) (MFAAssertion, string, bool) {
	assertion, ok := ctx.Value(mfaAssertionContextKey{}).(trustedMFAAssertion)
	if !ok || assertion.signature == "" {
		return MFAAssertion{}, "", false
	}
	return assertion.value, assertion.signature, true
}

// HasStrongMFAAt reports only a canonical, subject-bound strong assertion that
// is still fresh at the caller's authorization clock. The PEP rechecks at its
// own linearization point so time spent in an earlier group lookup cannot carry
// an age=300 assertion across the 301-second boundary as mfa=true.
func HasStrongMFAAt(ctx context.Context, expectedSubject string, now int64) bool {
	assertion, _, ok := MFAAssertionFromContext(ctx)
	if !ok || expectedSubject == "" || assertion.Subject != expectedSubject ||
		assertion.AAL != MFAAALStrong || !assertion.UV || assertion.AuthTime <= 0 ||
		assertion.AuthTime > now || now-assertion.AuthTime > MFAAssertionFreshnessSeconds {
		return false
	}
	_, err := CanonicalMFAAssertion(assertion)
	return err == nil
}
