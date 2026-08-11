package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testStepUpRef = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type failingGetSessionStore struct {
	*MemoryStore
}

func (f *failingGetSessionStore) GetSession(context.Context, string) (Session, bool, error) {
	return Session{}, false, errors.New("test session authority failure")
}

func stepUpTestSession() Session {
	return Session{
		ID:        "gw-session-before-step-up",
		Sub:       testSub,
		Email:     testEmail,
		Scope:     requestedScope,
		CreatedAt: 1_754_400_000,
		ExpiresAt: 1_754_403_600,
		AAL:       SessionAALNone,
	}
}

func stepUpRequest(
	p *Provider,
	method string,
	body io.Reader,
	continuation StepUpContinuation,
) *http.Request {
	r := httptest.NewRequest(method, "https://"+continuation.Host+StepUpPath+"?ref="+testStepUpRef, body)
	r.Host = continuation.Host
	r = r.WithContext(ContextWithStepUpContinuation(r.Context(), continuation))
	r.AddCookie(&http.Cookie{Name: p.cfg.CookieName, Value: p.signer.sign(stepUpTestSession().ID)})
	return r
}

func hiddenStepUpValue(body, name string) string {
	marker := `name="` + name + `" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.IndexByte(body[start:], '"')
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}

func attributeValue(body, name string) string {
	marker := name + `="`
	start := strings.Index(body, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.IndexByte(body[start:], '"')
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}

func TestStepUpGETIsReadOnlyAndPOSTCreatesBoundStrongState(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	p.now = func() time.Time { return time.Unix(1_754_400_123, 0) }
	sessions := p.sessions.(*MemoryStore)
	states := p.states.(*MemoryStore)
	sessions.now = func() int64 { return p.now().Unix() }
	states.now = func() int64 { return p.now().Unix() }
	session := stepUpTestSession()
	if err := sessions.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	continuation := StepUpContinuation{
		Route:      "access-root",
		Host:       "access.example",
		PathPrefix: "/request/scope/step-up/",
	}

	get := stepUpRequest(p, http.MethodGet, nil, continuation)
	getRecorder := httptest.NewRecorder()
	p.ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", getRecorder.Code, getRecorder.Body.String())
	}
	states.mu.Lock()
	stateCount := len(states.states)
	states.mu.Unlock()
	if stateCount != 0 {
		t.Fatalf("GET created %d OAuth states", stateCount)
	}
	csrf := hiddenStepUpValue(getRecorder.Body.String(), "csrf_token")
	if csrf == "" {
		t.Fatal("GET did not render a session-bound CSRF token")
	}

	form := url.Values{"ref": {testStepUpRef}, "csrf_token": {csrf}}
	post := stepUpRequest(p, http.MethodPost, strings.NewReader(form.Encode()), continuation)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://"+continuation.Host)
	postRecorder := httptest.NewRecorder()
	p.ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusSeeOther {
		t.Fatalf("POST status = %d, body=%s", postRecorder.Code, postRecorder.Body.String())
	}
	authorizeURL, err := url.Parse(postRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if authorizeURL.Query().Get("acr_values") != stepUpRequiredACR {
		t.Fatalf("acr_values = %q", authorizeURL.Query().Get("acr_values"))
	}
	stateID := authorizeURL.Query().Get("state")
	stored, ok, err := states.TakeState(context.Background(), stateID)
	if err != nil || !ok {
		t.Fatalf("stored state = (%+v,%t,%v)", stored, ok, err)
	}
	if stored.Flow != OAuthFlowStepUp || stored.ExpectedSub != session.Sub ||
		stored.PreviousSessionID != session.ID || stored.StepUpRef != testStepUpRef ||
		stored.ContinuationRoute != continuation.Route || stored.ContinuationHost != continuation.Host ||
		stored.ContinuationPath != continuation.PathPrefix ||
		stored.OriginalURL != "https://access.example/request/scope/step-up/"+testStepUpRef {
		t.Fatalf("step-up state is not fully server bound: %+v", stored)
	}
}

func TestStepUpInterstitialIsTruthfulNoScriptSingleSubmit(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	p.now = func() time.Time { return time.Unix(1_754_400_123, 0) }
	sessions := p.sessions.(*MemoryStore)
	sessions.now = func() int64 { return p.now().Unix() }
	if err := sessions.CreateSession(context.Background(), stepUpTestSession()); err != nil {
		t.Fatal(err)
	}
	continuation := StepUpContinuation{
		Route:      "access-root",
		Host:       "access.example",
		PathPrefix: "/request/scope/step-up/",
	}
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, stepUpRequest(p, http.MethodGet, nil, continuation))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()

	// Truthful copy: the exact action is saved and has not executed.
	if !strings.Contains(body, "has not run") {
		t.Fatal("interstitial does not state that the saved action has not run")
	}
	// Exactly one explicit submit, and no auto-submit or JavaScript requirement.
	if got := strings.Count(body, "<form"); got != 1 {
		t.Fatalf("interstitial rendered %d forms, want 1", got)
	}
	if got := strings.Count(body, `type="submit"`); got != 1 {
		t.Fatalf("interstitial rendered %d submit controls, want 1", got)
	}
	if !strings.Contains(body, "Continue to verification") {
		t.Fatal("interstitial is missing the explicit continue control")
	}
	for _, forbidden := range []string{"<script", "onclick", "onload", "onsubmit", "setTimeout", ".submit()"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("interstitial must require no JavaScript or auto-submit, found %q", forbidden)
		}
	}
	// The bound hidden fields remain present for the CSRF-protected POST.
	if hiddenStepUpValue(body, "ref") == "" || hiddenStepUpValue(body, "csrf_token") == "" {
		t.Fatal("interstitial omitted a bound ref or CSRF field")
	}
	// Truthful non-execution invariant: clicking Continue immediately submits the interstitial POST
	// and persists OAuth state, so the copy must not claim "nothing is submitted"; it may promise
	// only that the saved action will not RUN without a successful verification.
	if !strings.Contains(body, "The saved action will not run unless you continue and successfully finish verification.") {
		t.Fatal("interstitial does not carry the exact truthful non-execution statement")
	}
	if strings.Contains(body, "nothing is submitted") {
		t.Fatal("interstitial must not claim nothing is submitted; the POST persists OAuth state")
	}
	// aria-labelledby must reference a heading id that actually exists in the document.
	labelledBy := attributeValue(body, "aria-labelledby")
	if labelledBy == "" || !strings.Contains(body, `id="`+labelledBy+`"`) {
		t.Fatalf("aria-labelledby=%q does not reference an existing heading id", labelledBy)
	}
	// The form action is exactly the fixed step-up path carrying the same opaque ref, the hidden
	// ref echoes that exact reference, and no browser-selected return target is present.
	wantAction := `action="` + StepUpPath + `?ref=` + testStepUpRef + `"`
	if !strings.Contains(body, wantAction) {
		t.Fatalf("interstitial form action is not exactly %q", wantAction)
	}
	if got := hiddenStepUpValue(body, "ref"); got != testStepUpRef {
		t.Fatalf("hidden ref = %q, want the same exact reference %q", got, testStepUpRef)
	}
	if strings.Contains(body, "return_to") {
		t.Fatal("interstitial must not contain any return_to field or parameter")
	}
}

func TestStepUpPOSTRejectsCrossSessionCSRFBeforeCreatingState(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	p.now = func() time.Time { return time.Unix(1_754_400_123, 0) }
	sessions := p.sessions.(*MemoryStore)
	states := p.states.(*MemoryStore)
	sessions.now = func() int64 { return p.now().Unix() }
	states.now = func() int64 { return p.now().Unix() }
	session := stepUpTestSession()
	if err := sessions.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	continuation := StepUpContinuation{Route: "access-root", Host: "access.example", PathPrefix: "/request/scope/step-up/"}
	csrf := p.mintStepUpCSRF(session, continuation, testStepUpRef, p.now().Unix()+60)

	other := session
	other.ID = "different-gateway-session"
	if err := sessions.CreateSession(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"ref": {testStepUpRef}, "csrf_token": {csrf}}
	post := stepUpRequest(p, http.MethodPost, strings.NewReader(form.Encode()), continuation)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://"+continuation.Host)
	post.Header.Set("Cookie", p.cfg.CookieName+"="+p.signer.sign(other.ID))
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, post)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	states.mu.Lock()
	defer states.mu.Unlock()
	if len(states.states) != 0 {
		t.Fatal("invalid CSRF created an OAuth state")
	}
}

func TestStepUpCSRFBindsSessionRouteHostPathRefAndExpiry(t *testing.T) {
	p := &Provider{
		signer: signer{key: []byte("step-up-csrf-test-secret")},
		now:    func() time.Time { return time.Unix(1_754_400_000, 0) },
	}
	session := stepUpTestSession()
	continuation := StepUpContinuation{
		Route: "access-root", Host: "access.example", PathPrefix: "/request/scope/step-up/",
	}
	expiresAt := p.now().Unix() + 60
	token := p.mintStepUpCSRF(session, continuation, testStepUpRef, expiresAt)
	if !p.verifyStepUpCSRF(session, continuation, testStepUpRef, token) {
		t.Fatal("valid step-up CSRF token was rejected")
	}

	otherSession := session
	otherSession.ID = "different-session"
	otherRoute := continuation
	otherRoute.Route = "different-route"
	otherHost := continuation
	otherHost.Host = "other.example"
	otherPath := continuation
	otherPath.PathPrefix = "/different/"
	otherRef := strings.Repeat("f", 64)
	for name, verify := range map[string]func() bool{
		"session": func() bool { return p.verifyStepUpCSRF(otherSession, continuation, testStepUpRef, token) },
		"route":   func() bool { return p.verifyStepUpCSRF(session, otherRoute, testStepUpRef, token) },
		"host":    func() bool { return p.verifyStepUpCSRF(session, otherHost, testStepUpRef, token) },
		"path":    func() bool { return p.verifyStepUpCSRF(session, otherPath, testStepUpRef, token) },
		"ref":     func() bool { return p.verifyStepUpCSRF(session, continuation, otherRef, token) },
	} {
		t.Run(name, func(t *testing.T) {
			if verify() {
				t.Fatal("cross-context CSRF token was accepted")
			}
		})
	}
	expired := p.mintStepUpCSRF(session, continuation, testStepUpRef, p.now().Unix()-1)
	if p.verifyStepUpCSRF(session, continuation, testStepUpRef, expired) {
		t.Fatal("expired step-up CSRF token was accepted")
	}
	beyondMaximum := p.mintStepUpCSRF(
		session,
		continuation,
		testStepUpRef,
		p.now().Unix()+stepUpCSRFTTLSeconds+1,
	)
	if p.verifyStepUpCSRF(session, continuation, testStepUpRef, beyondMaximum) {
		t.Fatal("overlong step-up CSRF token was accepted")
	}
}

func TestStepUpRejectsBrowserControlledContinuationParameters(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	now := time.Now().Unix()
	session := stepUpTestSession()
	session.CreatedAt = now - 60
	session.ExpiresAt = now + 3600
	if err := p.sessions.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	continuation := StepUpContinuation{
		Route: "access-root", Host: "access.example", PathPrefix: "/request/scope/step-up/",
	}
	for _, extra := range []string{
		"&return_to=https%3A%2F%2Fevil.example%2F",
		"&host=evil.example",
		"&action=approve",
		"&ref=" + testStepUpRef,
	} {
		request := stepUpRequest(p, http.MethodGet, nil, continuation)
		request.URL.RawQuery += extra
		recorder := httptest.NewRecorder()
		p.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("query suffix %q status = %d, want 400", extra, recorder.Code)
		}
	}
}

func TestMemoryReplaceSessionIsAtomicAndSubjectBound(t *testing.T) {
	store := NewMemoryStore()
	store.now = func() int64 { return 100 }
	old := Session{
		ID: "old", Sub: "alice", CreatedAt: 1, ExpiresAt: 200,
		SessionBinding: strings.Repeat("b", 64), AAL: SessionMFAStrong,
		UV: true, AuthTime: 1, FactorEpoch: 1,
	}
	if err := store.CreateSession(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	foreign := Session{ID: "foreign", Sub: "mallory", CreatedAt: 100, ExpiresAt: 200, AAL: SessionAALNone}
	if err := store.ReplaceSession(context.Background(), old.ID, old.SessionBinding, foreign); err != ErrSessionReplacementConflict {
		t.Fatalf("foreign replacement error = %v", err)
	}
	if _, ok, _ := store.GetSession(context.Background(), old.ID); !ok {
		t.Fatal("failed replacement removed the old session")
	}
	if err := store.ReplaceSession(context.Background(), old.ID, strings.Repeat("c", 64), foreign); err != ErrSessionReplacementConflict {
		t.Fatalf("binding mismatch error = %v", err)
	}
	colliding := Session{ID: "already-live", Sub: "alice", CreatedAt: 1, ExpiresAt: 200, AAL: SessionAALNone}
	if err := store.CreateSession(context.Background(), colliding); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSession(context.Background(), old.ID, old.SessionBinding, colliding); err != ErrSessionReplacementConflict {
		t.Fatalf("successor collision error = %v", err)
	}
	if _, ok, _ := store.GetSession(context.Background(), old.ID); !ok {
		t.Fatal("successor collision removed the old session")
	}
	strong := Session{
		ID: "new", Sub: "alice", CreatedAt: 100, ExpiresAt: 200,
		SessionBinding: strings.Repeat("a", 64), AAL: SessionMFAStrong,
		UV: true, AuthTime: 100, FactorEpoch: 7,
	}
	if err := store.ReplaceSession(context.Background(), old.ID, old.SessionBinding, strong); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.GetSession(context.Background(), old.ID); ok {
		t.Fatal("successful replacement retained old session")
	}
	if got, ok, _ := store.GetSession(context.Background(), strong.ID); !ok || got.AAL != SessionMFAStrong {
		t.Fatalf("replacement session = (%+v,%t)", got, ok)
	}
}

func TestMemoryReplaceSessionRechecksFreshnessInsideAtomicBoundary(t *testing.T) {
	store := NewMemoryStore()
	decisionNow := int64(1_754_400_301)
	store.now = func() int64 { return decisionNow }
	source := Session{
		ID: "freshness-source", Sub: "alice", CreatedAt: decisionNow - 60,
		ExpiresAt: decisionNow + 600, AAL: SessionAALNone,
	}
	if err := store.CreateSession(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	replacement := Session{
		ID: "freshness-successor", Sub: source.Sub, CreatedAt: decisionNow - 301,
		ExpiresAt: source.ExpiresAt, SessionBinding: strings.Repeat("a", 64),
		AAL: SessionMFAStrong, UV: true, AuthTime: decisionNow - 301, FactorEpoch: 7,
	}
	if err := store.ReplaceSession(context.Background(), source.ID, "", replacement); !errors.Is(err, ErrSessionReplacementAssurance) {
		t.Fatalf("stale replacement error = %v", err)
	}
	if _, ok, _ := store.GetSession(context.Background(), source.ID); !ok {
		t.Fatal("stale replacement removed the source session")
	}
	replacement.CreatedAt = decisionNow - 300
	replacement.AuthTime = decisionNow - 300
	if err := store.ReplaceSession(context.Background(), source.ID, "", replacement); err != nil {
		t.Fatalf("300-second boundary replacement error = %v", err)
	}
}

func TestMemoryConcurrentStepUpReplacementHasOneWinner(t *testing.T) {
	store := NewMemoryStore()
	store.now = func() int64 { return 100 }
	source := Session{ID: "source", Sub: "alice", CreatedAt: 1, ExpiresAt: 200, AAL: SessionAALNone}
	if err := store.CreateSession(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{"strong-a", "strong-b"} {
		id := id
		go func() {
			<-start
			results <- store.ReplaceSession(context.Background(), source.ID, "", Session{
				ID: id, Sub: source.Sub, CreatedAt: 100, ExpiresAt: 200,
				SessionBinding: strings.Repeat("a", 64), AAL: SessionMFAStrong,
				UV: true, AuthTime: 100, FactorEpoch: 7,
			})
		}()
	}
	close(start)
	var succeeded, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrSessionReplacementConflict):
			conflicted++
		default:
			t.Fatalf("unexpected replacement error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("replacement results: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	if _, ok, _ := store.GetSession(context.Background(), source.ID); ok {
		t.Fatal("concurrent replacement retained source")
	}
}

func TestFreshStrongAssuranceBoundary(t *testing.T) {
	now := int64(1_754_400_300)
	base := idTokenAssurance{
		SessionBinding: strings.Repeat("a", 64),
		AAL:            SessionMFAStrong,
		UV:             true,
		FactorEpoch:    7,
	}
	for _, test := range []struct {
		name     string
		authTime int64
		want     bool
	}{
		{name: "exactly 300 seconds", authTime: now - 300, want: true},
		{name: "301 seconds", authTime: now - 301, want: false},
		{name: "future", authTime: now + 1, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assurance := base
			assurance.AuthTime = test.authTime
			if got := freshStrongAssurance(assurance, now); got != test.want {
				t.Fatalf("freshStrongAssurance = %t, want %t", got, test.want)
			}
		})
	}
}

func TestStepUpFullFlowAtomicallyReplacesWeakSession(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	var continuation StepUpContinuation
	echo := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := GatewaySessionFromContext(r.Context())
		if !ok {
			http.Error(w, "missing gateway session", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"path": r.URL.Path,
			"aal":  session.AAL,
			"sub":  session.Sub,
		})
	}))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == StepUpPath {
			r = r.WithContext(ContextWithStepUpContinuation(r.Context(), continuation))
			p.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, GatewayPrefix) {
			p.ServeHTTP(w, r)
			return
		}
		echo.ServeHTTP(w, r)
	})
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	p.cfg.RedirectURI = srv.URL + CallbackPath
	gatewayURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	continuation = StepUpContinuation{
		Route:      "access-root",
		Host:       gatewayURL.Host,
		PathPrefix: "/request/scope/step-up/",
	}

	now := time.Now().Unix()
	old := Session{
		ID: "weak-before-step-up", Sub: testSub, Email: testEmail, Scope: requestedScope,
		CreatedAt: now - 60, ExpiresAt: now + 3600, AAL: SessionAALNone,
	}
	store := p.sessions.(*MemoryStore)
	if err := store.CreateSession(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	client := jarClient(t, srv)
	client.Jar.SetCookies(gatewayURL, []*http.Cookie{{
		Name: p.cfg.CookieName, Value: p.signer.sign(old.ID), Path: "/", Secure: true,
	}})

	getResponse, err := client.Get(srv.URL + StepUpPath + "?ref=" + testStepUpRef)
	if err != nil {
		t.Fatal(err)
	}
	getBody, err := io.ReadAll(getResponse.Body)
	getResponse.Body.Close()
	if err != nil || getResponse.StatusCode != http.StatusOK {
		t.Fatalf("step-up GET = %d, err=%v", getResponse.StatusCode, err)
	}
	csrf := hiddenStepUpValue(string(getBody), "csrf_token")
	if csrf == "" {
		t.Fatal("step-up GET omitted CSRF token")
	}

	form := url.Values{"ref": {testStepUpRef}, "csrf_token": {csrf}}
	request, err := http.NewRequest(
		http.MethodPost,
		srv.URL+StepUpPath+"?ref="+testStepUpRef,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", srv.URL)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	postResponse, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	postResponse.Body.Close()
	if postResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("step-up POST status = %d", postResponse.StatusCode)
	}
	authorizeLocation := postResponse.Header.Get("Location")
	authorizeURL, err := url.Parse(authorizeLocation)
	if err != nil || authorizeURL.Query().Get("acr_values") != stepUpRequiredACR {
		t.Fatalf("authorize Location = %q, err=%v", authorizeLocation, err)
	}

	client.CheckRedirect = nil
	finalResponse, err := client.Get(authorizeLocation)
	if err != nil {
		t.Fatal(err)
	}
	defer finalResponse.Body.Close()
	if finalResponse.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d", finalResponse.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(finalResponse.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["path"] != continuation.PathPrefix+testStepUpRef ||
		result["aal"] != SessionMFAStrong || result["sub"] != testSub {
		t.Fatalf("final continuation = %#v", result)
	}
	if _, ok, _ := store.GetSession(context.Background(), old.ID); ok {
		t.Fatal("successful step-up retained the weak gateway session")
	}
	var replacement Session
	for _, cookie := range client.Jar.Cookies(gatewayURL) {
		if cookie.Name != p.cfg.CookieName {
			continue
		}
		id, ok := p.signer.verify(cookie.Value)
		if !ok {
			t.Fatal("replacement cookie signature is invalid")
		}
		replacement, ok, err = store.GetSession(context.Background(), id)
		if err != nil || !ok {
			t.Fatalf("replacement session = (%+v,%t,%v)", replacement, ok, err)
		}
	}
	if replacement.AAL != SessionMFAStrong || !replacement.UV ||
		replacement.SessionBinding != strings.Repeat("a", 64) {
		t.Fatalf("replacement assurance = %+v", replacement)
	}
}

func seedStepUpCallback(
	t *testing.T,
	p *Provider,
	fi *fakeIssuer,
	code string,
) (OAuthState, Session) {
	t.Helper()
	now := time.Now().Unix()
	old := Session{
		ID: "callback-source-session", Sub: testSub, Email: testEmail, Scope: requestedScope,
		CreatedAt: now - 60, ExpiresAt: now + 3600, AAL: SessionAALNone,
	}
	if err := p.sessions.CreateSession(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	state := OAuthState{
		State:             "callback-step-up-state",
		Nonce:             "callback-step-up-nonce",
		CodeVerifier:      "callback-step-up-verifier",
		ExpiresAt:         now + 300,
		Flow:              OAuthFlowStepUp,
		ExpectedSub:       testSub,
		PreviousSessionID: old.ID,
		StepUpRef:         testStepUpRef,
		ContinuationRoute: "access-root",
		ContinuationHost:  "access.example",
		ContinuationPath:  "/request/scope/step-up/",
	}
	state.OriginalURL = stepUpReturnURL(StepUpContinuation{
		Route: state.ContinuationRoute, Host: state.ContinuationHost, PathPrefix: state.ContinuationPath,
	}, state.StepUpRef)
	if err := p.states.PutState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	fi.mu.Lock()
	fi.codes[code] = codeRec{
		challenge: pkceChallengeS256(state.CodeVerifier), nonce: state.Nonce,
		redirectURI: p.cfg.RedirectURI, clientID: testClientID, scope: requestedScope,
		acr: stepUpRequiredACR,
	}
	fi.mu.Unlock()
	return state, old
}

func stepUpCallbackRequest(p *Provider, state OAuthState, old Session, code string) *http.Request {
	request := httptest.NewRequest(
		http.MethodGet,
		"https://id.example"+CallbackPath+"?state="+url.QueryEscape(state.State)+"&code="+url.QueryEscape(code),
		nil,
	)
	request.AddCookie(&http.Cookie{Name: p.cfg.CookieName, Value: p.signer.sign(old.ID)})
	return request
}

func TestStepUpCallbackRejectsDowngradeStaleFutureAndSubjectMismatch(t *testing.T) {
	for _, mode := range []string{"weak", "stale", "future", "wrong-sub"} {
		t.Run(mode, func(t *testing.T) {
			fi := newFakeIssuer(t)
			fi.stepUpMode = mode
			p := newTestProvider(t, fi)
			state, old := seedStepUpCallback(t, p, fi, "code-"+mode)
			recorder := httptest.NewRecorder()
			p.ServeHTTP(recorder, stepUpCallbackRequest(p, state, old, "code-"+mode))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("callback status = %d, body=%s", recorder.Code, recorder.Body.String())
			}
			if _, ok, err := p.sessions.GetSession(context.Background(), old.ID); err != nil || !ok {
				t.Fatalf("rejected callback changed old session: ok=%t err=%v", ok, err)
			}
			if _, ok, err := p.states.TakeState(context.Background(), state.State); err != nil || ok {
				t.Fatalf("rejected callback state replay = ok=%t err=%v", ok, err)
			}
		})
	}
}

func TestStepUpOAuthErrorConsumesStateAndKeepsOldSession(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	state, old := seedStepUpCallback(t, p, fi, "unused-code")
	request := httptest.NewRequest(
		http.MethodGet,
		"https://id.example"+CallbackPath+"?state="+url.QueryEscape(state.State)+"&error=access_denied",
		nil,
	)
	request.AddCookie(&http.Cookie{Name: p.cfg.CookieName, Value: p.signer.sign(old.ID)})
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != state.OriginalURL {
		t.Fatalf("OAuth error response = %d Location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
	if _, ok, err := p.sessions.GetSession(context.Background(), old.ID); err != nil || !ok {
		t.Fatalf("OAuth error changed old session: ok=%t err=%v", ok, err)
	}

	replay := httptest.NewRecorder()
	p.ServeHTTP(replay, request.Clone(request.Context()))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("OAuth error replay status = %d, want 400", replay.Code)
	}
}

func TestStepUpCallbackSessionAuthorityFailureIs503(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	state, old := seedStepUpCallback(t, p, fi, "authority-failure-code")
	p.sessions = &failingGetSessionStore{MemoryStore: p.sessions.(*MemoryStore)}
	recorder := httptest.NewRecorder()
	p.ServeHTTP(
		recorder,
		stepUpCallbackRequest(p, state, old, "authority-failure-code"),
	)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf(
			"session authority failure = %d Retry-After=%q",
			recorder.Code,
			recorder.Header().Get("Retry-After"),
		)
	}
}
