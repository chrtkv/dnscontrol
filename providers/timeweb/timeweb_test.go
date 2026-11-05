package timeweb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dnsv2 "codeberg.org/miekg/dns"
	"github.com/DNSControl/dnscontrol/v5/models"
	"golang.org/x/net/idna"
)

const testDomain = "example.ru"

// fakeRecord is a record in fakeTimeweb, with the name Timeweb lists it under.
type fakeRecord struct {
	rec      twRecord
	listFQDN string
}

// fakeTimeweb imitates the parts of Timeweb's DNS API this provider uses, including the behaviour observed on
// 2026-11-05 that the provider has to work around: non-TXT records on a subdomain are listed under the subdomain's
// fqdn only, TXT records always under the domain; a subdomain written to without an object is listed nowhere; a new
// subdomain object gets Timeweb's SPF record; the v2 PATCH refuses "subdomain" and moves a TXT record to the apex.
type fakeTimeweb struct {
	t        *testing.T
	mu       sync.Mutex
	nextID   int64
	records  []*fakeRecord
	explicit map[string]bool // subdomain objects
	implicit map[string]bool // subdomains created by writing a record on them
	calls    []string
}

func newFake(t *testing.T) (*fakeTimeweb, *timewebProvider) {
	f := &fakeTimeweb{t: t, nextID: 100, explicit: map[string]bool{}, implicit: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := newClient("test-token")
	c.baseURL = srv.URL + "/api"
	c.sleep = func(time.Duration) {}
	return f, &timewebProvider{api: c}
}

func (f *fakeTimeweb) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"status_code":%d,"error_code":%q,"message":%q}`, status, code, code)
}

func (f *fakeTimeweb) add(rec twRecord, listFQDN string) twRecord {
	f.nextID++
	rec.ID = f.nextID
	f.records = append(f.records, &fakeRecord{rec: rec, listFQDN: listFQDN})
	return rec
}

func (f *fakeTimeweb) find(id int64) *fakeRecord {
	for _, r := range f.records {
		if r.rec.ID == id {
			return r
		}
	}
	return nil
}

func (f *fakeTimeweb) remove(keep func(*fakeRecord) bool) {
	f.records = slices.DeleteFunc(f.records, func(r *fakeRecord) bool { return !keep(r) })
}

func (f *fakeTimeweb) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		f.fail(w, 401, "unauthorized")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api")
	f.calls = append(f.calls, r.Method+" "+path)
	for _, c := range path {
		if c > 127 {
			f.fail(w, 403, "forbidden") // what Timeweb answers to a Unicode name in the path
			return
		}
	}
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			f.t.Fatalf("bad JSON body for %s %s: %v", r.Method, path, err)
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	// parts: [v1|v2, domains, fqdn, ...]
	if len(parts) < 3 || parts[1] != "domains" {
		f.fail(w, 404, "not_found")
		return
	}
	// Timeweb keeps internationalized names in Unicode; requests name them in punycode.
	ver, fqdn, rest := parts[0], unicode(parts[2]), parts[3:]
	if len(rest) == 2 && rest[0] == "subdomains" {
		rest[1] = unicode(rest[1])
	}
	sub, isSub := strings.CutSuffix(fqdn, "."+testDomain)
	if fqdn != testDomain && !isSub {
		f.fail(w, 404, "domain_not_found")
		return
	}

	switch {
	case r.Method == "GET" && len(rest) == 0 && fqdn == testDomain:
		var subs []twSubdomain
		for l := range f.explicit {
			subs = append(subs, twSubdomain{FQDN: l + "." + testDomain})
		}
		json.NewEncoder(w).Encode(map[string]any{"domain": twDomain{FQDN: testDomain, Subdomains: subs}})

	case r.Method == "GET" && len(rest) == 1 && rest[0] == "dns-records":
		if isSub && !f.explicit[sub] && !f.implicit[sub] {
			f.fail(w, 404, "not_found")
			return
		}
		var out []twRecord
		for _, fr := range f.records {
			if fr.listFQDN == fqdn {
				out = append(out, fr.rec)
			}
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		end := min(offset+limit, len(out))
		if offset > len(out) {
			offset = end
		}
		json.NewEncoder(w).Encode(map[string]any{"dns_records": out[offset:end], "meta": map[string]int{"total": len(out)}})

	case r.Method == "POST" && len(rest) == 1 && rest[0] == "dns-records" && fqdn == testDomain:
		rec := twRecord{Type: req["type"].(string), TTL: 600}
		if v, ok := req["ttl"].(float64); ok {
			rec.TTL = int64(v)
		}
		if v, ok := req["value"].(string); ok {
			rec.Data.Value = v
		}
		if v, ok := req["priority"].(float64); ok {
			p := int64(v)
			rec.Data.Priority = &p
		}
		if v, ok := req["port"].(float64); ok {
			p := int64(v)
			rec.Data.Port = &p
		}
		if v, ok := req["service"].(string); ok {
			rec.Data.Service = v
		}
		if v, ok := req["protocol"].(string); ok {
			rec.Data.Protocol = strings.ToUpper(v)
		}
		if v, ok := req["host"].(string); ok {
			rec.Data.Host = v
		}
		label, hasSub := req["subdomain"].(string)
		switch {
		case ver == "v2" && hasSub:
			f.fail(w, 400, "bad_request")
		case ver == "v2":
			f.add(rec, testDomain)
			w.WriteHeader(201)
		case !hasSub:
			f.fail(w, 400, "bad_subdomain_name")
		case rec.Type == "TXT":
			rec.Data.Subdomain = new(label)
			f.add(rec, testDomain)
			f.implicitIfNew(label)
			w.WriteHeader(201)
		default:
			f.add(rec, label+"."+testDomain)
			f.implicitIfNew(label)
			w.WriteHeader(201)
		}

	case r.Method == "PATCH" && len(rest) == 2 && rest[0] == "dns-records":
		id, _ := strconv.ParseInt(rest[1], 10, 64)
		fr := f.find(id)
		if fr == nil || fr.listFQDN != fqdn {
			f.fail(w, 404, "dns_record_not_found")
			return
		}
		label, hasSub := req["subdomain"].(string)
		if ver == "v2" && hasSub {
			f.fail(w, 400, "bad_request")
			return
		}
		if v, ok := req["value"].(string); ok {
			fr.rec.Data.Value = v
		}
		if v, ok := req["ttl"].(float64); ok {
			fr.rec.TTL = int64(v)
		}
		if v, ok := req["priority"].(float64); ok {
			p := int64(v)
			fr.rec.Data.Priority = &p
		}
		if v, ok := req["port"].(float64); ok {
			p := int64(v)
			fr.rec.Data.Port = &p
		}
		if v, ok := req["host"].(string); ok {
			fr.rec.Data.Host = v
		}
		if v, ok := req["service"].(string); ok {
			fr.rec.Data.Service = v
		}
		if v, ok := req["protocol"].(string); ok {
			fr.rec.Data.Protocol = strings.ToUpper(v)
		}
		if fr.rec.Type == "TXT" {
			// What Timeweb does: the subdomain becomes whatever the body says, the apex when it says nothing.
			fr.rec.Data.Subdomain = nil
			if hasSub {
				fr.rec.Data.Subdomain = new(label)
			}
		}

	case r.Method == "DELETE" && len(rest) == 2 && rest[0] == "dns-records":
		id, _ := strconv.ParseInt(rest[1], 10, 64)
		fr := f.find(id)
		if fr == nil || fr.listFQDN != fqdn {
			f.fail(w, 404, "not_found")
			return
		}
		f.remove(func(x *fakeRecord) bool { return x != fr })
		w.WriteHeader(204)

	case r.Method == "POST" && len(rest) == 2 && rest[0] == "subdomains" && fqdn == testDomain:
		label := rest[1]
		if f.explicit[label] || f.implicit[label] || label == "www" {
			f.fail(w, 409, "entity_already_exists")
			return
		}
		f.explicit[label] = true
		f.add(twRecord{Type: "TXT", TTL: 600, Data: twData{Subdomain: new(label), Value: timewebDefaultSPF}}, testDomain)
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"subdomain":{"fqdn":"%s.%s"}}`, label, testDomain)

	case r.Method == "DELETE" && len(rest) == 2 && rest[0] == "subdomains" && fqdn == testDomain:
		label := rest[1]
		if !f.explicit[label] {
			f.fail(w, 404, "not_found")
			return
		}
		delete(f.explicit, label)
		f.remove(func(x *fakeRecord) bool {
			onSub := x.rec.Data.Subdomain != nil && *x.rec.Data.Subdomain == label
			return x.listFQDN != label+"."+testDomain && !onSub
		})
		w.WriteHeader(204)

	case r.Method == "DELETE" && len(rest) == 0:
		f.t.Errorf("DELETE /domains/%s deletes the whole domain on Timeweb; the provider must never call it", fqdn)
		w.WriteHeader(204)

	default:
		f.fail(w, 404, "not_found")
	}
}

func unicode(name string) string {
	u, err := idna.ToUnicode(name)
	if err != nil {
		return name
	}
	return u
}

func (f *fakeTimeweb) implicitIfNew(label string) {
	if !f.explicit[label] {
		f.implicit[label] = true
	}
}

func newDC(t *testing.T) *models.DomainConfig {
	t.Helper()
	dc, err := models.NewDomainConfig(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	return dc
}

func parse(t *testing.T, dc *models.DomainConfig, label string, ttl uint32, typ, data string) *models.RecordConfig {
	t.Helper()
	rc, err := dc.NewRecordConfigParse(label, ttl, typ, data)
	if err != nil {
		t.Fatalf("%s %s %q: %v", label, typ, data, err)
	}
	return rc
}

func txt(t *testing.T, dc *models.DomainConfig, label string, ttl uint32, value string) *models.RecordConfig {
	t.Helper()
	rc, err := dc.NewRecordConfig(label, ttl, dnsv2.TypeTXT, value)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

// push runs one preview and push of desired against the provider and returns how many changes it made.
func push(t *testing.T, p *timewebProvider, desired func(dc *models.DomainConfig) models.Records) int {
	t.Helper()
	dc := newDC(t)
	dc.Records = desired(dc)
	if errs := p.AuditRecords(dc.Records); len(errs) > 0 {
		t.Fatalf("audit: %v", errs)
	}
	existing, err := p.GetZoneRecords(dc)
	if err != nil {
		t.Fatalf("GetZoneRecords: %v", err)
	}
	corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatalf("GetZoneRecordsCorrections: %v", err)
	}
	for _, c := range corrections {
		if c.F == nil {
			continue
		}
		if err := c.F(); err != nil {
			t.Fatalf("%s: %v", c.Msg, err)
		}
	}
	return count
}

// zone returns the fake's records as "label TYPE value ttl" lines, sorted, for comparison.
func (f *fakeTimeweb) zone() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var lines []string
	for _, fr := range f.records {
		label := "@"
		if s, ok := strings.CutSuffix(fr.listFQDN, "."+testDomain); ok {
			label = s
		}
		if fr.rec.Data.Subdomain != nil {
			label = *fr.rec.Data.Subdomain
		}
		v := fr.rec.Data.Value
		switch fr.rec.Type {
		case "MX":
			v = fmt.Sprintf("%d %s", *fr.rec.Data.Priority, v)
		case "SRV":
			v = fmt.Sprintf("%s.%s %d %d %s", fr.rec.Data.Service, fr.rec.Data.Protocol, *fr.rec.Data.Priority, *fr.rec.Data.Port, fr.rec.Data.Host)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %d", label, fr.rec.Type, v, fr.rec.TTL))
	}
	slices.Sort(lines)
	return lines
}

func fullZone(t *testing.T) func(dc *models.DomainConfig) models.Records {
	return func(dc *models.DomainConfig) models.Records {
		return models.Records{
			parse(t, dc, "@", 300, "A", "192.0.2.1"),
			parse(t, dc, "www", 300, "A", "192.0.2.1"),
			parse(t, dc, "@", 600, "MX", "10 mx.example.net."),
			txt(t, dc, "@", 600, "v=spf1 -all"),
			txt(t, dc, "_dmarc", 600, "v=DMARC1; p=reject"),
			txt(t, dc, "app", 600, "app-verification"),
			parse(t, dc, "app", 300, "A", "192.0.2.2"),
			parse(t, dc, "x.y", 600, "CNAME", "target.example.net."),
			parse(t, dc, "_sip._tcp", 600, "SRV", "10 0 5060 sip.example.net."),
			parse(t, dc, "_sip._udp.app", 600, "SRV", "20 0 5060 sip.example.net."),
		}
	}
}

func TestPushCreatesFindableZoneAndIsIdempotent(t *testing.T) {
	f, p := newFake(t)
	if n := push(t, p, fullZone(t)); n == 0 {
		t.Fatal("first push made no changes")
	}
	want := []string{
		"@ A 192.0.2.1 300",
		"@ MX 10 mx.example.net 600",
		"@ SRV _sip._TCP 10 5060 sip.example.net 600",
		"@ TXT v=spf1 -all 600",
		"_dmarc TXT v=DMARC1; p=reject 600",
		"app A 192.0.2.2 300",
		"app SRV _sip._UDP 20 5060 sip.example.net 600",
		"app TXT app-verification 600",
		"www A 192.0.2.1 300",
		"x.y CNAME target.example.net 600",
	}
	if got := f.zone(); !slices.Equal(got, want) {
		t.Fatalf("zone after push:\n got %q\nwant %q", got, want)
	}
	// Every subdomain that can be an object is one, so it stays findable after it leaves dnsconfig.js.
	if !f.explicit["app"] || !f.explicit["x.y"] || len(f.explicit) != 2 {
		t.Errorf("subdomain objects = %v, want app and x.y", f.explicit)
	}
	if n := push(t, p, fullZone(t)); n != 0 {
		t.Errorf("second push of the same zone made %d changes, want 0", n)
	}
}

func TestChangeKeepsSubdomainTXTOnItsSubdomain(t *testing.T) {
	f, p := newFake(t)
	push(t, p, fullZone(t))
	n := push(t, p, func(dc *models.DomainConfig) models.Records {
		rs := fullZone(t)(dc)
		for i, rc := range rs {
			if rc.Type == "TXT" && rc.GetLabel() == "app" {
				rs[i] = txt(t, dc, "app", 900, "app-verification-2")
			}
			if rc.Type == "A" && rc.GetLabel() == "app" {
				rs[i] = parse(t, dc, "app", 900, "A", "192.0.2.3")
			}
		}
		return rs
	})
	if n != 2 {
		t.Errorf("changes = %d, want 2", n)
	}
	got := f.zone()
	for _, line := range []string{"app TXT app-verification-2 900", "app A 192.0.2.3 900"} {
		if !slices.Contains(got, line) {
			t.Errorf("zone lacks %q: %q", line, got)
		}
	}
	if slices.Contains(got, "@ TXT app-verification-2 900") {
		t.Errorf("the changed TXT record moved to the apex: %q", got)
	}
}

func TestRemovingASubdomainDeletesItsObject(t *testing.T) {
	f, p := newFake(t)
	push(t, p, fullZone(t))
	push(t, p, func(dc *models.DomainConfig) models.Records {
		return models.Records{parse(t, dc, "@", 300, "A", "192.0.2.1")}
	})
	if got := f.zone(); !slices.Equal(got, []string{"@ A 192.0.2.1 300"}) {
		t.Errorf("zone = %q", got)
	}
	if len(f.explicit) != 0 {
		t.Errorf("subdomain objects left: %v", f.explicit)
	}
}

func TestRecordsOnAnUnlistedSubdomainAreReadWhenWanted(t *testing.T) {
	f, p := newFake(t)
	// Written by hand without a subdomain object: Timeweb lists it nowhere.
	f.implicit["legacy"] = true
	f.add(twRecord{Type: "A", TTL: 600, Data: twData{Value: "192.0.2.9"}}, "legacy."+testDomain)
	dc := newDC(t)
	dc.Records = models.Records{parse(t, dc, "legacy", 600, "A", "192.0.2.9")}
	existing, err := p.GetZoneRecords(dc)
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 1 || existing[0].GetLabel() != "legacy" {
		t.Fatalf("existing = %v", existing)
	}
	_, count, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil || count != 0 {
		t.Errorf("corrections: count %d, err %v; want none", count, err)
	}
}

func TestNeverDeletesTheDomain(t *testing.T) {
	f, p := newFake(t)
	push(t, p, fullZone(t))
	push(t, p, func(*models.DomainConfig) models.Records { return nil })
	for _, c := range f.calls {
		if strings.HasPrefix(c, "DELETE /v1/domains/") && strings.Count(c, "/") == 3 {
			t.Errorf("called %s", c)
		}
	}
	if got := f.zone(); len(got) != 0 {
		t.Errorf("zone after emptying = %q", got)
	}
}

func TestAudit(t *testing.T) {
	dc := newDC(t)
	cases := []struct {
		rc   *models.RecordConfig
		fail bool
	}{
		{parse(t, dc, "_acme-challenge", 300, "CNAME", "x.example.net."), true},
		{parse(t, dc, "sel._domainkey", 300, "CNAME", "x.example.net."), true},
		{txt(t, dc, "sel._domainkey", 300, "v=DKIM1; p=abc"), false},
		{parse(t, dc, "www", 300, "A", "192.0.2.1"), false},
		{parse(t, dc, "*", 300, "A", "192.0.2.1"), false},
		{parse(t, dc, "a.b", 300, "A", "192.0.2.1"), false},
		{parse(t, dc, "_sip._tcp", 300, "SRV", "10 5 5060 sip.example.net."), true},
		{parse(t, dc, "_sip._tcp.app", 300, "SRV", "10 0 5060 sip.example.net."), false},
		{parse(t, dc, "sip", 300, "SRV", "10 0 5060 sip.example.net."), true},
		{txt(t, dc, "@", 300, `has "quotes"`), true},
		{txt(t, dc, "@", 300, "it's"), true},
		{txt(t, dc, "@", 300, `back\slash`), true},
		{parse(t, dc, "c", 300, "CNAME", "www.example.net."), true},
		{parse(t, dc, "c", 300, "CNAME", "a.www.example.net."), false},
		{parse(t, dc, "c", 300, "CNAME", "wwwx.example.net."), false},
		{parse(t, dc, "xn--ndaaa", 300, "A", "192.0.2.1"), true},
		{txt(t, dc, "xn--ndaaa", 300, "v"), true},
		{txt(t, dc, "@", 300, "back`tick"), true},
		{txt(t, dc, "@", 300, "trailing "), true},
		{txt(t, dc, "@", 300, " leading"), false},
		{parse(t, dc, "c", 300, "CNAME", "xn--ndaaa.example.net."), true},
		{parse(t, dc, "@", 300, "MX", "10 mx.xn--ndaaa.example.net."), true},
		{parse(t, dc, "_sip._tcp", 300, "SRV", "10 0 5060 xn--ndaaa.example.net."), true},
	}
	p := &timewebProvider{}
	for _, c := range cases {
		errs := p.AuditRecords(models.Records{c.rc})
		if (len(errs) > 0) != c.fail {
			t.Errorf("%s %s %s: errors %v, want failure %v", c.rc.GetLabel(), c.rc.Type, c.rc.GetRDATA(), errs, c.fail)
		}
	}
}

func TestRetries(t *testing.T) {
	var calls int
	status := http.StatusTooManyRequests
	retryAfter := "3"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", retryAfter)
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	var slept []time.Duration
	c := newClient("x")
	c.baseURL = srv.URL
	c.sleep = func(d time.Duration) { slept = append(slept, d) }

	if err := c.do("POST", "/p", map[string]string{}, nil); err != nil || calls != 2 || !slices.Equal(slept, []time.Duration{3 * time.Second}) {
		t.Errorf("429 on POST: err %v, calls %d, slept %v; want one retry after Retry-After", err, calls, slept)
	}
	status = http.StatusTooManyRequests

	calls, slept, retryAfter = 0, nil, "3600"
	if err := c.do("GET", "/p", nil, nil); err != nil || !slices.Equal(slept, []time.Duration{maxRetryAfter}) {
		t.Errorf("Retry-After 3600: err %v, slept %v; want one wait of %v", err, slept, maxRetryAfter)
	}

	calls, slept, status = 0, nil, http.StatusBadGateway
	if err := c.do("POST", "/p", map[string]string{}, nil); err == nil || calls != 1 {
		t.Errorf("502 on POST: err %v, calls %d; want the error and no retry", err, calls)
	}
	calls = 0
	if err := c.do("GET", "/p", nil, nil); err != nil || calls != 2 {
		t.Errorf("502 on GET: err %v, calls %d; want one retry", err, calls)
	}
}

func TestParseError(t *testing.T) {
	err := parseError(400, []byte(`{"status_code":400,"message":["property weight should not exist"],"error_code":"bad_request"}`))
	if got := err.Error(); got != "timeweb: HTTP 400 bad_request: [property weight should not exist]" {
		t.Errorf("got %q", got)
	}
	if !isStatus(parseError(409, []byte(`{"error_code":"entity_already_exists","message":"Entity already exists"}`)), 409) {
		t.Error("isStatus did not match 409")
	}
}

func TestApexNSRecordsAreDroppedWithoutTouchingTheCallersSlice(t *testing.T) {
	f, p := newFake(t)
	withNS := func(dc *models.DomainConfig) models.Records {
		// NS first, so that filtering in place would overwrite them in the caller's slice.
		return append(models.Records{
			parse(t, dc, "@", 300, "NS", "ns1.timeweb.ru."),
			parse(t, dc, "@", 300, "NS", "hydrogen.ns.hetzner.com."),
		}, fullZone(t)(dc)...)
	}
	push(t, p, withNS)
	if n := push(t, p, withNS); n != 0 {
		t.Errorf("second push made %d changes, want 0", n)
	}
	for _, line := range f.zone() {
		if strings.Contains(line, " NS ") {
			t.Errorf("NS record written: %q", line)
		}
	}

	dc := newDC(t)
	dc.Records = withNS(dc)
	shared := dc.Records
	before := len(shared)
	if _, _, err := p.GetZoneRecordsCorrections(dc, nil); err != nil {
		t.Fatal(err)
	}
	if len(dc.Records) != before-2 {
		t.Errorf("records after dropping apex NS: %d, want %d", len(dc.Records), before-2)
	}
	if shared[0].Type != "NS" || shared[1].Type != "NS" {
		t.Error("the slice the caller passed in was changed")
	}
}

func TestUnicodeSubdomainIsReadAndDeletedByItsPunycodeName(t *testing.T) {
	f, p := newFake(t)
	// Made in the panel: Timeweb lists it in Unicode, with its SPF record.
	f.explicit["ööö"] = true
	f.add(twRecord{Type: "TXT", TTL: 600, Data: twData{Subdomain: new("ööö"), Value: timewebDefaultSPF}}, testDomain)
	f.add(twRecord{Type: "A", TTL: 600, Data: twData{Value: "192.0.2.7"}}, "ööö."+testDomain)

	dc := newDC(t)
	existing, err := p.GetZoneRecords(dc)
	if err != nil {
		t.Fatalf("GetZoneRecords: %v", err)
	}
	var labels []string
	for _, rc := range existing {
		labels = append(labels, rc.GetLabel()+" "+rc.Type)
	}
	slices.Sort(labels)
	if !slices.Equal(labels, []string{"xn--ndaaa A", "xn--ndaaa TXT"}) {
		t.Fatalf("records read: %q", labels)
	}
	push(t, p, func(*models.DomainConfig) models.Records { return nil })
	if got := f.zone(); len(got) != 0 || len(f.explicit) != 0 {
		t.Errorf("after emptying: zone %q, subdomain objects %v", got, f.explicit)
	}
}

func TestIgnoredRecordsKeepTheirSubdomainObject(t *testing.T) {
	f, p := newFake(t)
	push(t, p, fullZone(t))
	// app's records are IGNORE()d, nothing else on app is wanted: the push must not delete app's object, which
	// would take the ignored records with it.
	dc := newDC(t)
	dc.Records = models.Records{parse(t, dc, "@", 300, "A", "192.0.2.1")}
	dc.Unmanaged = []*models.UnmanagedConfig{{LabelPattern: "app"}}
	existing, err := p.GetZoneRecords(dc)
	if err != nil {
		t.Fatal(err)
	}
	corrections, _, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corrections {
		if c.F != nil {
			if err := c.F(); err != nil {
				t.Fatalf("%s: %v", c.Msg, err)
			}
		}
	}
	if !f.explicit["app"] {
		t.Error("the subdomain object of an IGNORE()d name was deleted")
	}
	for _, line := range []string{"app A 192.0.2.2 300", "app TXT app-verification 600"} {
		if !slices.Contains(f.zone(), line) {
			t.Errorf("ignored record %q is gone", line)
		}
	}
	if f.explicit["x.y"] {
		t.Error("x.y lost its records but kept its object")
	}
}

func TestTypeChangeOnASubdomainKeepsItsObject(t *testing.T) {
	f, p := newFake(t)
	push(t, p, func(dc *models.DomainConfig) models.Records {
		return models.Records{parse(t, dc, "app", 300, "A", "192.0.2.2")}
	})
	// diff2.ByRecord turns this into DELETE A + CREATE CNAME: every existing record on app is deleted, but app is
	// still wanted, so its object (and the new CNAME on it) must stay.
	push(t, p, func(dc *models.DomainConfig) models.Records {
		return models.Records{parse(t, dc, "app", 600, "CNAME", "target.example.net.")}
	})
	if got := f.zone(); !slices.Equal(got, []string{"app CNAME target.example.net 600"}) {
		t.Errorf("zone = %q", got)
	}
	if !f.explicit["app"] {
		t.Error("app lost its subdomain object")
	}
}

func TestSRVChangeUpdatesTargetAndPort(t *testing.T) {
	f, p := newFake(t)
	push(t, p, fullZone(t))
	n := push(t, p, func(dc *models.DomainConfig) models.Records {
		rs := fullZone(t)(dc)
		for i, rc := range rs {
			if rc.Type == "SRV" && rc.GetLabel() == "_sip._udp.app" {
				rs[i] = parse(t, dc, "_sip._udp.app", 600, "SRV", "20 0 5070 sip2.example.net.")
			}
		}
		return rs
	})
	if n != 1 {
		t.Errorf("changes = %d, want 1", n)
	}
	if !slices.Contains(f.zone(), "app SRV _sip._UDP 20 5070 sip2.example.net 600") {
		t.Errorf("zone = %q", f.zone())
	}
}

func TestReadsEveryPage(t *testing.T) {
	f, p := newFake(t)
	for i := range 250 {
		f.add(twRecord{Type: "TXT", TTL: 600, Data: twData{Value: fmt.Sprintf("r%03d", i)}}, testDomain)
	}
	existing, err := p.GetZoneRecords(newDC(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 250 {
		t.Errorf("read %d records, want 250", len(existing))
	}
}

func TestWildcardIsAlwaysRead(t *testing.T) {
	f, p := newFake(t)
	f.implicit["*"] = true
	f.add(twRecord{Type: "A", TTL: 600, Data: twData{Value: "192.0.2.8"}}, "*."+testDomain)
	existing, err := p.GetZoneRecords(newDC(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 1 || existing[0].GetLabel() != "*" {
		t.Errorf("existing = %v; want the wildcard record even though dnsconfig.js does not name it", existing)
	}
}

func TestWritingOnAnUnlistedSubdomainStillWorks(t *testing.T) {
	f, p := newFake(t)
	f.implicit["legacy"] = true
	f.add(twRecord{Type: "A", TTL: 600, Data: twData{Value: "192.0.2.9"}}, "legacy."+testDomain)
	// Timeweb answers 409 when the provider tries to make legacy an object; the write must go on.
	push(t, p, func(dc *models.DomainConfig) models.Records {
		return models.Records{
			parse(t, dc, "legacy", 600, "A", "192.0.2.9"),
			parse(t, dc, "legacy", 600, "AAAA", "2001:db8::9"),
		}
	})
	if !slices.Contains(f.zone(), "legacy AAAA 2001:db8::9 600") {
		t.Errorf("zone = %q", f.zone())
	}
}

func TestSubdomainCallsRefuseLabelsThatAreNotLabels(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := newClient("x")
	c.baseURL = srv.URL
	for _, label := range []string{"..", ".", "", "a..b", ".a", "a/b"} {
		if err := c.deleteSubdomain(testDomain, label); err == nil {
			t.Errorf("deleteSubdomain(%q) succeeded", label)
		}
		if err := c.addSubdomain(testDomain, label); err == nil {
			t.Errorf("addSubdomain(%q) succeeded", label)
		}
	}
	if calls != 0 {
		t.Errorf("%d requests sent for refused labels", calls)
	}
}
