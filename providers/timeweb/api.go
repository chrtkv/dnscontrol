package timeweb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const defaultBaseURL = "https://api.timeweb.cloud/api"

// twData is the "data" object of a Timeweb DNS record. Which fields are set depends on the record type.
type twData struct {
	Subdomain *string `json:"subdomain,omitempty"`
	Value     string  `json:"value,omitempty"`
	Priority  *int64  `json:"priority,omitempty"`
	Host      string  `json:"host,omitempty"`
	Port      *int64  `json:"port,omitempty"`
	Service   string  `json:"service,omitempty"`
	Protocol  string  `json:"protocol,omitempty"`
}

// twRecord is a DNS record as Timeweb lists it.
type twRecord struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl"`
	Data twData `json:"data"`
}

// twRequest is the body that creates or updates a record.
type twRequest struct {
	Type      string `json:"type"`
	Value     string `json:"value,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	Priority  *int64 `json:"priority,omitempty"`
	TTL       int64  `json:"ttl,omitempty"`
	Service   string `json:"service,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Host      string `json:"host,omitempty"`
	Port      *int64 `json:"port,omitempty"`
}

type twSubdomain struct {
	FQDN string `json:"fqdn"`
}

type twDomain struct {
	FQDN       string        `json:"fqdn"`
	Subdomains []twSubdomain `json:"subdomains"`
}

// apiError is a non-2xx answer. Code is Timeweb's error_code, e.g. "entity_already_exists".
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("timeweb: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

func isStatus(err error, status int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == status
}

type client struct {
	baseURL string
	token   string
	http    *http.Client
	// sleep is replaced in tests so that the 429 retries do not wait.
	sleep func(time.Duration)
}

func newClient(token string) *client {
	return &client{
		baseURL: defaultBaseURL,
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
		sleep:   time.Sleep,
	}
}

const maxAttempts = 6

// maxRetryAfter caps a Retry-After from Timeweb, so that a large value cannot stall a push for hours.
const maxRetryAfter = time.Minute

// do sends one request and decodes a 2xx answer into out (when out is not nil). It retries on 429, and on 5xx for
// reads only: a write that failed with 5xx may still have been applied, and repeating a create would duplicate the
// record. It waits for Retry-After when Timeweb sends it (at most maxRetryAfter) and doubles the wait otherwise.
func (c *client) do(method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	wait := time.Second
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("timeweb: %s %s: %w", method, path, err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("timeweb: %s %s: reading the answer: %w", method, path, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && method == http.MethodGet) {
			if attempt < maxAttempts {
				d := wait
				if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
					d = min(time.Duration(s)*time.Second, maxRetryAfter)
				}
				c.sleep(d)
				wait *= 2
				continue
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return parseError(resp.StatusCode, data)
		}
		if out == nil || len(data) == 0 {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("timeweb: %s %s: decoding the answer: %w", method, path, err)
		}
		return nil
	}
}

func parseError(status int, data []byte) error {
	var e struct {
		ErrorCode string          `json:"error_code"`
		Message   json.RawMessage `json:"message"`
	}
	ae := &apiError{Status: status}
	if json.Unmarshal(data, &e) != nil {
		ae.Message = string(data)
		return ae
	}
	ae.Code = e.ErrorCode
	// "message" is a string, or a list of strings for validation errors.
	var one string
	var many []string
	switch {
	case json.Unmarshal(e.Message, &one) == nil:
		ae.Message = one
	case json.Unmarshal(e.Message, &many) == nil:
		ae.Message = fmt.Sprint(many)
	default:
		ae.Message = string(e.Message)
	}
	return ae
}

func (c *client) getDomain(fqdn string) (*twDomain, error) {
	var out struct {
		Domain twDomain `json:"domain"`
	}
	if err := c.do(http.MethodGet, "/v1/domains/"+url.PathEscape(fqdn), nil, &out); err != nil {
		return nil, err
	}
	return &out.Domain, nil
}

const pageSize = 100

func (c *client) listDomains() ([]twDomain, error) {
	var all []twDomain
	for offset := 0; ; offset += pageSize {
		var out struct {
			Domains []twDomain `json:"domains"`
		}
		path := fmt.Sprintf("/v1/domains?limit=%d&offset=%d", pageSize, offset)
		if err := c.do(http.MethodGet, path, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Domains...)
		if len(out.Domains) < pageSize {
			return all, nil
		}
	}
}

// listRecords lists the records Timeweb keeps under fqdn, a domain or a subdomain. A subdomain that does not exist
// is answered with 404, which the caller decides how to treat.
func (c *client) listRecords(fqdn string) ([]twRecord, error) {
	var all []twRecord
	for offset := 0; ; offset += pageSize {
		var out struct {
			Records []twRecord `json:"dns_records"`
		}
		path := fmt.Sprintf("/v1/domains/%s/dns-records?limit=%d&offset=%d", url.PathEscape(fqdn), pageSize, offset)
		if err := c.do(http.MethodGet, path, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Records...)
		if len(out.Records) < pageSize {
			return all, nil
		}
	}
}

// createRecordAtApex creates a record on the domain itself. Only the v2 call accepts records without a subdomain.
func (c *client) createRecordAtApex(domain string, req twRequest) error {
	req.Subdomain = ""
	return c.do(http.MethodPost, "/v2/domains/"+url.PathEscape(domain)+"/dns-records", req, nil)
}

// createRecordAtSubdomain creates a record on req.Subdomain (a label relative to domain). The v1 call takes the
// subdomain in the body; the v2 one would need the subdomain's own fqdn and refuses TXT.
func (c *client) createRecordAtSubdomain(domain string, req twRequest) error {
	return c.do(http.MethodPost, "/v1/domains/"+url.PathEscape(domain)+"/dns-records", req, nil)
}

// updateRecord changes a non-TXT record in place. listFQDN is the name the record was listed under. The v2 call
// refuses a subdomain in the body.
func (c *client) updateRecord(listFQDN string, id int64, req twRequest) error {
	req.Subdomain = ""
	return c.do(http.MethodPatch, fmt.Sprintf("/v2/domains/%s/dns-records/%d", url.PathEscape(listFQDN), id), req, nil)
}

// updateTXTRecord changes a TXT record in place. TXT records are listed under the domain whatever their name, and
// the subdomain must be sent again: the v2 call, which refuses it, moves a TXT record from its subdomain to the
// apex (seen 2026-11-05).
func (c *client) updateTXTRecord(domain string, id int64, req twRequest) error {
	return c.do(http.MethodPatch, fmt.Sprintf("/v1/domains/%s/dns-records/%d", url.PathEscape(domain), id), req, nil)
}

// deleteRecord deletes a record. listFQDN is the name the record was listed under; Timeweb answers 404 for any other.
func (c *client) deleteRecord(listFQDN string, id int64) error {
	return c.do(http.MethodDelete, fmt.Sprintf("/v1/domains/%s/dns-records/%d", url.PathEscape(listFQDN), id), nil, nil)
}

// addSubdomain creates the subdomain object label.domain. Timeweb answers 409 when the name already exists, listed
// or not.
func (c *client) addSubdomain(domain, label string) error {
	if !canBeObject(label) {
		return fmt.Errorf("timeweb: %q is not a subdomain label", label)
	}
	return c.do(http.MethodPost, "/v1/domains/"+url.PathEscape(domain)+"/subdomains/"+url.PathEscape(label), nil, nil)
}

// deleteSubdomain deletes the subdomain object label.domain together with every record on it. It goes to
// /domains/{domain}/subdomains/{label}; DELETE /domains/{fqdn} with a subdomain's fqdn deletes the whole domain, so
// this provider never calls that one.
func (c *client) deleteSubdomain(domain, label string) error {
	// The label comes from Timeweb's own list. Checking it keeps a malformed one such as ".." from turning this into
	// a request a path-normalizing proxy would read as DELETE /domains/{domain}.
	if !canBeObject(label) {
		return fmt.Errorf("timeweb: refusing to delete subdomain %q of %s: not a subdomain label", label, domain)
	}
	return c.do(http.MethodDelete, "/v1/domains/"+url.PathEscape(domain)+"/subdomains/"+url.PathEscape(label), nil, nil)
}

// addDomain adds a domain registered elsewhere to the account. Timeweb then creates its own SPF, DMARC and MX
// records on it, which the next push removes unless dnsconfig.js has them.
func (c *client) addDomain(domain string) error {
	return c.do(http.MethodPost, "/v1/add-domain/"+url.PathEscape(domain), nil, nil)
}
