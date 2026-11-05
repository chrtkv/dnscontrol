package timeweb

/*
Timeweb Cloud DNS provider.

How Timeweb stores records, as observed through its API (2026-11-05):

  - Records on the domain itself, and every TXT record whatever its name, are listed under the domain
    (GET /v1/domains/{domain}/dns-records); a TXT record on a subdomain carries the label in data.subdomain.
  - Every other record on a subdomain is listed only under that subdomain's own fqdn
    (GET /v1/domains/{label}.{domain}/dns-records). Changes and deletes must use the fqdn the record is listed under.
  - A subdomain is either an explicit object (POST /v1/domains/{domain}/subdomains/{label}), which the domain lists,
    or implicit: created on the fly when a record is added on that label, and listed nowhere. Records on an implicit
    subdomain can only be found by asking for that name. To keep every name it writes findable, this provider creates
    the subdomain object before it writes the first record on a label. Labels that cannot be objects ("www", "*",
    and names with "_") are always implicit; "www" and "*" are always looked up, and AuditRecords refuses non-TXT
    records on the others because nothing could find them again once they leave dnsconfig.js.
  - Creating a subdomain object adds Timeweb's own SPF TXT record on it, which this provider deletes straight away.
  - SRV records keep service and protocol in data and sit on the subdomain after "_service._proto".
  - Timeweb answers for www with the apex records unless www has records of its own.
*/

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	dnsv2 "codeberg.org/miekg/dns"
	dnsrdatav2 "codeberg.org/miekg/dns/rdata"
	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/diff2"
	"github.com/DNSControl/dnscontrol/v5/pkg/nrc"
	"github.com/DNSControl/dnscontrol/v5/pkg/printer"
	"github.com/DNSControl/dnscontrol/v5/pkg/providers"
	"golang.org/x/net/idna"
)

func init() {
	providers.Register[*timewebProvider]("TIMEWEB", providers.Definition{
		FriendlyName: "Timeweb Cloud",
		Maintainer:   "@chrtkv",
		SupportedTypes: []string{
			"A",
			"AAAA",
			"CNAME",
			"MX",
			"SRV",
			"TXT",
		},
		CanDualHost:         providers.Cannot("Timeweb serves its own NS records at the apex and does not let them be changed"),
		CanUseDSForChildren: providers.Cannot(),
		CanConcur:           providers.Cannot("not verified"),
	})
}

// nameservers are the ones Timeweb serves for every domain on it.
var nameservers = []string{"ns1.timeweb.ru", "ns2.timeweb.ru", "ns3.timeweb.org", "ns4.timeweb.org"}

// timewebDefaultSPF is the TXT record Timeweb adds to every subdomain object it creates.
const timewebDefaultSPF = "v=spf1 include:_spf.timeweb.ru ~all"

type timewebProvider struct {
	api *client
}

// Initialize initializes a fresh provider instance.
func (p *timewebProvider) Initialize(m map[string]string, _ json.RawMessage, _ *providers.CreateOptions) error {
	token := m["api_token"]
	if token == "" {
		return errors.New("timeweb: missing api_token")
	}
	p.api = newClient(token)
	return nil
}

// existingRecord is what this provider keeps in RecordConfig.Original: the record and where Timeweb lists it.
type existingRecord struct {
	rec      twRecord
	listFQDN string
}

// GetNameservers returns the name servers Timeweb serves for the domain.
func (p *timewebProvider) GetNameservers(string) ([]*models.Nameserver, error) {
	return models.ToNameservers(nameservers)
}

// ListZones returns the domains in the Timeweb account.
func (p *timewebProvider) ListZones() ([]string, error) {
	domains, err := p.api.listDomains()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(domains))
	for _, d := range domains {
		names = append(names, d.FQDN)
	}
	return names, nil
}

// EnsureZoneExists adds the domain to the account when it is not there yet.
func (p *timewebProvider) EnsureZoneExists(dc *models.DomainConfig) error {
	_, err := p.api.getDomain(dc.Name)
	if isStatus(err, http.StatusNotFound) {
		return p.api.addDomain(dc.Name)
	}
	return err
}

// asciiLabel returns a label as DNSControl spells it: lowercase, and in punycode. Timeweb returns internationalized
// subdomains in Unicode ("ööö"), and answers 403 to a request that names them so; punycode works.
func asciiLabel(label string) string {
	if a, err := idna.ToASCII(label); err == nil {
		label = a
	}
	return strings.ToLower(label)
}

// subdomainLabels returns the labels of the explicit subdomain objects of a domain.
func subdomainLabels(d *twDomain) map[string]bool {
	labels := map[string]bool{}
	for _, s := range d.Subdomains {
		if label, ok := strings.CutSuffix(asciiLabel(s.FQDN), "."+asciiLabel(d.FQDN)); ok {
			labels[label] = true
		}
	}
	return labels
}

// GetZoneRecords returns the records Timeweb has for the domain: those listed under the domain, and those listed
// under each subdomain this provider can know of.
func (p *timewebProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	domain := dc.Name
	dom, err := p.api.getDomain(domain)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return nil, fmt.Errorf("timeweb: %s is not in the account (dnscontrol push creates it)", domain)
		}
		return nil, err
	}
	explicit := subdomainLabels(dom)

	var out models.Records
	seen := map[int64]bool{}
	add := func(r twRecord, sub, listFQDN string) error {
		if seen[r.ID] {
			return nil
		}
		seen[r.ID] = true
		rc, err := toRecordConfig(dc, r, sub)
		if err != nil {
			return err
		}
		rc.Original = &existingRecord{rec: r, listFQDN: listFQDN}
		out = append(out, rc)
		return nil
	}

	recs, err := p.api.listRecords(domain)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		sub := ""
		if r.Data.Subdomain != nil {
			sub = *r.Data.Subdomain // NewRecordConfig lowercases it and turns Unicode into punycode
		}
		if err := add(r, sub, domain); err != nil {
			return nil, err
		}
	}

	for _, label := range labelsToProbe(explicit, dc.Records) {
		fqdn := label + "." + domain
		recs, err := p.api.listRecords(fqdn)
		if isStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(recs) > 0 && !explicit[label] && !alwaysImplicit(label) {
			printer.Warnf("TIMEWEB: %s has records but Timeweb does not list it as a subdomain; "+
				"if it leaves dnsconfig.js, dnscontrol cannot see its records any more. "+
				"Delete them in the Timeweb panel and push again to recreate it as a listed subdomain.\n", fqdn)
		}
		for _, r := range recs {
			if err := add(r, label, fqdn); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// labelsToProbe returns, sorted, the subdomain labels whose own record lists must be read: the explicit
// subdomains, "www" and "*", and the subdomain of every non-TXT record dnsconfig.js wants.
func labelsToProbe(explicit map[string]bool, desired models.Records) []string {
	set := map[string]bool{"www": true, "*": true}
	for l := range explicit {
		set[l] = true
	}
	for _, rc := range desired {
		if rc.Type == "TXT" {
			continue
		}
		if sub := subdomainOf(rc); sub != "" {
			set[sub] = true
		}
	}
	labels := make([]string, 0, len(set))
	for l := range set {
		labels = append(labels, l)
	}
	slices.Sort(labels)
	return labels
}

// alwaysImplicit reports the labels Timeweb never lists as subdomain objects but this provider always looks up.
func alwaysImplicit(label string) bool {
	return label == "www" || label == "*"
}

var hostnameLabels = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// canBeObject reports whether Timeweb accepts label as a subdomain object.
func canBeObject(label string) bool {
	return label != "www" && hostnameLabels.MatchString(label)
}

// splitSRVLabel splits "_service._proto" or "_service._proto.sub" into its parts.
func splitSRVLabel(label string) (service, proto, sub string, ok bool) {
	parts := strings.SplitN(label, ".", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") {
		return "", "", "", false
	}
	if len(parts) == 3 {
		sub = parts[2]
	}
	return parts[0], parts[1], sub, true
}

// subdomainOf returns the subdomain label a record is stored on, "" for the domain itself. For SRV that is what
// follows "_service._proto".
func subdomainOf(rc *models.RecordConfig) string {
	label := rc.GetLabel()
	if rc.Type == "SRV" {
		if _, _, sub, ok := splitSRVLabel(label); ok {
			return sub
		}
	}
	if label == "@" {
		return ""
	}
	return label
}

// toRecordConfig converts a Timeweb record found on subdomain sub ("" for the domain) to a RecordConfig.
func toRecordConfig(dc *models.DomainConfig, r twRecord, sub string) (*models.RecordConfig, error) {
	label := sub
	if label == "" {
		label = "@"
	}
	ttl := uint32(r.TTL)
	var priority int64
	if r.Data.Priority != nil {
		priority = *r.Data.Priority
	}

	var rc *models.RecordConfig
	var err error
	switch r.Type {
	case "MX":
		rc, err = dc.NewRecordConfig(label, ttl, dnsv2.TypeMX, uint16(priority), r.Data.Value,
			nrc.Flags{TargetIsFqdnNoDot: true})
	case "SRV":
		srvLabel := r.Data.Service + "." + r.Data.Protocol // Timeweb answers "_TCP"; labels are lowercased by NewRecordConfig
		if sub != "" {
			srvLabel += "." + sub
		}
		var port int64
		if r.Data.Port != nil {
			port = *r.Data.Port
		}
		rc, err = dc.NewRecordConfig(srvLabel, ttl, dnsv2.TypeSRV, uint16(priority), uint16(0), uint16(port),
			r.Data.Host, nrc.Flags{TargetIsFqdnNoDot: true})
	case "TXT":
		rc, err = dc.NewRecordConfig(label, ttl, dnsv2.TypeTXT, r.Data.Value)
	case "A", "AAAA", "CNAME":
		rc, err = dc.NewRecordConfigParse(label, ttl, r.Type, r.Data.Value, nrc.Flags{TargetIsFqdnNoDot: true})
	default:
		return nil, fmt.Errorf("timeweb: unsupported record type %q (id %d)", r.Type, r.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("timeweb: unparsable %s record (id %d): %w", r.Type, r.ID, err)
	}
	return rc, nil
}

// toRequest converts a RecordConfig to the body Timeweb takes and the subdomain it goes on ("" for the domain).
func toRequest(rc *models.RecordConfig) (twRequest, string, error) {
	req := twRequest{Type: rc.Type, TTL: int64(rc.TTL)}
	sub := subdomainOf(rc)
	switch f := rc.GetRDATA().(type) {
	case dnsrdatav2.MX:
		pr := int64(f.Preference)
		req.Priority = &pr
		req.Value = strings.TrimSuffix(f.Mx, ".")
	case dnsrdatav2.SRV:
		service, proto, _, ok := splitSRVLabel(rc.GetLabel())
		if !ok {
			return twRequest{}, "", fmt.Errorf("timeweb: SRV label %q is not _service._proto[.name]", rc.GetLabel())
		}
		pr, port := int64(f.Priority), int64(f.Port)
		req.Priority, req.Port = &pr, &port
		req.Service, req.Protocol = service, proto
		req.Host = strings.TrimSuffix(f.Target, ".")
	case dnsrdatav2.CNAME:
		req.Value = strings.TrimSuffix(f.Target, ".")
	case dnsrdatav2.TXT:
		req.Value = rc.GetTargetTXTJoined()
	default:
		req.Value = rc.GetRDATA().String()
	}
	return req, sub, nil
}

// pushState is shared by the corrections of one domain, which DNSControl runs one after another.
type pushState struct {
	explicit map[string]bool
}

// ensureSubdomain makes label a subdomain object before the first record is written on it, so that the record can
// be found again, and removes the SPF record Timeweb adds to a new subdomain.
func (p *timewebProvider) ensureSubdomain(st *pushState, domain, label string) error {
	if !canBeObject(label) || st.explicit[label] {
		return nil
	}
	before, err := p.api.listRecords(domain)
	if err != nil {
		return err
	}
	err = p.api.addSubdomain(domain, label)
	if isStatus(err, http.StatusConflict) {
		// The name exists but is not listed: something wrote on it without creating the object first.
		printer.Warnf("TIMEWEB: %s.%s exists but is not listed as a subdomain; see the warning about it above.\n", label, domain)
		st.explicit[label] = true
		return nil
	}
	if err != nil {
		return err
	}
	st.explicit[label] = true
	after, err := p.api.listRecords(domain)
	if err != nil {
		return err
	}
	for _, r := range newDefaultSPF(before, after, label) {
		if err := p.api.deleteRecord(domain, r.ID); err != nil {
			return fmt.Errorf("timeweb: deleting the SPF record Timeweb added to %s.%s: %w", label, domain, err)
		}
	}
	return nil
}

// newDefaultSPF returns Timeweb's SPF records on label that are in after but not in before.
func newDefaultSPF(before, after []twRecord, label string) []twRecord {
	old := map[int64]bool{}
	for _, r := range before {
		old[r.ID] = true
	}
	var added []twRecord
	for _, r := range after {
		if old[r.ID] || r.Type != "TXT" || r.Data.Subdomain == nil || asciiLabel(*r.Data.Subdomain) != label {
			continue
		}
		if r.Data.Value == timewebDefaultSPF {
			added = append(added, r)
		}
	}
	return added
}

// dropApexNS removes the apex NS records DNSControl adds from every provider's name servers. Timeweb serves its own
// four there and takes no NS records; when the domain also has another provider, its name servers are in the list
// too, so they are dropped without a warning. It builds a new slice: the old one may be shared.
func dropApexNS(dc *models.DomainConfig) {
	kept := make(models.Records, 0, len(dc.Records))
	for _, rc := range dc.Records {
		if rc.Type != "NS" || rc.GetLabel() != "@" {
			kept = append(kept, rc)
		}
	}
	dc.Records = kept
}

// GetZoneRecordsCorrections returns the corrections that turn the existing records into dc.Records.
func (p *timewebProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existing models.Records) ([]*models.Correction, int, error) {
	dropApexNS(dc)
	changes, count, err := diff2.ByRecord(existing, dc, nil)
	if err != nil {
		return nil, 0, err
	}
	domain := dc.Name
	dom, err := p.api.getDomain(domain)
	if err != nil {
		return nil, 0, err
	}
	st := &pushState{explicit: subdomainLabels(dom)}

	var corrections []*models.Correction
	deleted := models.Records{}
	for _, change := range changes {
		switch change.Type {
		case diff2.REPORT:
			corrections = append(corrections, &models.Correction{Msg: change.MsgsJoined})

		case diff2.CREATE:
			req, sub, err := toRequest(change.New[0])
			if err != nil {
				return nil, 0, err
			}
			corrections = append(corrections, &models.Correction{
				Msg: change.Msgs[0],
				F: func() error {
					if sub == "" {
						return p.api.createRecordAtApex(domain, req)
					}
					if err := p.ensureSubdomain(st, domain, sub); err != nil {
						return err
					}
					req.Subdomain = sub
					return p.api.createRecordAtSubdomain(domain, req)
				},
			})

		case diff2.CHANGE:
			old := change.Old[0].Original.(*existingRecord)
			req, sub, err := toRequest(change.New[0])
			if err != nil {
				return nil, 0, err
			}
			update := func() error { return p.api.updateRecord(old.listFQDN, old.rec.ID, req) }
			if req.Type == "TXT" {
				req.Subdomain = sub
				update = func() error { return p.api.updateTXTRecord(domain, old.rec.ID, req) }
			}
			corrections = append(corrections, &models.Correction{Msg: change.Msgs[0], F: update})

		case diff2.DELETE:
			old := change.Old[0].Original.(*existingRecord)
			deleted = append(deleted, change.Old[0])
			corrections = append(corrections, &models.Correction{
				Msg: change.Msgs[0],
				F:   func() error { return p.api.deleteRecord(old.listFQDN, old.rec.ID) },
			})

		default:
			panic(fmt.Sprintf("unhandled change.Type %s", change.Type))
		}
	}

	// A subdomain object that this push empties is deleted last, after its records.
	for _, label := range emptiedSubdomains(st.explicit, dc.Records, existing, deleted) {
		corrections = append(corrections, &models.Correction{
			Msg: fmt.Sprintf("- DELETE subdomain object %s.%s (no records left on it)", label, domain),
			F:   func() error { return p.api.deleteSubdomain(domain, label) },
		})
		count++
	}
	return corrections, count, nil
}

// emptiedSubdomains returns, sorted, the explicit subdomains that no wanted record is stored on and whose existing
// records this push deletes, every one of them. Deleting the object deletes whatever is still on it, so a subdomain
// that keeps a record the push leaves alone (an IGNORE()d one) keeps its object.
func emptiedSubdomains(explicit map[string]bool, desired, existing, deleted models.Records) []string {
	used := map[string]bool{}
	for _, rc := range desired {
		used[subdomainOf(rc)] = true
	}
	left := map[string]int{}
	for _, rc := range existing {
		left[subdomainOf(rc)]++
	}
	for _, rc := range deleted {
		left[subdomainOf(rc)]--
	}
	var emptied []string
	for label := range explicit {
		if !used[label] && left[label] == 0 {
			emptied = append(emptied, label)
		}
	}
	slices.Sort(emptied)
	return emptied
}
