package timeweb

import (
	"errors"
	"fmt"
	"strings"

	dnsrdatav2 "codeberg.org/miekg/dns/rdata"
	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider.  If all records are
// supported, an empty list is returned.
func (*timewebProvider) AuditRecords(records models.Records) []error {
	a := rejectif.Auditor{}

	a.Add("TXT", rejectif.TxtIsEmpty)
	a.Add("TXT", rejectif.TxtHasDoubleQuotes)  // Timeweb answers "Validation error". Last verified 2026-11-05
	a.Add("TXT", rejectif.TxtHasSingleQuotes)  // Timeweb answers "Validation error". Last verified 2026-11-06
	a.Add("TXT", rejectif.TxtHasBackslash)     // Timeweb answers "Validation error". Last verified 2026-11-06
	a.Add("TXT", rejectif.TxtHasBackticks)     // Timeweb answers "Validation error". Last verified 2026-11-06
	a.Add("TXT", rejectif.TxtHasTrailingSpace) // Timeweb drops it, so every push would change it. Last verified 2026-11-06

	a.Add("MX", rejectif.MxNull)

	a.Add("CNAME", cnameTargetStartsWithWWW) // Timeweb answers "Validation error". Last verified 2026-11-06

	a.Add("SRV", rejectif.SrvHasNullTarget)
	a.Add("SRV", srvHasWeight) // Timeweb answers "property weight should not exist". Last verified 2026-11-05
	a.Add("SRV", srvLabelNotServiceProto)

	for _, t := range []string{"A", "AAAA", "CNAME", "MX", "SRV", "TXT"} {
		a.Add(t, labelIsIDN)
	}
	for _, t := range []string{"CNAME", "MX", "SRV"} {
		a.Add(t, targetIsIDN) // Timeweb answers "Validation error" for a CNAME. Last verified 2026-11-06
	}
	for _, t := range []string{"A", "AAAA", "CNAME", "MX", "SRV"} {
		a.Add(t, labelCannotBeFound)
	}

	return a.Audit(records)
}

func srvHasWeight(rc *models.RecordConfig) error {
	if f, ok := rc.GetRDATA().(dnsrdatav2.SRV); ok && f.Weight != 0 {
		return errors.New("timeweb has no SRV weight; it must be 0")
	}
	return nil
}

func srvLabelNotServiceProto(rc *models.RecordConfig) error {
	if _, _, _, ok := splitSRVLabel(rc.GetLabel()); !ok {
		return errors.New("timeweb stores SRV as _service._proto[.name]; this label is not of that form")
	}
	return nil
}

// cnameTargetStartsWithWWW refuses "www.example.com" as a CNAME target; Timeweb takes "a.www.example.com" and
// "wwwx.example.com".
func cnameTargetStartsWithWWW(rc *models.RecordConfig) error {
	if f, ok := rc.GetRDATA().(dnsrdatav2.CNAME); ok && strings.HasPrefix(strings.ToLower(f.Target), "www.") {
		return errors.New("timeweb refuses a CNAME target that starts with \"www.\"")
	}
	return nil
}

// labelIsIDN refuses internationalized names: Timeweb stores them in Unicode, answers 403 to requests for that
// name and 500 to a record created on it (seen 2026-11-06).
func labelIsIDN(rc *models.RecordConfig) error {
	for part := range strings.SplitSeq(rc.GetLabel(), ".") {
		if strings.HasPrefix(part, "xn--") {
			return errors.New("timeweb cannot store records on an internationalized name")
		}
	}
	return nil
}

// targetIsIDN refuses an internationalized target name.
func targetIsIDN(rc *models.RecordConfig) error {
	var target string
	switch f := rc.GetRDATA().(type) {
	case dnsrdatav2.CNAME:
		target = f.Target
	case dnsrdatav2.MX:
		target = f.Mx
	case dnsrdatav2.SRV:
		target = f.Target
	}
	for part := range strings.SplitSeq(strings.ToLower(target), ".") {
		if strings.HasPrefix(part, "xn--") {
			return errors.New("timeweb refuses an internationalized target name")
		}
	}
	return nil
}

// labelCannotBeFound refuses records that would sit on a subdomain Timeweb cannot list ("_dkim", "a_b"):
// once such a record left dnsconfig.js, nothing could find it to delete it. TXT records are exempt, Timeweb lists
// them under the domain whatever their name; so are "www" and "*", which this provider always looks up.
func labelCannotBeFound(rc *models.RecordConfig) error {
	sub := subdomainOf(rc)
	if sub == "" || alwaysImplicit(sub) || canBeObject(sub) {
		return nil
	}
	return fmt.Errorf("timeweb cannot list the subdomain %q, so a %s record there could not be found again; only TXT records may use such a name", sub, rc.Type)
}
