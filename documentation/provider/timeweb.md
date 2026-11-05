## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to `TIMEWEB`
along with a Timeweb Cloud API token.

{% code title="creds.json" %}
```json
{
  "timeweb": {
    "TYPE": "TIMEWEB",
    "api_token": "your-timeweb-cloud-api-token"
  }
}
```
{% endcode %}

## Metadata
This provider does not recognize any special metadata fields unique to Timeweb Cloud.

## Usage
An example configuration:

{% code title="dnsconfig.js" %}
```javascript
var REG_NONE = NewRegistrar("none");
var DSP_TIMEWEB = NewDnsProvider("timeweb");

D("example.ru", REG_NONE, DnsProvider(DSP_TIMEWEB),
    A("@", "192.0.2.1"),
    A("app", "192.0.2.2"),
    TXT("_dmarc", "v=DMARC1; p=reject"),
);
```
{% endcode %}

## Activation
Create an API token in the Timeweb Cloud panel. The token can be limited to
"Domains and SSL" with the "Manage" permission and no access to anything else;
that is all this provider needs.

`dnscontrol push` adds a domain that is not in the account yet. Timeweb then
creates its own SPF, DMARC and MX records on it, which the same push deletes
unless `dnsconfig.js` has them.

## Caveats

- Record types: A, AAAA, CNAME, MX, SRV and TXT. Timeweb has no CAA or NS
  records, and serves its own four name servers at the apex.
- TXT values cannot contain double quotes, single quotes, backticks or
  backslashes, nor end with a space (Timeweb drops it). SRV records have no weight; it must be 0. A CNAME target cannot
  start with `www.` (`a.www.example.com` is accepted).
- Internationalized names (`xn--…`) are refused, as labels and as CNAME, MX
  or SRV targets: Timeweb stores them in Unicode and fails on records created
  there.
- Timeweb lists the records of a subdomain only when the subdomain exists as a
  subdomain object; records written on a name without one are listed nowhere.
  The provider creates the subdomain object before it writes the first record
  on a name, and deletes it once a push has deleted every record on it
  (deleting the object deletes its records, so a name with `IGNORE()`d records
  keeps its object). Names with `_` cannot be
  subdomain objects, so the provider accepts only TXT records on them (Timeweb
  lists every TXT record under the domain). `www` and `*` are always looked up.
- Records that were written on a name without a subdomain object (for example
  by hand in the panel) are found only while that name is in `dnsconfig.js`.
  The provider prints a warning for them.
- Timeweb answers for `www` with records of its own unless `www` has records in
  the zone.
- A domain added to Timeweb is served by its name servers only after a delay
  (about 40 minutes was observed).

## Feature Summary

<!-- provider-features-start -->
- Provider Type
  - [Official Support](../provider/index.md#providers-with-official-support): ❌
  - DNS Provider: ✅
  - Registrar: ❌
- Provider API
  - [Concurrent fetching](../advanced-features/concurrency-verified.md): ❌
  - [dual host](../advanced-features/dual-host.md): ❌
  - create-domains: ✅
  - [get-zones](../commands/get-zones.md): ✅
- DNS extensions
  - [`ALIAS`](../language-reference/domain-modifiers/ALIAS.md): ❌
  - [`CSYNC`](../language-reference/domain-modifiers/CSYNC.md): ❌
  - [`DNAME`](../language-reference/domain-modifiers/DNAME.md): ❌
  - [`LOC`](../language-reference/domain-modifiers/LOC.md): ❌
  - [`PTR`](../language-reference/domain-modifiers/PTR.md): ❌
  - [`RP`](../language-reference/domain-modifiers/RP.md): ❌
  - [`SOA`](../language-reference/domain-modifiers/SOA.md): ❌
- Service discovery
  - [`DHCID`](../language-reference/domain-modifiers/DHCID.md): ❌
  - [`NAPTR`](../language-reference/domain-modifiers/NAPTR.md): ❌
  - [`SRV`](../language-reference/domain-modifiers/SRV.md): ✅
  - [`SVCB`](../language-reference/domain-modifiers/SVCB.md): ❌
- Security
  - [`CAA`](../language-reference/domain-modifiers/CAA.md): ❌
  - [`HTTPS`](../language-reference/domain-modifiers/HTTPS.md): ❌
  - [`OPENPGPKEY`](../language-reference/domain-modifiers/OPENPGPKEY.md): ❌
  - [`SMIMEA`](../language-reference/domain-modifiers/SMIMEA.md): ❌
  - [`SSHFP`](../language-reference/domain-modifiers/SSHFP.md): ❌
  - [`TLSA`](../language-reference/domain-modifiers/TLSA.md): ❌
- DNSSEC
  - [`AUTODNSSEC`](../language-reference/domain-modifiers/AUTODNSSEC_ON.md): ❌
  - [`DNSKEY`](../language-reference/domain-modifiers/DNSKEY.md): ❌
  - [`DS`](../language-reference/domain-modifiers/DS.md): ❌
<!-- provider-features-end -->
