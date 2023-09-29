package goresolver

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultTimeout = 5 * time.Second
)

// Resolver contains the client configuration for github.com/miekg/dns,
// the instantiated client and the func that performs the actual queries.
// queryFn can be used for mocking the actual DNS lookups in the test suite.
type Resolver struct {
	queryFn         func(string, uint16) (*dns.Msg, error)
	dnsClient       *dns.Client
	dnsClientConfig *dns.ClientConfig
}

// Errors returned by the verification/validation methods at all levels.
var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
	ErrInvalidQuery         = errors.New("invalid query input")
)

var resolver *Resolver

type FetchedMessage struct {
	Qname   string
	Qtype   string
	Message *dns.Msg
}

type FetchedRecord struct {
	Qname  string
	Qtype  string
	Atype  string
	Record dns.RR
}

var FetchedRecords []FetchedRecord
var FetchedMessages []FetchedMessage

// NewDNSMessage creates and initializes a dns.Msg object, with EDNS enabled
// and the DO (DNSSEC OK) flag set.  It returns a pointer to the created
// object.
func NewDNSMessage() *dns.Msg {
	dnsMessage := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
	}
	dnsMessage.SetEdns0(4096, true)
	return dnsMessage
}

// localQuery takes a query name (qname) and query type (qtype) and
// performs a DNS lookup by calling dnsClient.Exchange.
// It returns the answer in a *dns.Msg (or nil in case of an error, in which
// case err will be set accordingly.)
func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := NewDNSMessage()
	dnsMessage.SetQuestion(qname, qtype)

	if resolver.dnsClientConfig == nil {
		return nil, errors.New("dns client not initialized")
	}

	for _, server := range resolver.dnsClientConfig.Servers {
		r, _, err := resolver.dnsClient.Exchange(dnsMessage, server+":"+resolver.dnsClientConfig.Port)
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, ErrNsNotAvailable
}

// queryDelegation takes a domain name and fetches the DS and DNSKEY records
// in that zone.  Returns a SignedZone or nil in case of error.
func queryDelegation(domainName string) (signedZone *SignedZone, err error) {

	signedZone = NewSignedZone(domainName)

	// dummy query NSEC records

	signedZone.dnskey, err = queryRRset(domainName, dns.TypeDNSKEY)
	if err != nil {
		fmt.Printf("ignoring missing DNSKEY since NSEC records may exist: %s\n", err)
		// return nil, err
	} else {
		signedZone.pubKeyLookup = make(map[uint16]*dns.DNSKEY)
		for _, rr := range signedZone.dnskey.rrSet {
			// TODO: handle CNAME records (follow to actual DNSKEY) -> not sure if this is necessary or if it this recursive lookup is always performed by DNS resolver
			// example: dig dnskey nga.cn +dnssec @1.1.1.1
			key, ok := rr.(*dns.DNSKEY)
			if !ok {
				return signedZone, fmt.Errorf("CNAME instead of DNSKEY returned")
			}
			signedZone.addPubKey(key)
		}
	}

	ds, nsec, nsec3, soa, err := queryRRsetOrNsecRecords(domainName, dns.TypeDS)
	if !ds.IsEmpty() {
		signedZone.ds = ds
	} else if nsec != nil {
		signedZone.dsNsecStruct = nsec
	} else if nsec3 != nil {
		signedZone.dsNsec3Struct = nsec3
	} else if soa != nil {
		signedZone.soaStruct = soa
	} else if domainName != "." {
		fmt.Printf("ignoring missing subdomain/other errors to allow (partial) verification: %s\n", err)
		// return signedZone, fmt.Errorf("Failed to fetch DS or NSEC(3) record (%s:DS)", domainName)
	}

	return signedZone, nil
}

// NewResolver initializes the package Resolver instance using the default
// dnsClientConfig.
func NewResolver(resolvConfText string) (res *Resolver, err error) {
	resolver = &Resolver{}
	resolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	resolver.dnsClientConfig, err = dns.ClientConfigFromReader(strings.NewReader(resolvConfText))
	if err != nil {
		return nil, err
	}
	resolver.queryFn = localQuery
	return resolver, nil
}
