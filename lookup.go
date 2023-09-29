package goresolver

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const MaxReturnedIPAddressesCount = 64

type NsecStatus struct {
	nsecProtectedDomains  []string
	nsec3ProtectedDomains []string
	nsec3OptOutDomains    []string
	unprotectedDomains    []string
	errors                []string
}

func (s *NsecStatus) GenerateCsvHeaders() []string {
	return []string{"domain", "result", "nsec-protected", "nsec3-protected", "nsec3-opt-out", "unprotected", "errors"}
}

func (s *NsecStatus) GenerateCsvRow(domain, result string) []string {
	return []string{domain, result, strings.Join(s.nsecProtectedDomains, ";"), strings.Join(s.nsec3ProtectedDomains, ";"), strings.Join(s.nsec3OptOutDomains, ";"), strings.Join(s.unprotectedDomains, ";"), strings.Join(s.errors, ";")}
}

func (s *NsecStatus) String() string {
	description := "<NsecStatus "
	description += fmt.Sprintf("nsecProtectedDomains=%s, ", s.nsecProtectedDomains)
	description += fmt.Sprintf("nsec3ProtectedDomains=%s, ", s.nsec3ProtectedDomains)
	description += fmt.Sprintf("nsec3OptOutDomains=%s, ", s.nsec3OptOutDomains)
	description += fmt.Sprintf("unprotectedDomains=%s, ", s.unprotectedDomains)
	description += fmt.Sprintf("errors=%s", s.errors)
	description += ">"
	return description
}

func (resolver *Resolver) LookupIP(qname string) (ips []net.IP, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}

	answers := make([]*RRSet, 0, len(qtypes))

	for _, qtype := range qtypes {

		answer, err := queryRRset(qname, qtype)
		if answer == nil {
			continue
		}
		if err != nil {
			continue
		}
		if answer.IsEmpty() {
			continue
		}
		if !answer.IsSigned() {
			continue
		}

		answers = append(answers, answer)
	}

	if len(answers) < 1 {
		log.Printf("no results")
		return nil, ErrNoResult
	}

	signerName := answers[0].SignerName()
	authChain := NewAuthenticationChain()
	err = authChain.Populate(signerName)
	if err != nil {
		log.Printf("Cannot populate authentication chain: %s\n", err)
		return nil, err
	}
	resultIPs := make([]net.IP, MaxReturnedIPAddressesCount)
	for _, answer := range answers {
		err = authChain.Verify(answer)
		if err != nil {
			log.Printf("DNSSEC validation failed: %s\n", err)
			continue
		}
		ips := formatResultRRs(answer)
		resultIPs = append(resultIPs, ips...)
	}

	return resultIPs, nil
}

func (resolver *Resolver) LookupIPv4(qname string) (ips []net.IP, err error) {
	return resolver.LookupIPType(qname, dns.TypeA)
}

func (resolver *Resolver) LookupIPv6(qname string) (ips []net.IP, err error) {
	return resolver.LookupIPType(qname, dns.TypeAAAA)
}

// Queries an A or AAAA RR
func (resolver *Resolver) LookupIPType(qname string, qtype uint16) (ips []net.IP, err error) {

	if len(qname) < 1 {
		return nil, nil
	}

	answer, err := queryRRset(qname, qtype)
	if answer == nil {
		return nil, ErrNoResult
	}

	if err != nil {
		return nil, err
	}

	if !answer.IsSigned() {
		return formatResultRRs(answer), ErrResourceNotSigned
	}

	signerName := answer.SignerName()
	authChain := NewAuthenticationChain()
	err = authChain.Populate(signerName)
	if err != nil {
		log.Printf("Cannot populate authentication chain: %s\n", err)
		return nil, err
	}

	err = authChain.Verify(answer)
	if err != nil {
		log.Printf("DNSSEC validation failed: %s\n", err)
		return nil, err
	}

	return formatResultRRs(answer), nil
}

func (resolver *Resolver) StrictNSQuery(qname string, qtype uint16) (rrSet []dns.RR, err error) {

	if len(qname) < 1 {
		return nil, ErrInvalidQuery
	}

	answer, err := queryRRset(qname, qtype)
	if err != nil {
		return nil, err
	}

	if answer.IsEmpty() {
		return nil, ErrNoResult
	}

	if !answer.IsSigned() {
		return nil, ErrResourceNotSigned
	}

	// isn't a check missing if signerName is an actual parent domain of the answer record?
	signerName := answer.SignerName()

	authChain := NewAuthenticationChain()
	err = authChain.Populate(signerName)

	if err == ErrNoResult {
		return nil, err
	}

	err = authChain.Verify(answer)
	if err != nil {
		log.Printf("DNSSEC validation failed: %s\n", err)
		return nil, err
	}

	return answer.rrSet, nil
}

func (resolver *Resolver) FetchNsecProofOfAbsenceStatus(qname string, qtype uint16) (nsecStatus *NsecStatus, err error) {
	return getNsecRecords(qname, qtype)
}

func (resolver *Resolver) StrictNSQueryWithNsec3(qname string, qtype uint16) (rrSet []dns.RR, err error) {

	if len(qname) < 1 {
		return nil, ErrInvalidQuery
	}

	answer, err := queryRRset(qname, qtype)
	if err != nil {
		return nil, err
	}

	// if answer.IsEmpty() {
	// return nil, ErrNoResult
	// }

	if !answer.IsEmpty() && !answer.IsSigned() {
		return nil, fmt.Errorf("%s (%s:%s)", ErrResourceNotSigned, qname, dns.TypeToString[qtype])
	}

	// isn't a check missing if signerName is an actual parent domain of the answer record?

	signerName := qname
	if !answer.IsEmpty() {
		signerName = answer.SignerName()
	}

	authChain := NewAuthenticationChain()
	err = authChain.PopulateWithNsec(signerName)

	if err == ErrNoResult {
		return nil, err
	} else if err != nil {
		return nil, err
	}

	err = authChain.VerifyWithNsec(qname)
	if err != nil {
		log.Printf("DNSSEC validation failed: %s\n", err)
		return nil, err
	}

	return answer.rrSet, nil
}

func getNsecRecords(domain string, qtype uint16) (*NsecStatus, error) {
	status := NsecStatus{}
	domainComponents := strings.Split(domain, ".")
	for nComponents := 1; nComponents <= len(domainComponents); nComponents++ {
		currentDomain := strings.Join(domainComponents[len(domainComponents)-nComponents:len(domainComponents)], ".")
		if currentDomain == "" {
			currentDomain = "."
		}
		// Dummy type to trigger the resolver to return NSEC records
		recordType := dns.TypeDS
		if nComponents == len(domainComponents) {
			recordType = qtype
		}
		rrSet, _, _, _, err := queryRRsetOrNsecRecords(currentDomain, dns.TypeNSEC3PARAM)
		if err != nil {
			status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
			status.errors = append(status.errors, err.Error())
		} else if !rrSet.IsEmpty() {
			_, ok := rrSet.rrSet[0].(*dns.NSEC3PARAM)
			if !ok {
				status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
				status.errors = append(status.errors, "wrong DNS type returned")
			} else {
				fmt.Println("NSEC3PARAM detected, checking for NSEC3 records")
				_, _, nsec3, _, err := queryRRsetOrNsecRecords(currentDomain, dns.TypeNSEC3)
				if err != nil {
					status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
					status.errors = append(status.errors, err.Error())
				} else if nsec3 != nil {
					err = nsec3.validate(dns.Type(dns.TypeNSEC3))
					if err != nil {
						status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
						status.errors = append(status.errors, err.Error())
					} else if nsec3.closestEncloserName == currentDomain {
						if nsec3.closestEncloserOptOut {
							status.nsec3OptOutDomains = append(status.nsec3OptOutDomains, currentDomain)
						} else {
							status.nsec3ProtectedDomains = append(status.nsec3ProtectedDomains, currentDomain)
						}
					} else {
						status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
					}
				}
			}
		} else {
			fmt.Println("no NSEC3PARAM detected, checking for NSEC records")
			nsecRecord, _, _, _, err := queryRRsetOrNsecRecords(currentDomain, dns.TypeNSEC)
			if err != nil {
				_, nsec, _, _, errDsRecord := queryRRsetOrNsecRecords(currentDomain, recordType)
				if errDsRecord != nil {
					status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
					status.errors = append(status.errors, errDsRecord.Error())
				} else if nsec == nil {
					status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
					status.errors = append(status.errors, "No NSEC record returned")
				} else {
					nsec.validate(dns.Type(dns.TypeDS))
					result := nsec.validationResult
					fmt.Printf("nsec validation (DS record): %s\n", nsec.validationResult)
					if nsec.validationResult == ValidationMissingNsecStatements {
						components := strings.Split(currentDomain, ".")
						wildcardDomain := strings.Join(append([]string{"*"}, components[1:]...), ".")
						if len(components) > 1 {
							_, nsecWildcard, _, _, errWildcardDsRecord := queryRRsetOrNsecRecords(wildcardDomain, recordType)
							if errWildcardDsRecord != nil {
								status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
								status.errors = append(status.errors, "Failed to fetch DS record for wildcard domain")
							} else {
								nsecMerged, err := mergeNsecRecords(nsec, nsecWildcard)
								if err != nil {
									status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
									status.errors = append(status.errors, "Failed to merge nsec and nsec (wildcard) records")
								} else {
									nsecMerged.findDomainAndWildcardRecords()
									nsecMerged.validate(dns.Type(dns.TypeDS))
									fmt.Printf("nsec validation (DS record + wildcard): %s\n", nsec.validationResult)
									result = nsecMerged.validationResult
								}
							}

						}
					}
					if result == ValidationNsecInexistantDomain {
						status.nsecProtectedDomains = append(status.nsecProtectedDomains, currentDomain)
					} else {
						status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
						status.errors = append(status.errors, "NSEC proof of absence could not be verified")
					}
				}
			} else {
				if nsecRecord.IsEmpty() {
					status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
					status.errors = append(status.errors, "No NSEC record was returned")
				} else if currentDomain == nsecRecord.rrSet[0].(*dns.NSEC).Header().Name {
					status.nsecProtectedDomains = append(status.nsecProtectedDomains, currentDomain)
				} else {
					status.unprotectedDomains = append(status.unprotectedDomains, currentDomain)
					status.errors = append(status.errors, "NSEC record was returned for wrong domain")

				}
			}
		}
	}
	return &status, nil
}

func formatResultRRs(signedRrset *RRSet) []net.IP {
	ips := make([]net.IP, 0, len(signedRrset.rrSet))
	for _, rr := range signedRrset.rrSet {
		switch t := rr.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}
	return ips
}
