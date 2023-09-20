package goresolver

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

type RRSet struct {
	domain string
	rrSet  []dns.RR
	rrSig  *dns.RRSIG
}

func queryRRset(qname string, qtype uint16) (*RRSet, error) {
	answerRrSet, _, err := queryRRsets(qname, qtype, false)
	return answerRrSet, err
}

func queryRRsetOrNsecRecords(qname string, qtype uint16) (*RRSet, *Nsec, *Nsec3, error) {
	answerRrSet, authoritativeRrSets, err := queryRRsets(qname, qtype, true)
	if !answerRrSet.IsEmpty() {
		return answerRrSet, nil, nil, err
	} else {
		// no record found, check if record is supposed to exist (via NSEC or NSEC3)
		nsec3RecordsExist := false
		nsec3 := NewNsec3(qname)
		for domain, rrSets := range authoritativeRrSets {
			if rr, ok := rrSets[dns.Type(dns.TypeNSEC3)]; ok {
				nsec3RecordsExist = true
				nsec3.nsec3Records[domain] = rr
			}
		}
		if nsec3RecordsExist {
			err := nsec3.validate(dns.Type(qtype))
			fmt.Printf("Validation of NSEC3 records resulted in %s (error=\"%s\", status=%s)\n", nsec3.validationResult, err, nsec3)
			if err != nil {
				fmt.Printf("Error in NSEC3 validation: %s (status=%s)", err, nsec3)
				return answerRrSet, nil, nsec3, err
			}
			result := nsec3.validationResult
			if result == ValidationNsecRecordExists || result == ValidationMissingNsecStatements || result == ValidationInconsistentNsecStatements {
				return answerRrSet, nil, nsec3, fmt.Errorf("%s record was not returned but should exist according to NSEC3 record: %v", dns.TypeToString[qtype], nsec3)
			}
		}

		// TODO: fix return statement
		log.Panic("stop")
		return nil, nil, nil, nil
	}
}

func queryRRsets(qname string, qtype uint16, includeAuthoritative bool) (*RRSet, map[string]map[dns.Type]*RRSet, error) {

	r, err := resolver.queryFn(qname, qtype)
	FetchedMessages = append(FetchedMessages, FetchedMessage{
		Qname:   qname,
		Qtype:   dns.TypeToString[qtype],
		Message: r,
	})

	if err != nil {
		log.Printf("cannot lookup %v", err)
		return nil, nil, err
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s -> ignoring for now since NSEC records may exist\n", qname)
		// return nil, nil, ErrNoResult
	}

	// answer section
	result := NewSignedRRSet()
	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			result.addSignature(t)
		default:
			if rr != nil {
				result.addRR(rr)
			}
		}
		FetchedRecords = append(FetchedRecords, FetchedRecord{
			Qname:  qname,
			Qtype:  dns.TypeToString[qtype],
			Record: rr,
		})
	}

	// authority section
	var authoritativeRrSets map[string]map[dns.Type]*RRSet
	if includeAuthoritative {
		rrSets := map[string]map[dns.Type]*RRSet{}
		for _, rr := range r.Ns {
			nameRrSets, ok := rrSets[rr.Header().Name]
			if !ok {
				nameRrSets = make(map[dns.Type]*RRSet)
				rrSets[rr.Header().Name] = nameRrSets
			}
			switch t := rr.(type) {
			case *dns.RRSIG:
				rrSet, ok := nameRrSets[dns.Type(t.TypeCovered)]
				if !ok {
					rrSet = NewSignedRRSet()
					nameRrSets[dns.Type(t.TypeCovered)] = rrSet
				}
				rrSet.addSignature(t)
			default:
				if rr != nil {
					rrSet, ok := nameRrSets[dns.Type(rr.Header().Rrtype)]
					if !ok {
						rrSet = NewSignedRRSet()
						nameRrSets[dns.Type(rr.Header().Rrtype)] = rrSet
					}
					rrSet.addRR(rr)
				}
			}
			FetchedRecords = append(FetchedRecords, FetchedRecord{
				Qname:  qname,
				Qtype:  dns.TypeToString[qtype],
				Record: rr,
			})
		}
		authoritativeRrSets = rrSets
	}

	return result, authoritativeRrSets, nil
}

func (sRRset *RRSet) IsSigned() bool {
	return sRRset.rrSig != nil
}

func (sRRset *RRSet) IsEmpty() bool {
	return len(sRRset.rrSet) < 1
}

func (sRRset *RRSet) SignerName() string {
	return sRRset.rrSig.SignerName
}

func (sRRset *RRSet) addRR(rr dns.RR) error {
	sRRset.rrSet = append(sRRset.rrSet, rr)
	return sRRset.addDomain(rr.Header().Name)
}

func (sRRset *RRSet) addDomain(domain string) error {
	if sRRset.domain != "" && sRRset.domain != domain {
		return fmt.Errorf("Assigning a different domain")
	}
	sRRset.domain = domain
	return nil
}

func (sRRset *RRSet) addSignature(signature *dns.RRSIG) error {
	if sRRset.rrSig != nil {
		return fmt.Errorf("Overriding signature")
	}
	sRRset.rrSig = signature
	return nil
}

func NewSignedRRSet() *RRSet {
	return &RRSet{
		rrSet: make([]dns.RR, 0),
	}
}
