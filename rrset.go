package goresolver

import (
	"log"

	"github.com/miekg/dns"
)

type RRSet struct {
	rrSet []dns.RR
	rrSig *dns.RRSIG
}

func queryRRset(qname string, qtype uint16) (*RRSet, error) {

	r, err := resolver.queryFn(qname, qtype)
	FetchedMessages = append(FetchedMessages, FetchedMessage{
		Qname:   qname,
		Qtype:   dns.TypeToString[qtype],
		Message: r,
	})

	if err != nil {
		log.Printf("cannot lookup %v", err)
		return nil, err
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s\n", qname)
		return nil, ErrNoResult
	}

	result := NewSignedRRSet()

	if r.Answer == nil {
		return result, nil
	}

	result.rrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			result.rrSig = t
		default:
			if rr != nil {
				result.rrSet = append(result.rrSet, rr)
			}
		}
		FetchedRecords = append(FetchedRecords, FetchedRecord{
			Qname:  qname,
			Qtype:  dns.TypeToString[qtype],
			Record: rr,
		})
	}
	return result, nil
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

func NewSignedRRSet() *RRSet {
	return &RRSet{
		rrSet: make([]dns.RR, 0),
	}
}
