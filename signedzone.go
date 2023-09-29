package goresolver

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Nsec struct {
	domain           string
	wildcardName     string
	nsecRecords      map[string]*RRSet
	domainRrSet      *RRSet
	wildcardRrSet    *RRSet
	validationType   dns.Type
	validationResult string
	validationProofs []*RRSet
}

type Nsec3 struct {
	domain                 string
	nsec3Records           map[string]*RRSet
	closestEncloserName    string
	closestEncloserOptOut  bool
	closestEncloserRrSet   *RRSet
	nextCloserName         string
	nextCloserRrSet        *RRSet
	wildcardName           string
	wildcardMatchRrSet     *RRSet
	wildcardCoverOnlyRrSet *RRSet
	validationType         dns.Type
	validationResult       string
	validationProofs       []*RRSet

	// fields for legacy validation
	parentMatch   *RRSet
	domainMatch   *RRSet
	domainCover   *RRSet
	wildcardMatch *RRSet
	wildcardCover *RRSet
}

const (
	ValidationNsecInexistantRecord            = "NSEC-INEXISTANT-RR"
	ValidationNsecInexistantDomain            = "NSEC-INEXISTANT-DOMAIN"
	ValidationNsecInexistantDomainWithOptOut  = "NSEC-INEXISTANT-DOMAIN-OPT-OUT"
	ValidationNsecRecordExists                = "NSEC-RR-EXISTS"
	ValidationInconsistentNsecStatements      = "NSEC-INCONSISTENT"
	ValidationMissingNsecStatements           = "NSEC-MISSING"
	ValidationMissingNsecStatementsWithOptOut = "NSEC-MISSING-OPT-OUT"
)

func mergeNsecRecords(nsec0, nsec1 *Nsec) (*Nsec, error) {
	if nsec0 == nil || nsec1 == nil {
		return nil, fmt.Errorf("Cannot merge non-existing records")
	}
	if nsec0.domain == nsec1.domain || nsec0.wildcardName == nsec1.domain || nsec0.domain == nsec1.wildcardName {
		domain := nsec0.domain
		if strings.HasPrefix(domain, "*.") {
			domain = nsec1.domain
		}
		merged := NewNsec(domain)
		for d, rrSet := range nsec0.nsecRecords {
			if _, ok := merged.nsecRecords[d]; !ok {
				merged.nsecRecords[d] = rrSet
			}
		}
		for d, rrSet := range nsec1.nsecRecords {
			if _, ok := merged.nsecRecords[d]; !ok {
				merged.nsecRecords[d] = rrSet
			}
		}
		return merged, nil
	} else {
		return nil, fmt.Errorf("Cannot merge nsec records (different domains)")
	}
}

func NewNsec(domain string) *Nsec {
	return &Nsec{
		domain:      domain,
		nsecRecords: map[string]*RRSet{},
	}
}

func nsecDomainLessThan(d0, d1 string) bool {
	d0Components := strings.Split(d0, ".")
	d1Components := strings.Split(d1, ".")
	for i := 0; i < min(len(d0Components), len(d1Components)); i++ {
		if d0Components[len(d0Components)-i-1] < d1Components[len(d1Components)-i-1] {
			return true
		} else if d0Components[len(d0Components)-i-1] > d1Components[len(d1Components)-i-1] {
			return false
		}
	}
	if len(d0Components) < len(d1Components) {
		return true
	} else if len(d0Components) > len(d1Components) {
		return false
	}
	return false
}

func nsecCover(domain string, nsecRecord *dns.NSEC) bool {
	startName := nsecRecord.Header().Name
	endName := nsecRecord.NextDomain
	if (startName == domain || nsecDomainLessThan(startName, domain)) &&
		nsecDomainLessThan(domain, endName) {
		return true
	} else {
		return false
	}
}

// finds the two relevant NSEC records as described in https://datatracker.ietf.org/doc/html/rfc7129#section-3.2: the domain and wildcard record.
func (n *Nsec) findDomainAndWildcardRecords() {
	domainComponents := strings.Split(n.domain, ".")
	parentName := strings.Join(domainComponents[1:], ".")
	n.wildcardName = strings.Join([]string{"*", parentName}, ".")

	for _, rrSet := range n.nsecRecords {
		rrNsec := rrSet.rrSet[0].(*dns.NSEC)
		if nsecCover(n.domain, rrNsec) {
			n.domainRrSet = rrSet
		}
		if nsecCover(n.wildcardName, rrNsec) {
			n.wildcardRrSet = rrSet
		}
	}
}

func (n *Nsec) validate(rrType dns.Type) error {
	n.validationType = rrType

	exactDomainMatch := n.domainRrSet != nil && n.domain == n.domainRrSet.rrSet[0].(*dns.NSEC).Header().Name

	if n.wildcardRrSet == nil {
		if n.domainRrSet == nil {
			n.validationResult = ValidationMissingNsecStatements
			return fmt.Errorf("No covering NSEC records found")
		} else if !exactDomainMatch {
			n.validationResult = ValidationMissingNsecStatements
			return fmt.Errorf("Wildcard NSEC record missing")
		} else {
			// if we match the domain exactly, there is no need for a wildcard NSEC record (the domain takes precedence over the wildcard due to the longer closest encloser)
		}
	}
	n.validationProofs = []*RRSet{n.domainRrSet}
	if n.wildcardRrSet != nil {
		n.validationProofs = append(n.validationProofs, n.wildcardRrSet)
	}

	wildcardMatch := n.wildcardRrSet != nil && n.wildcardName == n.wildcardRrSet.rrSet[0].(*dns.NSEC).Header().Name
	domainContainsRr := slices.Contains(n.domainRrSet.rrSet[0].(*dns.NSEC).TypeBitMap, uint16(rrType))
	wildcardContainsRr := wildcardMatch && n.wildcardRrSet != nil && slices.Contains(n.wildcardRrSet.rrSet[0].(*dns.NSEC).TypeBitMap, uint16(rrType))

	// TODO: could also detect other inconsistencies, e.g., multiple records covering the same domain

	if exactDomainMatch {
		if wildcardMatch {
			// check for matched RR types in domain and wildcard (+ check for conflicts)
			if domainContainsRr != wildcardContainsRr {
				n.validationResult = ValidationInconsistentNsecStatements
				return fmt.Errorf("Wildcard and domain NSEC records claim different state")
			} else {
				if domainContainsRr {
					n.validationResult = ValidationNsecRecordExists
				} else {
					n.validationResult = ValidationNsecInexistantRecord
				}
				return nil
			}
		} else {
			// check for matched RR types in domain
			if domainContainsRr {
				n.validationResult = ValidationNsecRecordExists
			} else {
				n.validationResult = ValidationNsecInexistantRecord
			}
			return nil
		}
	} else {
		if wildcardMatch {
			// check for matched RR types in wildcard
			if wildcardContainsRr {
				n.validationResult = ValidationNsecRecordExists
			} else {
				n.validationResult = ValidationNsecInexistantRecord
			}
			return nil
		} else {
			// neither domain nor wildcard matched
			n.validationResult = ValidationNsecInexistantDomain
			return nil
		}
	}
}

func NewNsec3(domain string) *Nsec3 {
	return &Nsec3{
		domain:       domain,
		nsec3Records: map[string]*RRSet{},
	}
}

func (n *Nsec) String() string {
	description := fmt.Sprintf("<NSEC %s %s: ", n.domain, n.validationResult)
	if n.domainRrSet != nil {
		description += "domain " + "(start=" + n.domainRrSet.rrSet[0].Header().Name + ", end=" + n.domainRrSet.rrSet[0].(*dns.NSEC).NextDomain + "), "
	}
	if n.wildcardRrSet != nil {
		description += "wildcard " + "(start=" + n.wildcardRrSet.rrSet[0].Header().Name + ", end=" + n.wildcardRrSet.rrSet[0].(*dns.NSEC).NextDomain + "), "
	}
	// description += "NSEC records: ["
	// isFirst := true
	// for _, rrSet := range n.nsecRecords {
	// 	if !isFirst {
	// 		description += ", "
	// 	}
	// 	isFirst = false
	// 	description += fmt.Sprintf("%v, ", rrSet.rrSet[0])
	// }
	// description += "]"
	description += ">"
	return description
}

func (n *Nsec3) String() string {
	description := fmt.Sprintf("<NSEC3 %s %s: ", n.domain, n.validationResult)
	if n.closestEncloserRrSet != nil {
		options := ""
		if n.closestEncloserRrSet.rrSet[0].(*dns.NSEC3).Flags&(1<<0) != 0 {
			options += "[OPT-OUT] "
		}
		description += "closest encloser " + options + "(domain=" + n.closestEncloserName + ", hash=" + n.closestEncloserRrSet.rrSet[0].Header().Name + ", "
		for _, t := range n.closestEncloserRrSet.rrSet[0].(*dns.NSEC3).TypeBitMap {
			description += " " + dns.Type(t).String()
		}
		description += ")"

		if n.nextCloserRrSet != nil {
			description += ", !∃ next closer name (domain=" + n.nextCloserName + ", hash=" + n.nextCloserRrSet.rrSet[0].Header().Name + ")"
		}

		if n.wildcardMatchRrSet != nil {
			description += ", ∃ wildcard (domain=" + n.wildcardName + ", hash=" + n.wildcardMatchRrSet.rrSet[0].Header().Name + ", "
			for _, t := range n.wildcardMatchRrSet.rrSet[0].(*dns.NSEC3).TypeBitMap {
				description += " " + dns.Type(t).String()
			}
			description += ")"
		}

		if n.wildcardCoverOnlyRrSet != nil {
			description += ", !∃ wildcard (domain=" + n.wildcardName + ", hash=" + n.wildcardCoverOnlyRrSet.rrSet[0].Header().Name + ")"
		}
	}
	description += ">"
	return description
}

// finds the three relevant NSEC3 records as described in https://datatracker.ietf.org/doc/html/rfc7129#section-5.5: the closest encloser, the next closer name, and the wildcard name. Returns false if no encloser exists.
func (n *Nsec3) findClosestEncloserWithRelevantRecords() bool {
	// find closest encloser (domain + RRSet)
	domainComponents := strings.Split(n.domain, ".")
	var nextCloserName string
	var wildcardName string
validate:
	for nComponents := len(domainComponents); nComponents >= 2; nComponents-- {
		currentDomain := strings.Join(domainComponents[len(domainComponents)-nComponents:], ".")
		for _, rrSet := range n.nsec3Records {
			rrNsec3 := rrSet.rrSet[0].(*dns.NSEC3)
			if rrNsec3.Match(currentDomain) {
				n.closestEncloserName = currentDomain
				n.closestEncloserOptOut = rrNsec3.Flags&(1<<0) != 0
				if nComponents < len(domainComponents) {
					nextCloserName = strings.Join(domainComponents[len(domainComponents)-nComponents-1:], ".")
				}
				wildcardName = strings.Join([]string{"*", n.closestEncloserName}, ".")
				n.closestEncloserRrSet = rrSet
				break validate
			}
		}
	}
	if n.closestEncloserName == "" {
		// did not find any encloser NSEC record
		return false
	}

	// TODO: this is currently not looking at inconsistencies in nsec records, i.e., once we found a match/cover nsec3 record, we simply accept it
	for _, rrSet := range n.nsec3Records {
		rrNsec3 := rrSet.rrSet[0].(*dns.NSEC3)
		if rrNsec3.Cover(nextCloserName) {
			n.nextCloserName = nextCloserName
			n.nextCloserRrSet = rrSet
			break
		}
	}
	for _, rrSet := range n.nsec3Records {
		rrNsec3 := rrSet.rrSet[0].(*dns.NSEC3)
		if rrNsec3.Match(wildcardName) {
			n.wildcardName = wildcardName
			n.wildcardMatchRrSet = rrSet
			break
		} else if rrNsec3.Cover(wildcardName) {
			n.wildcardName = wildcardName
			n.wildcardCoverOnlyRrSet = rrSet
			break
		}
	}
	return true
}

func (n *Nsec3) validate(rrType dns.Type) error {
	n.validationType = rrType
	// TODO: don't use direct parent, look for possible parents in all NSEC3 records
	encloserExists := n.closestEncloserName != ""

	var exactDomainMatch bool
	// check if all necessary nsec records exist, otherwise return an error
	if !encloserExists {
		n.validationResult = ValidationMissingNsecStatements
		return fmt.Errorf("No encloser NSEC3 record found")
	}

	if n.closestEncloserName == n.domain {
		exactDomainMatch = true
		// an NSEC3 record for the domain is found, continue processing
	} else if n.nextCloserRrSet == nil {
		if n.closestEncloserOptOut {
			n.validationResult = ValidationMissingNsecStatementsWithOptOut
		} else {
			n.validationResult = ValidationMissingNsecStatements
		}
		return fmt.Errorf("No NSEC3 record covers the domain")
	} else if n.wildcardMatchRrSet == nil && n.wildcardCoverOnlyRrSet == nil {
		if n.closestEncloserOptOut {
			n.validationResult = ValidationMissingNsecStatementsWithOptOut
		} else {
			n.validationResult = ValidationMissingNsecStatements
		}
		return fmt.Errorf("No NSEC3 record covers/matches the wildcard domain")
	}

	// TODO: could also detect other inconsistencies, e.g., multiple records covering the same domain
	if n.wildcardMatchRrSet != nil && n.wildcardCoverOnlyRrSet != nil {
		n.validationResult = ValidationInconsistentNsecStatements
		return fmt.Errorf("The target's wildcard domain is both matched and covered with different NSEC3 records")
	}

	domainContainsRr := slices.Contains(n.closestEncloserRrSet.rrSet[0].(*dns.NSEC3).TypeBitMap, uint16(rrType))
	wildcardContainsRr := n.wildcardMatchRrSet != nil && slices.Contains(n.wildcardMatchRrSet.rrSet[0].(*dns.NSEC3).TypeBitMap, uint16(rrType))
	if exactDomainMatch {
		if n.wildcardMatchRrSet != nil {
			// check for matched RR types in domain and wildcard (+ check for conflicts)
			if domainContainsRr != wildcardContainsRr {
				n.validationResult = ValidationInconsistentNsecStatements
				n.validationProofs = []*RRSet{n.closestEncloserRrSet, n.wildcardMatchRrSet}
				return fmt.Errorf("Wildcard and domain NSEC3 records claim different state")
			} else {
				if domainContainsRr {
					n.validationResult = ValidationNsecRecordExists
				} else {
					n.validationResult = ValidationNsecInexistantRecord
				}
				n.validationProofs = []*RRSet{n.closestEncloserRrSet, n.wildcardMatchRrSet}
				return nil
			}
		} else {
			// check for matched RR types in domain
			if domainContainsRr {
				n.validationResult = ValidationNsecRecordExists
			} else {
				n.validationResult = ValidationNsecInexistantRecord
			}
			n.validationProofs = []*RRSet{n.closestEncloserRrSet, n.wildcardCoverOnlyRrSet}
			return nil
		}
	} else {
		if n.wildcardMatchRrSet != nil {
			// check for matched RR types in wildcard
			if wildcardContainsRr {
				n.validationResult = ValidationNsecRecordExists
			} else {
				n.validationResult = ValidationNsecInexistantRecord
			}
			n.validationProofs = []*RRSet{n.closestEncloserRrSet, n.nextCloserRrSet, n.wildcardMatchRrSet}
			return nil
		} else {
			// neither domain nor wildcard matched
			if n.closestEncloserOptOut {
				n.validationResult = ValidationNsecInexistantDomainWithOptOut
				n.validationProofs = []*RRSet{n.closestEncloserRrSet, n.nextCloserRrSet, n.wildcardCoverOnlyRrSet}
			} else {
				n.validationResult = ValidationNsecInexistantDomain
				n.validationProofs = []*RRSet{n.closestEncloserRrSet, n.nextCloserRrSet, n.wildcardCoverOnlyRrSet}
			}
			return nil
		}
	}
}

func (n *Nsec3) validateOld(rrType dns.Type) error {
	n.validationType = rrType
	parentDomain := strings.Join(strings.Split(n.domain, ".")[1:], ".")
	wildcardDomain := strings.Join([]string{"*", parentDomain}, ".")
	for _, rrSet := range n.nsec3Records {
		rrNsec3 := rrSet.rrSet[0].(*dns.NSEC3)
		domainMatch := rrNsec3.Match(n.domain)
		domainCover := !domainMatch && rrNsec3.Cover(n.domain)
		parentMatch := rrNsec3.Match(parentDomain)
		wildcardMatch := rrNsec3.Match(wildcardDomain)
		wildcardCover := !wildcardMatch && rrNsec3.Cover(wildcardDomain)
		if domainCover {
			if n.domainCover != nil || n.domainMatch != nil {
				n.validationResult = ValidationInconsistentNsecStatements
				n.validationProofs = []*RRSet{n.domainCover, n.domainMatch, rrSet}
				return fmt.Errorf("Multiple NSEC3 records cover/match the target domain")
			}
			n.domainCover = rrSet
		}
		if domainMatch {
			if n.domainCover != nil || n.domainMatch != nil {
				n.validationResult = ValidationInconsistentNsecStatements
				n.validationProofs = []*RRSet{n.domainCover, n.domainMatch, rrSet}
				return fmt.Errorf("Multiple NSEC3 records cover/match the target domain")
			}
			n.domainMatch = rrSet
		}
		if parentMatch {
			if n.parentMatch != nil {
				// TODO: should not actually be possible since the hash would then collide...
				n.validationResult = ValidationInconsistentNsecStatements
				n.validationProofs = []*RRSet{n.parentMatch, rrSet}
				return fmt.Errorf("Multiple NSEC3 records match the target's parent domain")
			}
			n.parentMatch = rrSet
		}
		if wildcardCover {
			if n.wildcardCover != nil || n.wildcardMatch != nil {
				n.validationResult = ValidationInconsistentNsecStatements
				n.validationProofs = []*RRSet{n.wildcardCover, n.wildcardMatch, rrSet}
				return fmt.Errorf("Multiple NSEC3 records cover/match the target's wildcard domain")
			}
			n.wildcardCover = rrSet
		}
		if wildcardMatch {
			if n.wildcardCover != nil || n.wildcardMatch != nil {
				n.validationResult = ValidationInconsistentNsecStatements
				n.validationProofs = []*RRSet{n.wildcardCover, n.wildcardMatch, rrSet}
				return fmt.Errorf("Multiple NSEC3 records cover/match the target's wildcard domain")
			}
			n.wildcardMatch = rrSet
		}
	}

	if n.parentMatch == nil {
		n.validationResult = ValidationMissingNsecStatements
		return fmt.Errorf("The parent's NSEC3 record is missing")
	}
	if n.domainMatch == nil && n.domainCover == nil {
		n.validationResult = ValidationMissingNsecStatements
		return fmt.Errorf("No NSEC3 record covers/matches the domain")
	}
	if n.domainMatch == nil && n.wildcardMatch == nil && n.wildcardCover == nil {
		n.validationResult = ValidationMissingNsecStatements
		return fmt.Errorf("No NSEC3 record covers/matches the wildcard domain")
	}

	// assertions added just for clarity (should already be covered by previous error statements)
	if n.domainCover != nil && n.domainMatch != nil {
		log.Panic("Invalid state detected (should never reach here)")
	}
	if n.wildcardCover != nil && n.wildcardMatch != nil {
		log.Panic("Invalid state detected (should never reach here)")
	}

	if n.domainCover != nil && n.wildcardCover != nil {
		// neither domain nor wildcard exists
		n.validationResult = ValidationNsecInexistantDomain
		n.validationProofs = []*RRSet{n.domainCover, n.wildcardCover}
		return nil
	}

	// look at NSEC3 records
	rrContainedInDomainNsecRecord := n.domainMatch != nil && slices.Contains(n.domainMatch.rrSet[0].(*dns.NSEC3).TypeBitMap, uint16(rrType))
	rrNotContainedInDomainNsecRecord := n.domainMatch != nil && !slices.Contains(n.domainMatch.rrSet[0].(*dns.NSEC3).TypeBitMap, uint16(rrType))
	rrContainedInWildcardNsecRecord := n.wildcardMatch != nil && slices.Contains(n.wildcardMatch.rrSet[0].(*dns.NSEC3).TypeBitMap, uint16(rrType))
	rrNotContainedInWildcardNsecRecord := n.wildcardMatch != nil && !slices.Contains(n.wildcardMatch.rrSet[0].(*dns.NSEC3).TypeBitMap, uint16(rrType))
	// TODO: check all entries not just the first one to detect inconsistencies
	if false ||
		(rrContainedInDomainNsecRecord && rrContainedInWildcardNsecRecord) ||
		(rrContainedInDomainNsecRecord && n.wildcardCover != nil) ||
		(n.domainCover != nil && rrContainedInWildcardNsecRecord) {
		// domain exists and should provide the RR
		n.validationResult = ValidationNsecRecordExists
		n.validationProofs = []*RRSet{n.domainMatch, n.wildcardMatch, n.domainCover, n.wildcardCover}
		return nil
	}

	if false ||
		(rrNotContainedInDomainNsecRecord && rrNotContainedInWildcardNsecRecord) ||
		(rrNotContainedInDomainNsecRecord && n.wildcardCover != nil) ||
		(n.domainCover != nil && rrNotContainedInWildcardNsecRecord) {
		// domain exists but does not provide the RR
		n.validationResult = ValidationNsecInexistantRecord
		n.validationProofs = []*RRSet{n.domainMatch, n.wildcardMatch, n.domainCover, n.wildcardCover}
		return nil
	}

	if false ||
		(rrContainedInDomainNsecRecord && rrNotContainedInWildcardNsecRecord) ||
		(rrNotContainedInDomainNsecRecord && rrContainedInWildcardNsecRecord) {
		// two NSEC records with conflicting statements
		n.validationResult = ValidationInconsistentNsecStatements
		n.validationProofs = []*RRSet{n.domainMatch, n.wildcardMatch}
		return fmt.Errorf("Wildcard and domain NSEC3 records claim different state")
	}

	if rrNotContainedInDomainNsecRecord && rrNotContainedInWildcardNsecRecord {
		n.validationResult = ValidationNsecInexistantRecord
		n.validationProofs = []*RRSet{n.domainMatch, n.wildcardMatch}
	}
	if rrNotContainedInDomainNsecRecord && n.wildcardCover != nil {
		n.validationResult = ValidationNsecInexistantRecord
		n.validationProofs = []*RRSet{n.domainMatch, n.wildcardCover}
	}
	if n.domainCover != nil && rrNotContainedInWildcardNsecRecord {
		n.validationResult = ValidationNsecInexistantRecord
		n.validationProofs = []*RRSet{n.domainCover, n.wildcardMatch}
	}
	return nil
}

// SignedZone represents a DNSSEC-enabled zone, its DNSKEY and DS records
type SignedZone struct {
	zone          string
	dnskey        *RRSet
	ds            *RRSet
	parentZone    *SignedZone
	pubKeyLookup  map[uint16]*dns.DNSKEY
	nsec          *RRSet
	nsec3         *RRSet
	dsNsecStruct  *Nsec
	dsNsec3Struct *Nsec3
	nsec3param    *RRSet
}

func (z SignedZone) String() string {
	records := []string{}
	if z.dnskey != nil && !z.dnskey.IsEmpty() {
		records = append(records, "DNSKEY")
	}
	if z.ds != nil && !z.ds.IsEmpty() {
		records = append(records, "DS")
	}
	if z.dsNsec3Struct != nil {
		records = append(records, "NSEC3 (DS)")
	}
	description := fmt.Sprintf("<Zone %s: %s>", z.zone, strings.Join(records, ", "))
	return description
}

// lookupPubkey returns a DNSKEY by its keytag
func (z SignedZone) lookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.pubKeyLookup[keyTag]
}

// addPubkey stores a DNSKEY in the keytag lookup table.
func (z SignedZone) addPubKey(k *dns.DNSKEY) {
	z.pubKeyLookup[k.KeyTag()] = k
}

// verifyRRSIG verifies the signature on a signed
// RRSET, and checks the validity period on the RRSIG.
// It returns nil if the RRSIG verifies and the signature
// is valid, and the appropriate error value in case
// of validation failure.
func (z SignedZone) verifyRRSIG(signedRRset *RRSet) (err error) {

	if !signedRRset.IsSigned() {
		return ErrInvalidRRsig
	}

	// Verify the RRSIG of the DNSKEY RRset
	key := z.lookupPubKey(signedRRset.rrSig.KeyTag)
	if key == nil {
		log.Printf("DNSKEY keytag %d not found", signedRRset.rrSig.KeyTag)
		return ErrDnskeyNotAvailable
	}

	err = signedRRset.rrSig.Verify(key, signedRRset.rrSet)
	if err != nil {
		log.Println("DNSKEY verification", err)
		return err
	}

	if !signedRRset.rrSig.ValidityPeriod(time.Now()) {
		log.Println("invalid validity period", err)
		return ErrRrsigValidityPeriod
	}
	return nil
}

// verifyDS validates the DS record against the KSK
// (key signing key) of the zone.
// Return nil if the DS record matches the digest of
// the KSK.
func (z SignedZone) verifyDS(dsRrset []dns.RR) (err error) {

	for _, rr := range dsRrset {

		ds := rr.(*dns.DS)

		if ds.DigestType != dns.SHA256 {
			log.Printf("Unknown digest type (%d) on DS RR", ds.DigestType)
			continue
		}

		parentDsDigest := strings.ToUpper(ds.Digest)
		key := z.lookupPubKey(ds.KeyTag)
		if key == nil {
			log.Printf("DNSKEY keytag %d not found", ds.KeyTag)
			return ErrDnskeyNotAvailable
		}
		dsDigest := strings.ToUpper(key.ToDS(ds.DigestType).Digest)
		if parentDsDigest == dsDigest {
			return nil
		}

		log.Printf("DS does not match DNSKEY\n")
		return ErrDsInvalid
	}
	return ErrUnknownDsDigestType
}

// checkHasDnskeys returns true if the SignedZone has a DNSKEY
// record, false otherwise.
func (z *SignedZone) checkHasDnskeys() bool {
	return len(z.dnskey.rrSet) > 0
}

// NewSignedZone initializes a new SignedZone and returns it.
func NewSignedZone(domainName string) *SignedZone {
	return &SignedZone{
		zone:   domainName,
		ds:     &RRSet{},
		dnskey: &RRSet{},
	}
}
