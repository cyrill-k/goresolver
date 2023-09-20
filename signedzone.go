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
	nsecRecords map[string]*RRSet
	inclusion   *RRSet
	parent      *RRSet
}

type Nsec3 struct {
	domain           string
	nsec3Records     map[string]*RRSet
	parentMatch      *RRSet
	domainMatch      *RRSet
	domainCover      *RRSet
	wildcardMatch    *RRSet
	wildcardCover    *RRSet
	validationType   dns.Type
	validationResult string
	validationProofs []*RRSet
}

const (
	ValidationNsecInexistantRecord       = "NSEC-INEXISTANT-RR"
	ValidationNsecInexistantDomain       = "NSEC-INEXISTANT-DOMAIN"
	ValidationNsecRecordExists           = "NSEC-RR-EXISTS"
	ValidationInconsistentNsecStatements = "NSEC-INCONSISTENT"
	ValidationMissingNsecStatements      = "NSEC-MISSING"
)

// NewSignedZone initializes a new SignedZone and returns it.
func NewNsec3(domain string) *Nsec3 {
	return &Nsec3{
		domain:       domain,
		nsec3Records: map[string]*RRSet{},
	}
}

func (n *Nsec3) String() string {
	description := fmt.Sprintf("<NSEC3 %s (%s): ", n.domain, n.validationResult)
	isFirst := true
	if n.domainMatch != nil {
		if !isFirst {
			description += ", "
		}
		isFirst = false
		description += "∃ domain (hash=" + n.domainMatch.rrSet[0].Header().Name + ", "
		for _, t := range n.domainMatch.rrSet[0].(*dns.NSEC3).TypeBitMap {
			description += " " + dns.Type(t).String()
		}
		description += ")"
	}
	if n.domainCover != nil {
		if !isFirst {
			description += ", "
		}
		isFirst = false
		description += "!∃ domain (hash=" + n.domainCover.rrSet[0].Header().Name + ")"
	}
	if n.wildcardMatch != nil {
		if !isFirst {
			description += ", "
		}
		isFirst = false
		description += "∃ wildcard (hash=" + n.wildcardMatch.rrSet[0].Header().Name + ", "
		for _, t := range n.wildcardMatch.rrSet[0].(*dns.NSEC3).TypeBitMap {
			description += " " + dns.Type(t).String()
		}
		description += ")"
	}
	if n.wildcardCover != nil {
		if !isFirst {
			description += ", "
		}
		isFirst = false
		description += "!∃ wildcard (hash=" + n.wildcardCover.rrSet[0].Header().Name + ")"
	}
	description += ">"
	return description
}

func (n *Nsec3) validate(rrType dns.Type) error {
	n.validationType = rrType
	// TODO: don't use direct parent, look for possible parents in all NSEC3 records

	// TODO: first push existing changes and remove this todo!!!!
	// find closest encloser (domain + RRSet)
	// closestEncloserName := ...

	// check if next closer name exists (if it must exist)
	// nextCloserName := ...

	// check if wildcard domaine exists (if it must exist)
	// wilcardName := ...

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
	zone         string
	dnskey       *RRSet
	ds           *RRSet
	parentZone   *SignedZone
	pubKeyLookup map[uint16]*dns.DNSKEY
	nsec         *RRSet
	nsec3        *RRSet
	nsecStruct   *Nsec
	nsec3Struct  *Nsec3
	nsec3param   *RRSet
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
