package goresolver

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

// Populate queries the RRs required for the zone validation
// It begins the queries at the *domainName* zone and then walks
// up the delegation tree all the way up to the root zone, thus
// populating a linked list of SignedZone objects. Also include
// NSEC records if necessary.
func (authChain *AuthenticationChain) PopulateWithNsec(domainName string) error {

	qnameComponents := strings.Split(domainName, ".")
	zonesToVerify := len(qnameComponents)
	if zonesToVerify < 0 {
		zonesToVerify = 0
	}
	authChain.delegationChain = []SignedZone{}
	for i := zonesToVerify - 1; i >= 0; i-- {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))

		delegation, err := queryDelegation(zoneName)
		if err != nil {
			return err
		}

		if i < zonesToVerify-1 {
			delegation.parentZone = &authChain.delegationChain[0]
		}
		authChain.delegationChain = append([]SignedZone{*delegation}, authChain.delegationChain...)
	}
	return nil
}

// Verify uses the zone data in delegationChain to validate the DNSSEC
// chain of trust.
// It starts the verification in the RRSet supplied as parameter (verifies
// the RRSIG on the answer RRs), and, assuming a signature is correct and
// valid, it walks through the delegationChain checking the RRSIGs on
// the DNSKEY and DS resource record sets, as well as correctness of each
// delegation using the lower level methods in SignedZone. Also verify NSEC
// records if present.
func (authChain *AuthenticationChain) VerifyWithNsec(domainName string) error {
	if len(authChain.delegationChain) == 0 {
		return ErrDnskeyNotAvailable
	}

	for i := len(authChain.delegationChain) - 1; i >= 0; i-- {
		signedZone := authChain.delegationChain[i]
		fmt.Println(signedZone)

		if signedZone.dnskey.IsEmpty() {
		} else {
			// Verify the RRSIG of the DNSKEY RRset with the public KSK.
			err := signedZone.verifyRRSIG(signedZone.dnskey)
			if err != nil {
				return ErrRrsigValidationError
			}
		}

		if signedZone.parentZone != nil {
			if signedZone.ds.IsEmpty() {
				if signedZone.dsNsec3Struct != nil {

					err := signedZone.dsNsec3Struct.validate(dns.Type(dns.TypeDS))
					if err != nil {
						return err
					}
					result := signedZone.dsNsec3Struct.validationResult
					if false ||
						result == ValidationNsecRecordExists ||
						result == ValidationMissingNsecStatements ||
						result == ValidationMissingNsecStatementsWithOptOut ||
						result == ValidationInconsistentNsecStatements {
						return fmt.Errorf("%s (NSEC3=%s)", ErrDsNotAvailable, result)
					} else {
						return nil
					}
				}
				return ErrDsNotAvailable
			}

			err := signedZone.parentZone.verifyRRSIG(signedZone.ds)
			if err != nil {
				log.Printf("DS on %s doesn't validate against RRSIG %d\n", signedZone.zone, signedZone.ds.rrSig.KeyTag)
				return ErrRrsigValidationError
			}
			err = signedZone.verifyDS(signedZone.ds.rrSet)
			if err != nil {
				log.Printf("DS does not validate: %s", err)
				return ErrDsInvalid
			}
		}
	}
	return nil
}
