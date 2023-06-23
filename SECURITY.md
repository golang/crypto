# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
decliet



 Types ¶
type Certificate ¶
type Certificate struct {
	// Certificate is the parsed certificate
	X509 *x509.Certificate
	// Constraints contains a list of additional constraints that should be
	// applied to any certificates that chain to Certificate. If there are
	// any unknown constraints in the slice, Certificate should not be
	// trusted.
	Constraints []Constraint
}
A Certificate represents a single trusted serverAuth certificate in the NSS certdata.txt list and any constraints that should be applied to chains rooted by it.

func Parse ¶
func Parse(r io.Reader) ([]*Certificate, error)
Parse parses a NSS certdata.txt formatted file, returning only trusted serverAuth roots, as well as any additional constraints. This parser is very opinionated, only returning roots that are currently trusted for serverAuth. As such roots returned by this package should only be used for making trust decisions about serverAuth certificates, as the trust status for other uses is not considered. Using the roots returned by this package for trust decisions should be done carefully.

Some roots returned by the parser may include additional constraints (currently only DistrustAfter) which need to be considered when verifying certificates which chain to them.

Parse is not intended to be a general purpose parser for certdata.txt.

type Constraint ¶
type Constraint interface {
	Kind() Kind
}
Constraint is a constraint to be applied to a certificate or certificate chain.

type DistrustAfter ¶
type DistrustAfter time.Time
DistrustAfter is a Constraint that indicates a certificate has a CKA_NSS_SERVER_DISTRUST_AFTER constraint. This constraint defines a date after which any certificate issued which is rooted by the constrained certificate should be distrusted.

func (DistrustAfter) Kind ¶
func (DistrustAfter) Kind() Kind
type Kind ¶
type Kind int
Kind is the constraint kind, using the NSS enumeration
