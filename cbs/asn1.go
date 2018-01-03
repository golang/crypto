package cbs

type ASN1Tag byte

const (
	// // The following values are tag numbers for UNIVERSAL elements.
	ASN1_BOOLEAN         ASN1Tag = '\x01'
	ASN1_INTEGER         ASN1Tag = '\x02'
	ASN1_BITSTRING       ASN1Tag = '\x03'
	ASN1_OCTETSTRING     ASN1Tag = '\x04'
	ASN1_NULL            ASN1Tag = '\x05'
	ASN1_OBJECT          ASN1Tag = '\x06'
	ASN1_ENUMERATED      ASN1Tag = '\x0a'
	ASN1_UTF8STRING      ASN1Tag = '\x0c'
	ASN1_SEQUENCE        ASN1Tag = ('\x10' | ASN1_CONSTRUCTED)
	ASN1_SET             ASN1Tag = ('\x11' | ASN1_CONSTRUCTED)
	ASN1_NUMERICSTRING   ASN1Tag = '\x12'
	ASN1_PRINTABLESTRING ASN1Tag = '\x13'
	ASN1_T61STRING       ASN1Tag = '\x14'
	ASN1_VIDEOTEXSTRING  ASN1Tag = '\x15'
	ASN1_IA5STRING       ASN1Tag = '\x16'
	ASN1_UTCTIME         ASN1Tag = '\x17'
	ASN1_GENERALIZEDTIME ASN1Tag = '\x18'
	ASN1_GRAPHICSTRING   ASN1Tag = '\x19'
	ASN1_VISIBLESTRING   ASN1Tag = '\x1a'
	ASN1_GENERALSTRING   ASN1Tag = '\x1b'
	ASN1_UNIVERSALSTRING ASN1Tag = '\x1c'
	ASN1_BMPSTRING       ASN1Tag = '\x1e'

	// ASN1_CONSTRUCTED may be ORed into a tag to toggle the constructed
	// bit. |CBS| and |CBB| APIs consider the constructed bit to be part of the
	// tag.
	ASN1_CONSTRUCTED ASN1Tag = '\x20'

	// The following values specify the constructed bit or tag class and may be ORed
	// into a tag number to produce the final tag. If none is used, the tag will be
	// UNIVERSAL.
	//
	// Note that although they currently match the DER serialization, consumers must
	// use these bits rather than make assumptions about the representation. This is
	// to allow for tag numbers beyond 31 in the future.
	ASN1_APPLICATION      ASN1Tag = '\x40'
	ASN1_CONTEXT_SPECIFIC ASN1Tag = '\x80'
	ASN1_PRIVATE          ASN1Tag = '\xc0'

	// ASN1_CLASS_MASK may be ANDed with a tag to query its class.
	ASN1_CLASS_MASK ASN1Tag = '\xc0'

	// ASN1_TAG_NUMBER_MASK may be ANDed with a tag to query its number.
	ASN1_TAG_NUMBER_MASK ASN1Tag = '\x1f'
)

func (bs *ByteString) getAnyASN1Element() (*ByteString, ASN1Tag, int) {
	hdr := bs.Clone()
	tag := ASN1Tag(hdr.GetU8())
	if (tag & '\x1f') == '\x1f' {
		panic("parser only supports tag numbers < 31")
	}

	switch {
	case (hdr.PeekU8() & '\x80') == 0:
		return bs.Get(int(hdr.PeekU8() + 2)), tag, 2
	case hdr.PeekU8() == '\x80':
		panic("ber,cer not supported")
	case hdr.PeekU8() == '\xff':
		panic("reserved")
	}

	// definite long
	lenLen := hdr.GetU8() & '\x7f'
	if lenLen > 4 {
		panic("too big")
	}
	len := hdr.getU(int(lenLen))

	return bs.Get(int(len) + 2 + int(lenLen)), tag, 2 + int(lenLen)
}
