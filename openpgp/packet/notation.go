package packet

// Notation type represents a Notation Data subpacket
// see https://tools.ietf.org/html/rfc4880#section-5.2.3.16
type Notation struct {
	flags      []byte
	name       string
	value      []byte
	critical   bool
}

func (not *Notation) IsHumanReadable() (bool) {
	return not.flags[0] & 0x80 == 0x80
}

func (not *Notation) GetName() (string) {
	return not.name
}

func (not *Notation) GetBinaryValue() ([]byte) {
	return not.value
}

func (not *Notation) GetStringValue() (string) {
	return string(not.value)
}

func (not *Notation) IsCritical() (bool) {
	return not.critical
}

func (not *Notation) getData() ([]byte) {
	nameLen := len(not.name)
	valueLen := len(not.value)
	nameData := []byte(not.name)

	data := not.flags
	data[4] = byte(nameLen >> 8)
	data[5] = byte(nameLen)
	data[6] = byte(valueLen >> 8)
	data[7] = byte(valueLen)

	data = append(data, nameData...)
	return append(data, not.value...)
}
