package cbs

func (bs *ByteString) PeekU8() uint {
	return bs.peekU(1)
}

func (bs *ByteString) GetU8() uint {
	return bs.getU(1)
}

func (bs *ByteString) GetU8LengthPrefixed() *ByteString {
	return bs.getULengthPrefixed(1)
}

func (bs *ByteBuilder) PutU8(n uint) {
	bs.putU(1, n)
}

func (bs *ByteBuilder) PutU8LengthPrefixed() *ByteBuilder {
	return bs.putULengthPrefixed(1)
}

func (bs *ByteString) PeekU16() uint {
	return bs.peekU(2)
}

func (bs *ByteString) GetU16() uint {
	return bs.getU(2)
}

func (bs *ByteString) GetU16LengthPrefixed() *ByteString {
	return bs.getULengthPrefixed(2)
}

func (bs *ByteBuilder) PutU16(n uint) {
	bs.putU(2, n)
}

func (bs *ByteBuilder) PutU16LengthPrefixed() *ByteBuilder {
	return bs.putULengthPrefixed(2)
}

func (bs *ByteString) PeekU24() uint {
	return bs.peekU(3)
}

func (bs *ByteString) GetU24() uint {
	return bs.getU(3)
}

func (bs *ByteString) GetU24LengthPrefixed() *ByteString {
	return bs.getULengthPrefixed(3)
}

func (bs *ByteBuilder) PutU24(n uint) {
	bs.putU(3, n)
}

func (bs *ByteBuilder) PutU24LengthPrefixed() *ByteBuilder {
	return bs.putULengthPrefixed(3)
}

func (bs *ByteString) PeekU32() uint {
	return bs.peekU(4)
}

func (bs *ByteString) GetU32() uint {
	return bs.getU(4)
}

func (bs *ByteString) GetU32LengthPrefixed() *ByteString {
	return bs.getULengthPrefixed(4)
}

func (bs *ByteBuilder) PutU32(n uint) {
	bs.putU(4, n)
}

func (bs *ByteBuilder) PutU32LengthPrefixed() *ByteBuilder {
	return bs.putULengthPrefixed(4)
}
