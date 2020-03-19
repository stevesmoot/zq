package sst

import (
	"io"
	"os"
)

type reader struct {
	filename string
	file     *os.File
	frame    []byte
	valsize  int
}

// Reader reads an SST file and implements the Stream interface.
type Reader struct {
	reader
	in []byte
}

func (r *reader) init(path string, level int) {
	r.filename = filename(path, level)
}

// NewReader returns a Reader ready to read an SST file.
// Close() should be called when done.
func NewReader(path string) *Reader {
	r := &Reader{}
	r.init(path, 0)
	return r
}

func (r *reader) Open() error {
	var err error
	if r.file, err = os.Open(r.filename); err != nil {
		return err
	}
	return r.readFileHeader()
}

func (r *reader) readFileHeader() error {
	var hdr [FileHeaderLen]byte
	n, err := r.file.Read(hdr[:])
	if err != nil {
		return err
	}
	if n != FileHeaderLen {
		return ErrCorruptFile
	}
	if decodeInt(hdr[0:4]) != magic {
		return ErrBadMagic
	}
	if versionMajor != hdr[4] || versionMinor != hdr[5] {
		return ErrFileVersion
	}
	r.valsize = decodeInt(hdr[6:10])
	//XXX
	if r.valsize > 10*1024*1024 {
		return ErrCorruptFile
	}
	framesize := decodeInt(hdr[10:14])
	//XXX
	if framesize > 10*1024*1024 {
		return ErrCorruptFile
	}
	r.frame = make([]byte, 0, framesize)
	return nil
}

func (r *reader) Close() error {
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *Reader) readInt() (int, error) {
	if len(r.in) < 4 {
		return 0, ErrCorruptFile
	}
	v := decodeInt(r.in)
	r.in = r.in[4:]
	return v, nil
}

func (r *Reader) decode() ([]byte, error) {
	n, err := r.readInt()
	if err != nil {
		return nil, err
	}
	if n > len(r.in) {
		return nil, ErrCorruptFile
	}
	value := r.in[:n]
	r.in = r.in[n:]
	return value, nil
}

func (r *Reader) Read() (Pair, error) {
	if len(r.in) == 0 {
		if err := r.readFrame(); err != nil {
			if err == io.EOF {
				return Pair{}, nil
			}
			return Pair{}, err
		}
	}
	key, err := r.decode()
	if err != nil {
		return Pair{}, err
	}
	value, err := r.decode()
	if err != nil {
		return Pair{}, err
	}
	// this key and value point into the frame buffer so the caller
	// needs to copy them before the next call to read
	// XXX for a merge we don't need to convert to a string
	return Pair{key, value}, nil
}

func (r *reader) grow(target int) {
	size := cap(r.frame)
	for size < target {
		size *= 2
	}
	r.frame = make([]byte, 0, target)
}

func (r *Reader) readFrame() error {
	var hdr [5]byte
	hdr[0] = 0 // compression type XXX
	n, err := r.file.Read(hdr[:])
	if err != nil {
		return err
	}
	if n < 5 {
		return ErrCorruptFile
	}
	flen := decodeInt(hdr[1:])
	if cap(r.frame) < flen {
		r.grow(flen)
	}
	r.in = r.frame[:flen]
	n, err = r.file.Read(r.in)
	if err != nil {
		return err
	}
	if n != flen {
		return ErrCorruptFile
	}
	return nil
}

type FrameReader struct {
	reader
}

func NewFrameReader(path string, level int) *FrameReader {
	r := &FrameReader{}
	r.init(path, level)
	return r
}

func (r *FrameReader) ReadFrameAt(off int64) ([]byte, error) {
	var hdr [FrameHeaderLen]byte
	n, err := r.file.ReadAt(hdr[:], off)
	if err != nil {
		return nil, err
	}
	if n != FrameHeaderLen {
		return nil, ErrCorruptFile
	}
	framelen := decodeInt(hdr[1:5])
	//XXX
	if framelen > 10*1024*1024 {
		return nil, ErrCorruptFile
	}
	r.grow(framelen)
	n, err = r.file.ReadAt(r.frame[0:framelen], off+FrameHeaderLen)
	if err != nil {
		return nil, err
	}
	if n != framelen {
		return nil, ErrCorruptFile
	}
	return r.frame[:framelen], nil
}
