package dlcbf

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"math"
	"sync"
)

const bucketHeight = 8
const bucketsSize = 4096

type fingerprint uint16

type target struct {
	bucketIndex []uint
	fingerprint fingerprint
}

type match struct {
	tbl         uint
	bkt         uint
	entry       uint
	fingerprint fingerprint
}

type bucket struct {
	entries  [bucketHeight]fingerprint
	counters [bucketHeight]uint8 // counter for each entry
	count    uint8               // entries used
}

type table []bucket

/*
Dlcbf is a struct representing a d-left Counting Bloom Filter
*/
type Dlcbf struct {
	tables     []table
	numTables  uint
	numBuckets uint
	lock       sync.RWMutex
}

/*
NewDlcbf returns a newly created Dlcbf
*/
func NewDlcbf(numTables uint, numBuckets uint) (*Dlcbf, error) {

	if numBuckets < numTables {
		return nil, errors.New("numBuckets has to be greater than numTables")
	}

	dlcbf := &Dlcbf{
		numTables:  numTables,
		numBuckets: numBuckets,
		tables:     make([]table, numTables, numTables),
		lock:       sync.RWMutex{},
	}

	for i := range dlcbf.tables {
		dlcbf.tables[i] = make(table, numBuckets, numBuckets)
	}

	return dlcbf, nil
}

/*
NewDlcbfForCapacity returns a newly created Dlcbf for a given max Capacity
*/
func NewDlcbfForCapacity(capacity uint) (*Dlcbf, error) {
	t := capacity / (bucketsSize * bucketHeight)
	return NewDlcbf(t, bucketsSize)
}

func (dlcbf *Dlcbf) getTarget(data []byte) target {
	hasher := fnv.New64a()
	hasher.Write(data)
	fp := hasher.Sum(nil)
	hsum := hasher.Sum64()

	h1 := uint32(hsum & 0xffffffff)
	h2 := uint32((hsum >> 32) & 0xffffffff)

	indices := make([]uint, dlcbf.numTables, dlcbf.numTables)
	for i := uint(0); i < dlcbf.numTables; i++ {
		saltedHash := uint((h1 + uint32(i)*h2))
		indices[i] = (saltedHash % dlcbf.numBuckets)
	}

	return target{
		bucketIndex: indices,
		fingerprint: fingerprint(binary.LittleEndian.Uint16(fp)),
	}
}

func (dlcbf *Dlcbf) getTargets(datas [][]byte) []target {
	targets := make([]target, len(datas))
	for k := range datas {
		targets[k] = dlcbf.getTarget(datas[k])
	}
	return targets
}

/*
Add data to filter return true if insertion was successful,
returns false if data already in filter or size limit was exceeeded
*/
func (dlcbf *Dlcbf) addTarget(t target, permit_duplicate bool) bool {
	m := dlcbf.lookup(t)
	if m != nil {
		// key already exist
		if !permit_duplicate {
			return false
		}
		bucket := &dlcbf.tables[m.tbl][m.bkt]
		if bucket.counters[m.entry] >= math.MaxUint8 {
			// the counter exceed the limit
			return false
		}
		bucket.counters[m.entry]++
		return true
	}

	minCount := uint8(math.MaxUint8)
	tableI := uint(0)

	for i, idx := range t.bucketIndex {
		tmpCount := dlcbf.tables[i][idx].count
		if tmpCount < minCount && tmpCount < bucketHeight {
			minCount = dlcbf.tables[i][idx].count
			tableI = uint(i)
		}
	}

	if minCount == uint8(math.MaxUint8) {
		// insert failed
		return false
	}
	bucket := &dlcbf.tables[tableI][t.bucketIndex[tableI]]
	bucket.entries[minCount] = t.fingerprint
	bucket.counters[minCount] = 1
	bucket.count++
	return true
}

func (dlcbf *Dlcbf) Add(data []byte) bool {
	t := dlcbf.getTarget(data)

	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	return dlcbf.addTarget(t, true)
}

func (dlcbf *Dlcbf) TestAndAdd(data []byte) bool {
	t := dlcbf.getTarget(data)

	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	return dlcbf.addTarget(t, false)
}

func (dlcbf *Dlcbf) AddBatch(datas [][]byte) []bool {
	targets := dlcbf.getTargets(datas)
	res := make([]bool, len(datas))

	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	for k := range targets {
		res[k] = dlcbf.addTarget(targets[k], true)
	}
	return res
}

func (dlcbf *Dlcbf) TestAddBatch(datas [][]byte) []bool {
	targets := dlcbf.getTargets(datas)
	res := make([]bool, len(datas))

	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	for k := range targets {
		res[k] = dlcbf.addTarget(targets[k], false)
	}
	return res
}

/*
Delete data to filter return true if deletion was successful,
returns false if data not in filter
*/
func (dlcbf *Dlcbf) deleteTarget(t target) bool {
	deleted := false
	for i, idx := range t.bucketIndex {
		for j, fp := range dlcbf.tables[i][idx].entries {
			if fp == t.fingerprint {
				if dlcbf.tables[i][idx].count == 0 {
					continue
				}
				// move entries after entry to be deleted
				var k uint8
				for k = uint8(j + 1); k < dlcbf.tables[i][idx].count; k++ {
					dlcbf.tables[i][idx].entries[k-1] = dlcbf.tables[i][idx].entries[k]
					dlcbf.tables[i][idx].counters[k-1] = dlcbf.tables[i][idx].counters[k]
				}

				dlcbf.tables[i][idx].count--
				lastindex := dlcbf.tables[i][idx].count
				dlcbf.tables[i][idx].entries[lastindex] = 0
				dlcbf.tables[i][idx].counters[lastindex] = 0
				deleted = true
			}
		}
	}
	return deleted
}

func (dlcbf *Dlcbf) Delete(data []byte) bool {
	t := dlcbf.getTarget(data)

	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	return dlcbf.deleteTarget(t)
}

func (dlcbf *Dlcbf) DeleteBatch(datas [][]byte) []bool {
	targets := dlcbf.getTargets(datas)
	res := make([]bool, len(datas))

	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	for k := range targets {
		res[k] = dlcbf.deleteTarget(targets[k])
	}
	return res
}

func (dlcbf *Dlcbf) lookup(t target) *match {
	for i, idx := range t.bucketIndex {
		for j, fp := range dlcbf.tables[i][idx].entries {
			if fp == t.fingerprint {
				return &match{
					tbl:         uint(i),
					bkt:         idx,
					entry:       uint(j),
					fingerprint: fp,
				}
			}
		}
	}
	return nil
}

/*
Get returns counter if data is in filter
*/
func (dlcbf *Dlcbf) targetCounter(t target) uint8 {
	dlcbf.lock.RLock()
	defer dlcbf.lock.RUnlock()

	m := dlcbf.lookup(t)
	if m == nil {
		return 0
	}
	return dlcbf.tables[m.tbl][m.bkt].counters[m.entry]
}

func (dlcbf *Dlcbf) targetsCounter(targets []target) []uint8 {
	dlcbf.lock.RLock()
	defer dlcbf.lock.RUnlock()

	res := make([]uint8, len(targets))
	for k := range targets {
		m := dlcbf.lookup(targets[k])
		if m == nil {
			res[k] = 0
		} else {
			res[k] = dlcbf.tables[m.tbl][m.bkt].counters[m.entry]
		}
	}
	return res
}

func (dlcbf *Dlcbf) Get(data []byte) uint8 {
	return dlcbf.targetCounter(dlcbf.getTarget(data))
}

func (dlcbf *Dlcbf) GetBatch(datas [][]byte) []uint8 {
	return dlcbf.targetsCounter(dlcbf.getTargets(datas))
}

/*
GetCount returns cardinlaity count of current filter
*/
func (dlcbf *Dlcbf) Count() uint {
	count := uint(0)
	for _, table := range dlcbf.tables {
		for _, bucket := range table {
			count += uint(bucket.count)
		}
	}
	return count
}

func (dlcbf *Dlcbf) ClearAll() {
	dlcbf.lock.Lock()
	defer dlcbf.lock.Unlock()

	for i := range dlcbf.tables {
		for j := range dlcbf.tables[i] {
			for k := 0; k < int(dlcbf.tables[i][j].count); k++ {
				dlcbf.tables[i][j].entries[k] = 0
				dlcbf.tables[i][j].counters[k] = 0
			}
			dlcbf.tables[i][j].count = 0
		}
	}
}

func (dlcbf *Dlcbf) Encode() ([]byte, error) {
	// dlcbf.lock.Lock()
	// defer dlcbf.lock.Unlock()
	bytes := make([]byte, 0, int(dlcbf.numTables)*bucketsSize*(bucketHeight*3))

	for i := range dlcbf.tables { // tables
		for j := range dlcbf.tables[i] { // buckets
			for k := 0; k < bucketHeight; k++ {
				next := make([]byte, 2)
				binary.LittleEndian.PutUint16(next, uint16(dlcbf.tables[i][j].entries[k]))
				bytes = append(bytes, next...)
				bytes = append(bytes, dlcbf.tables[i][j].counters[k])
			}
		}
	}

	return bytes, nil
}

func (dlcbf *Dlcbf) Decode(bytes []byte) error {

	for i := range dlcbf.tables { // tables
		for j := range dlcbf.tables[i] { // buckets
			for k := 0; k < bucketHeight; k++ {
				var next []byte
				next, bytes = bytes[0:3], bytes[3:]

				if fp := binary.LittleEndian.Uint16(next[0:2]); fp != 0 {
					dlcbf.tables[i][j].entries[k] = fingerprint(fp)
					dlcbf.tables[i][j].counters[k] = next[2]
					dlcbf.tables[i][j].count++
				}
			}
		}
	}

	return nil
}

func (dlcbf *Dlcbf) WriteTo(stream io.Writer) (int64, error) {
	data, _ := dlcbf.Encode()
	length := uint64(len(data))
	err := binary.Write(stream, binary.LittleEndian, length)
	if err != nil {
		return 0, err
	}

	err = binary.Write(stream, binary.LittleEndian, data)
	if err != nil {
		return 0, err
	}

	return int64(length) + int64(binary.Size(uint64(0))), nil
}

func (dlcbf *Dlcbf) ReadFrom(stream io.Reader) (int64, error) {
	var length uint64
	err := binary.Read(stream, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}

	data := make([]byte, length)
	err = binary.Read(stream, binary.LittleEndian, &data)
	if err != nil {
		return 0, err
	}

	dlcbf.Decode(data)
	return int64(length) + int64(binary.Size(uint64(0))), nil
}
