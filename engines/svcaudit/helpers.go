package svcaudit

import (
	"encoding/binary"
	"regexp"
	"strconv"
	"strings"
)

var redisVersionRe = regexp.MustCompile(`redis_version:([0-9][0-9.]*)`)

func itoa(n int) string {
	return strconv.Itoa(n)
}

func extractField(body, key string) string {
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	rest = strings.TrimLeft(rest, ": \"")
	end := strings.IndexAny(rest, "\",}")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

func bsonListDatabases() []byte {
	var doc []byte
	doc = append(doc, 0x10)
	doc = append(doc, []byte("listDatabases")...)
	doc = append(doc, 0x00)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, 1)
	doc = append(doc, v...)

	doc = append(doc, 0x02)
	doc = append(doc, []byte("$db")...)
	doc = append(doc, 0x00)
	s := "admin\x00"
	sl := make([]byte, 4)
	binary.LittleEndian.PutUint32(sl, uint32(len(s)))
	doc = append(doc, sl...)
	doc = append(doc, []byte(s)...)

	doc = append(doc, 0x00)

	full := make([]byte, 4+len(doc))
	binary.LittleEndian.PutUint32(full[:4], uint32(4+len(doc)))
	copy(full[4:], doc)
	return full
}

func mongoListDatabasesQuery() []byte {
	body := bsonListDatabases()
	section := make([]byte, 4+1+len(body))
	copy(section[5:], body)

	msg := make([]byte, 16+len(section))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint32(msg[4:8], 1)
	binary.LittleEndian.PutUint32(msg[8:12], 0)
	binary.LittleEndian.PutUint32(msg[12:16], 2013)
	copy(msg[16:], section)
	return msg
}
