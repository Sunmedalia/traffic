package index

import (
	"database/sql"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// Driver is the SQLite driver every session database is opened with. It is the
// stock driver plus traffic_url_decode, which lets filters match the decoded
// form of a stored URL without rewriting the evidence.
const Driver = "sqlite3_traffic"

// MaxURLDecodeRounds bounds traffic_url_decode so a crafted URL cannot make a
// filter scan arbitrarily expensive.
const MaxURLDecodeRounds = 4

func init() {
	sql.Register(Driver, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return conn.RegisterFunc("traffic_url_decode", URLDecode, true)
	}})
}

var percentEscape = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

// URLDecode applies up to rounds of percent-decoding ('+' becomes a space) and
// stops early once a round changes nothing. Malformed escapes are kept as typed.
func URLDecode(text string, rounds int) string {
	if rounds > MaxURLDecodeRounds {
		rounds = MaxURLDecodeRounds
	}
	for i := 0; i < rounds; i++ {
		next, err := url.QueryUnescape(text)
		if err != nil {
			next = percentEscape.ReplaceAllStringFunc(strings.ReplaceAll(text, "+", " "), func(escape string) string {
				value, _ := strconv.ParseUint(escape[1:], 16, 8)
				return string([]byte{byte(value)})
			})
		}
		if next == text {
			break
		}
		text = next
	}
	return text
}
