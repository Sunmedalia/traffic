package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Sunmedalia/traffic/internal/session"
)

const maxRuleBytes = 1 << 20
const maxRuleFiles = 256

func defaultRulesDir() string { return filepath.Join(session.RuntimeRoot(), "rules") }

type ruleLibrary struct {
	mu   sync.Mutex
	root *os.Root
	dir  string
}

type ruleFile struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Content  string    `json:"content,omitempty"`
	Revision string    `json:"revision,omitempty"`
	Count    int       `json:"rule_count"`
	Valid    bool      `json:"valid"`
	Error    string    `json:"error,omitempty"`
}

func openRuleLibrary(dir string) (*ruleLibrary, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return &ruleLibrary{root: root, dir: abs}, nil
}

func validRuleFilename(name string) bool {
	if len(name) > 128 || !utf8.ValidString(name) {
		return false
	}
	ext := filepath.Ext(name)
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	base := strings.TrimSuffix(name, ext)
	if base == "" {
		return false
	}
	for i, r := range base {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !(i > 0 && (r == '-' || r == '_' || r == '.')) {
			return false
		}
	}
	device := strings.ToUpper(strings.SplitN(base, ".", 2)[0])
	if device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" {
		return false
	}
	if len(device) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && device[3] >= '0' && device[3] <= '9' {
		return false
	}
	return true
}

func ruleRevision(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func validateRuleContent(content string) ([]Rule, error) {
	if len(content) > maxRuleBytes {
		return nil, fmt.Errorf("规则文件不能超过 1 MiB")
	}
	if !utf8.ValidString(content) || len(bytes.TrimSpace([]byte(content))) == 0 {
		return nil, errors.New("请输入 UTF-8 YAML 规则列表")
	}
	return rulesFromYAML([]byte(content))
}

func (l *ruleLibrary) list() ([]ruleFile, error) {
	file, err := l.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(10000)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) == 10000 {
		return nil, errors.New("规则目录条目过多，请使用独立规则目录")
	}
	result := []ruleFile{}
	for _, entry := range entries {
		if !validRuleFilename(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		result = append(result, ruleFile{Name: entry.Name(), Size: info.Size(), Modified: info.ModTime()})
		if len(result) > maxRuleFiles {
			return nil, fmt.Errorf("规则目录最多支持 %d 个文件", maxRuleFiles)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (l *ruleLibrary) read(name string) (ruleFile, error) {
	info, err := l.root.Lstat(name)
	if err != nil {
		return ruleFile{}, err
	}
	if !info.Mode().IsRegular() {
		return ruleFile{}, errors.New("只能操作规则目录中的普通文件")
	}
	file, err := l.root.Open(name)
	if err != nil {
		return ruleFile{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRuleBytes+1))
	if err != nil {
		return ruleFile{}, err
	}
	if len(data) > maxRuleBytes {
		return ruleFile{}, errors.New("规则文件不能超过 1 MiB")
	}
	result := ruleFile{Name: name, Size: int64(len(data)), Modified: info.ModTime(), Content: string(data), Revision: ruleRevision(data)}
	rs, err := validateRuleContent(result.Content)
	if err != nil {
		result.Error = err.Error()
	} else {
		result.Valid = true
		result.Count = len(rs) - len(builtinRules)
	}
	return result, nil
}

func (l *ruleLibrary) write(name, content, revision string) (ruleFile, int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := validateRuleContent(content); err != nil {
		return ruleFile{}, http.StatusUnprocessableEntity, err
	}
	previous, err := l.read(name)
	if err == nil {
		if revision == "" || revision != previous.Revision {
			return ruleFile{}, http.StatusConflict, errors.New("文件已存在或已被修改，请重新打开后保存")
		}
	} else if !os.IsNotExist(err) {
		return ruleFile{}, http.StatusBadRequest, err
	} else {
		if revision != "" {
			return ruleFile{}, http.StatusConflict, errors.New("文件已被删除，请另存为新文件")
		}
		files, err := l.list()
		if err != nil {
			return ruleFile{}, http.StatusInternalServerError, err
		}
		if len(files) >= maxRuleFiles {
			return ruleFile{}, http.StatusConflict, errors.New("规则文件数量已达上限")
		}
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return ruleFile{}, 500, err
	}
	tmp := ".rule-" + hex.EncodeToString(random[:]) + ".tmp"
	file, err := l.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ruleFile{}, 500, err
	}
	defer l.root.Remove(tmp)
	_, err = file.WriteString(content)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = l.root.Rename(tmp, name)
	}
	if err != nil {
		return ruleFile{}, 500, err
	}
	result, err := l.read(name)
	return result, http.StatusOK, err
}

func decodeWebJSON(rw http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(rw, r.Body, 8*maxRuleBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("请求只能包含一个 JSON 对象")
	}
	return nil
}

func (w *webServer) requireRuleLibrary(rw http.ResponseWriter) *ruleLibrary {
	if w.ruleLibrary == nil {
		webError(rw, 503, errors.New("规则目录未配置"))
		return nil
	}
	return w.ruleLibrary
}

func (w *webServer) handleRuleList(rw http.ResponseWriter, r *http.Request) {
	l := w.requireRuleLibrary(rw)
	if l == nil {
		return
	}
	l.mu.Lock()
	files, err := l.list()
	l.mu.Unlock()
	if err != nil {
		webError(rw, 500, err)
		return
	}
	webJSON(rw, 200, map[string]any{"dir": l.dir, "files": files, "builtin_rules": builtinRules, "max_bytes": maxRuleBytes})
}

func (w *webServer) handleRuleFile(rw http.ResponseWriter, r *http.Request) {
	l := w.requireRuleLibrary(rw)
	if l == nil {
		return
	}
	name := r.PathValue("name")
	if !validRuleFilename(name) {
		webError(rw, 400, errors.New("文件名需以字母或数字开头，只能包含字母、数字、点、下划线或短横线，并以 .yaml / .yml 结尾"))
		return
	}
	if r.Method == http.MethodGet {
		l.mu.Lock()
		result, err := l.read(name)
		l.mu.Unlock()
		if err != nil {
			status := 400
			if os.IsNotExist(err) {
				status = 404
			}
			webError(rw, status, err)
			return
		}
		webJSON(rw, 200, result)
		return
	}
	var input struct {
		Content  string `json:"content"`
		Revision string `json:"revision"`
	}
	if err := decodeWebJSON(rw, r, &input); err != nil {
		webError(rw, 400, err)
		return
	}
	if r.Method == http.MethodPut {
		result, status, err := l.write(name, input.Content, input.Revision)
		if err != nil {
			webError(rw, status, err)
			return
		}
		webJSON(rw, status, result)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	previous, err := l.read(name)
	if err != nil {
		status := 400
		if os.IsNotExist(err) {
			status = 404
		}
		webError(rw, status, err)
		return
	}
	if input.Revision == "" || input.Revision != previous.Revision {
		webError(rw, 409, errors.New("文件已被修改，请重新打开后删除"))
		return
	}
	if err = l.root.Remove(name); err != nil {
		webError(rw, 500, err)
		return
	}
	webJSON(rw, 200, map[string]bool{"deleted": true})
}

func (w *webServer) handleRuleValidate(rw http.ResponseWriter, r *http.Request) {
	var input struct {
		Content string `json:"content"`
	}
	if err := decodeWebJSON(rw, r, &input); err != nil {
		webError(rw, 400, err)
		return
	}
	rs, err := validateRuleContent(input.Content)
	if err != nil {
		webError(rw, 422, err)
		return
	}
	webJSON(rw, 200, map[string]any{"valid": true, "rule_count": len(rs) - len(builtinRules), "total_rules": len(rs)})
}
