package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

// The web server keeps only the most recent runs in memory; the session's own
// analysis report remains the durable record.
const maxWebAnalysisHistory = 20

type webAnalysisJob struct {
	ID        string          `json:"id"`
	SessionID string          `json:"session_id"`
	RulesFile string          `json:"rules_file"`
	State     string          `json:"state"`
	Started   time.Time       `json:"started"`
	Finished  time.Time       `json:"finished,omitempty"`
	Error     string          `json:"error,omitempty"`
	Report    *analysisReport `json:"report,omitempty"`
}

func (w *webServer) handleAnalyze(rw http.ResponseWriter, r *http.Request) {
	var input struct {
		RulesFile string `json:"rules_file"`
	}
	if err := decodeWebJSON(rw, r, &input); err != nil {
		webError(rw, 400, err)
		return
	}
	var rs []Rule
	var err error
	if input.RulesFile != "" {
		if !validRuleFilename(input.RulesFile) {
			webError(rw, 400, errors.New("请选择规则目录中的 YAML 文件"))
			return
		}
		library := w.requireRuleLibrary(rw)
		if library == nil {
			return
		}
		library.mu.Lock()
		file, readErr := library.read(input.RulesFile)
		library.mu.Unlock()
		if readErr != nil {
			webError(rw, 400, readErr)
			return
		}
		rs, err = validateRuleContent(file.Content)
	} else {
		rs, err = rulesFromYAML(nil)
	}
	if err != nil {
		webError(rw, 422, err)
		return
	}
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	dir := s.dir
	s.db.Close()
	w.jobMu.Lock()
	defer w.jobMu.Unlock()
	if w.ctx.Err() != nil {
		webError(rw, 503, errors.New("分析服务正在停止"))
		return
	}
	if w.job != nil && w.job.State == "running" {
		webError(rw, 409, errors.New("已有分析任务正在运行，请等待完成或先取消"))
		return
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		webError(rw, 500, err)
		return
	}
	job := &webAnalysisJob{ID: hex.EncodeToString(random[:]), SessionID: r.PathValue("sid"), RulesFile: input.RulesFile, State: "running", Started: time.Now().UTC()}
	ctx, cancel := context.WithCancel(w.ctx)
	w.job, w.jobCancel = job, cancel
	w.jobHistory = append([]*webAnalysisJob{job}, w.jobHistory...)
	if len(w.jobHistory) > maxWebAnalysisHistory {
		w.jobHistory = w.jobHistory[:maxWebAnalysisHistory]
	}
	w.jobs.Add(1)
	go func() {
		defer w.jobs.Done()
		defer cancel()
		report, err := analyzeSessionRules(ctx, dir, "", rs, time.Minute, 20)
		w.jobMu.Lock()
		defer w.jobMu.Unlock()
		job.Finished = time.Now().UTC()
		if err != nil {
			job.State = "failed"
			job.Error = err.Error()
			if errors.Is(err, context.Canceled) {
				job.State = "cancelled"
			}
		} else {
			job.State = "succeeded"
			job.Report = &report
		}
	}()
	webJSON(rw, http.StatusAccepted, job)
}

func (w *webServer) handleAnalysisStatus(rw http.ResponseWriter, r *http.Request) {
	w.jobMu.Lock()
	defer w.jobMu.Unlock()
	history := w.jobHistory
	if history == nil {
		history = []*webAnalysisJob{}
	}
	webJSON(rw, 200, map[string]any{"job": w.job, "history": history})
}

func (w *webServer) handleAnalysisCancel(rw http.ResponseWriter, r *http.Request) {
	var input struct {
		ID string `json:"id"`
	}
	if err := decodeWebJSON(rw, r, &input); err != nil {
		webError(rw, 400, err)
		return
	}
	w.jobMu.Lock()
	defer w.jobMu.Unlock()
	if w.job == nil || w.job.ID != input.ID || w.job.State != "running" {
		webError(rw, 409, errors.New("该任务已结束或已被替换"))
		return
	}
	w.jobCancel()
	webJSON(rw, 202, map[string]bool{"cancelling": true})
}
