package main

import (
	"context"

	"github.com/hilather/go-jenkins-mcp/internal/adapter"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// extLogsBridge maps tools.ExternalLogQuerier → adapter.ExternalLogQuery with
// panic isolation via adapter.Call (FND-004: tools does not import adapter).
type extLogsBridge struct {
	entry *adapter.Entry
	q     adapter.ExternalLogQuery
}

func (b *extLogsBridge) QueryExternalLogs(ctx context.Context, req tools.ExternalLogQueryRequest) (tools.ExternalLogQueryResult, error) {
	var out tools.ExternalLogQueryResult
	err := adapter.Call(b.entry, func() error {
		res, err := b.q.QueryExternalLogs(ctx, adapter.ExternalLogQueryRequest{
			Job:        req.Job,
			Build:      req.Build,
			Start:      req.Start,
			End:        req.End,
			Query:      req.Query,
			MaxEntries: req.MaxEntries,
		})
		if err != nil {
			return err
		}
		entries := make([]tools.ExternalLogEntry, 0, len(res.Entries))
		for _, e := range res.Entries {
			entries = append(entries, tools.ExternalLogEntry{
				RefID:          e.RefID,
				Excerpt:        e.Excerpt,
				Timestamp:      e.Timestamp,
				SourceLabel:    e.SourceLabel,
				Freshness:      e.Freshness,
				EvidenceSource: e.EvidenceSource,
			})
		}
		out = tools.ExternalLogQueryResult{
			Entries:        entries,
			Count:          res.Count,
			Truncated:      res.Truncated,
			MaxEntries:     res.MaxEntries,
			SourceLabel:    res.SourceLabel,
			Freshness:      res.Freshness,
			EvidenceSource: res.EvidenceSource,
			Residuals:      append([]string(nil), res.Residuals...),
			Message:        res.Message,
		}
		return nil
	})
	return out, err
}

// otelExportBridge maps tools.TraceExporter → adapter.TraceExporter with
// panic isolation via adapter.Call (FND-004: tools does not import adapter).
type otelExportBridge struct {
	entry *adapter.Entry
	e     adapter.TraceExporter
}

func (b *otelExportBridge) ExportTraceRefs(ctx context.Context, req tools.TraceExportRequest) (tools.TraceExportResult, error) {
	var out tools.TraceExportResult
	err := adapter.Call(b.entry, func() error {
		envelopes := make([]adapter.TraceExportEnvelope, 0, len(req.Envelopes))
		for _, e := range req.Envelopes {
			envelopes = append(envelopes, adapter.TraceExportEnvelope{
				TraceID: e.TraceID,
				SpanID:  e.SpanID,
				Service: e.Service,
				Job:     e.Job,
				Build:   e.Build,
				Format:  e.Format,
			})
		}
		res, err := b.e.ExportTraceRefs(ctx, adapter.TraceExportRequest{
			Job:       req.Job,
			Build:     req.Build,
			Envelopes: envelopes,
		})
		if err != nil {
			return err
		}
		out = tools.TraceExportResult{
			Status:         res.Status,
			Backend:        res.Backend,
			Accepted:       res.Accepted,
			Attempted:      res.Attempted,
			Truncated:      res.Truncated,
			EvidenceSource: res.EvidenceSource,
			Residuals:      append([]string(nil), res.Residuals...),
			Message:        res.Message,
		}
		return nil
	})
	return out, err
}

// workItemsBridge maps tools.WorkItemLookuper → adapter.WorkItemLookup (stub).
type workItemsBridge struct {
	entry *adapter.Entry
	w     adapter.WorkItemLookup
}

func (b *workItemsBridge) LookupWorkItemRefs(ctx context.Context, ids []string) ([]string, error) {
	var out []string
	err := adapter.Call(b.entry, func() error {
		res, err := b.w.LookupWorkItems(ctx, adapter.WorkItemLookupRequest{Refs: ids})
		if err != nil {
			return err
		}
		out = make([]string, 0, len(res.Refs))
		for _, r := range res.Refs {
			if r.ID != "" {
				out = append(out, r.ID)
			}
		}
		return nil
	})
	return out, err
}
