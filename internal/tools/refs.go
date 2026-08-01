package tools

import (
	"errors"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// DefaultLogLength is the seed default for jenkins_get_build_logs length.
const DefaultLogLength int64 = 8192

// jobFullName validates a tool job_name/name string as a typed JobRef full name
// (MCP-002). Returns the trimmed full name for Jenkins client calls, or an
// invalid_argument apperr that identifies the field and allowed form.
//
// Compatibility: JSON field remains job_name or name (string). Absolute
// http(s) URLs, absolute path forms, empty segments, and "." / ".." segments
// are rejected with a clear invalid_argument (Wave 31 fail closed) rather than
// being path-escaped into Jenkins.
func jobFullName(field, raw string) (string, error) {
	ref, err := contracts.ParseJobFullName(field, raw)
	if err != nil {
		return "", fieldErrToInvalidArg(err)
	}
	return ref.FullName, nil
}

// buildRef validates job + build_number tool fields into a contracts.BuildRef.
func buildRef(jobField, jobName, numberField string, number int) (contracts.BuildRef, error) {
	ref, err := contracts.ParseBuildRef(jobField, jobName, numberField, int64(number))
	if err != nil {
		return contracts.BuildRef{}, fieldErrToInvalidArg(err)
	}
	return ref, nil
}

// queueItemRef validates queue_id (+ optional profile) tool fields.
func queueItemRef(idField string, id int, profile string) (contracts.QueueItemRef, error) {
	ref, err := contracts.ParseQueueItemRef(idField, int64(id), contracts.ProfileID(profile))
	if err != nil {
		return contracts.QueueItemRef{}, fieldErrToInvalidArg(err)
	}
	return ref, nil
}

// logEvidence validates flattened log tool fields (job_name, build_number,
// offset, length). lengthDefault applies when length <= 0.
func logEvidence(jobField, jobName, numberField string, number int, offset, length int, lengthDefault int64) (contracts.LogEvidenceRef, error) {
	ref, err := contracts.ParseLogEvidenceRef(jobField, jobName, numberField, int64(number), int64(offset), int64(length), "", lengthDefault)
	if err != nil {
		return contracts.LogEvidenceRef{}, fieldErrToInvalidArg(err)
	}
	return ref, nil
}

// fieldErrToInvalidArg maps contracts.FieldError to apperr invalid_argument.
// Other errors are wrapped as invalid_argument with a safe message.
func fieldErrToInvalidArg(err error) error {
	if err == nil {
		return nil
	}
	var fe *contracts.FieldError
	if errors.As(err, &fe) && fe != nil {
		return apperr.New(apperr.CodeInvalidArgument, fe.Error())
	}
	return apperr.New(apperr.CodeInvalidArgument, err.Error())
}
