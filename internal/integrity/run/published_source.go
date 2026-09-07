package run

import (
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// ValidatePublishedSource checks a typed storage projection's schema/bindings.
// It is not source authentication or authorization: callers must obtain data
// from a scoped repository snapshot and recheck immutable source hashes on use.
// Neither this type nor its output is bound to an HTTP request.
func ValidatePublishedSource(data repository.PublishedRead) (analyzer.Document, error) {
	return decodePublished(data)
}
