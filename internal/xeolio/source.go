package xeolio

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type EventSource interface {
	Serialize() map[string]interface{}
}

type DirectorySource struct {
	ID     string
	Type   string
	Target string
}

func (s *DirectorySource) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"ID":     s.ID,
		"Type":   s.Type,
		"Target": s.Target,
	}
}

func NewDirectorySource(sbomSource source.Metadata) *DirectorySource {
	return &DirectorySource{
		ID:     sbomSource.ID,
		Type:   string(sbomSource.Scheme),
		Target: sbomSource.Path,
	}
}

type ImageSource struct {
	ID             string
	Type           string
	ImageName      string
	ImageDigest    string
	ManifestDigest string
}

func NewImageSource(sbomSource source.Metadata) *ImageSource {
	return &ImageSource{
		ID:             sbomSource.ID,
		Type:           string(sbomSource.Scheme),
		ImageName:      sbomSource.ImageMetadata.UserInput,
		ImageDigest:    sbomSource.ImageMetadata.ID,
		ManifestDigest: sbomSource.ImageMetadata.ManifestDigest,
	}
}

func (s *ImageSource) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"ID":             s.ID,
		"Type":           s.Type,
		"ImageName":      s.ImageName,
		"ImageDigest":    s.ImageDigest,
		"ManifestDigest": s.ManifestDigest,
	}
}

func EventSourceScheme(sbomSource source.Metadata) source.Scheme {
	return sbomSource.Scheme
}

func NewEventSource(sbomSource source.Metadata) (map[string]interface{}, error) {
	if sbomSource.Scheme == source.DirectoryScheme {
		return NewDirectorySource(sbomSource).Serialize(), nil
	}
	if sbomSource.Scheme == source.ImageScheme {
		return NewImageSource(sbomSource).Serialize(), nil
	}

	return nil, fmt.Errorf("unsupported source type: %s", sbomSource.Scheme)
}
