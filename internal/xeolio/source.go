package xeolio

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

type EventSource interface {
	Serialize() map[string]interface{}
}

type DirectorySource struct {
	Type   string
	Target string
}

func (s *DirectorySource) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"Type":   s.Type,
		"Target": s.Target,
	}
}

func NewDirectorySource(dirSource source.DirectorySourceMetadata) *DirectorySource {
	return &DirectorySource{
		Type:   "DirectoryScheme",
		Target: dirSource.Path,
	}
}

type ImageSource struct {
	Type        string
	ImageName   string
	ImageDigest string
	ImageLabels map[string]string
}

func NewImageSource(imageSource source.StereoscopeImageSourceMetadata) *ImageSource {
	return &ImageSource{
		Type:        "ImageScheme",
		ImageName:   imageSource.UserInput,
		ImageDigest: imageSource.ManifestDigest,
		ImageLabels: imageSource.Labels,
	}
}

func (s *ImageSource) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"Type":        s.Type,
		"ImageName":   s.ImageName,
		"ImageDigest": s.ImageDigest,
		"ImageLabels": s.ImageLabels,
	}
}

func NewEventSource(sbomSource source.Description) (map[string]interface{}, error) {
	switch v := sbomSource.Metadata.(type) {
	case source.DirectorySourceMetadata:
		return NewDirectorySource(v).Serialize(), nil
	case source.StereoscopeImageSourceMetadata:
		return NewImageSource(v).Serialize(), nil
	default:
		return nil, fmt.Errorf("unsupported source type: %s", v)
	}
}
