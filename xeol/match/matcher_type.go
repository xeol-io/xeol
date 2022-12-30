package match

const (
	UnknownMatcherType MatcherType = "UnknownMatcherType"
	PackageMatcher     MatcherType = "package-matcher"
)

var AllMatcherTypes = []MatcherType{
	PackageMatcher,
}

type MatcherType string
