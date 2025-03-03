package v1

const EolStoreFileName = "xeol.db"

type Product struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Permalink string `json:"permalink"`
}

type Cycle struct {
	ProductName       string `json:"productName"`
	ProductPermalink  string `json:"productPermalink"`
	ReleaseDate       string `json:"releaseDate"`
	ReleaseCycle      string `json:"releaseCycle"`
	LatestReleaseDate string `json:"latestReleaseDate"`
	LatestRelease     string `json:"latestRelease"`
	LTS               string `json:"lts"`
	Eol               string `json:"eol"`
	EolBool           bool   `json:"eolBool"`
}

type Purl struct {
	Purl string `json:"purl"`
}

type Cpe struct {
	Cpe string `json:"cpe"`
}

type EolStore interface {
	EolStoreReader
	EolStoreWriter
}

type EolStoreReader interface {
	GetCyclesByPurl(purl string) ([]Cycle, error)
	GetCyclesByCpe(cpe string) ([]Cycle, error)
	GetVulnCountByPurlAndVersion(purl string, version string) (int, error)
	GetAllProducts() (*[]Product, error)
}

type EolStoreWriter interface {
}
