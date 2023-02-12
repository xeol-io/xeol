package v1

const EolStoreFileName = "xeol.db"

type Product struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Cycle struct {
	ProductName       string `json:"productName"`
	ReleaseDate       string `json:"releaseDate"`
	ReleaseCycle      string `json:"releaseCycle"`
	LatestReleaseDate string `json:"latestReleaseDate"`
	LatestRelease     string `json:"latestRelease"`
	Eol               string `json:"eol"`
	EolBool           bool   `json:"eolBool"`
}

type Purl struct {
	Purl string `json:"purl"`
}

type EolStore interface {
	EolStoreReader
	EolStoreWriter
}

type EolStoreReader interface {
	GetCyclesByPurl(purl string) ([]Cycle, error)
	GetAllProducts() (*[]Product, error)
}

type EolStoreWriter interface {
}
