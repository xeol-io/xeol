package v1

type Store interface {
	StoreReader
	StoreWriter
	DBCloser
}

type StoreReader interface {
	IDReader
	EolStoreReader
}

type StoreWriter interface {
	IDWriter
	EolStoreWriter
}

type DBCloser interface {
	Close()
}
