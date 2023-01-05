package xeol

import (
	"github.com/anchore/go-logger"
	"github.com/anchore/syft/syft/linux"
	"github.com/wagoodman/go-partybus"

	"github.com/noqcks/xeol/internal/bus"
	"github.com/noqcks/xeol/internal/log"
	"github.com/noqcks/xeol/xeol/db"
	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/matcher"
	"github.com/noqcks/xeol/xeol/pkg"
	"github.com/noqcks/xeol/xeol/store"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func FindEolForPackage(store store.Store, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package) (match.Matches, error) {
	return matcher.FindMatches(store, d, matchers, packages)
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}

func LoadEolDB(cfg db.Config, update bool) (*store.Store, *db.Status, *db.Closer, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	if update {
		log.Debug("looking for updates on eol database")
		_, err := dbCurator.Update()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	storeReader, dbCloser, err := dbCurator.GetStore()
	if err != nil {
		return nil, nil, nil, err
	}

	status := dbCurator.Status()

	p, err := db.NewEolProvider(storeReader)
	if err != nil {
		return nil, &status, nil, err
	}

	s := &store.Store{
		Provider: p,
	}

	closer := &db.Closer{DBCloser: dbCloser}

	return s, &status, closer, nil
}
