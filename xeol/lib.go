package xeol

import (
	"time"

	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/db"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/matcher"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/store"
	"github.com/xeol-io/xeol/xeol/xeolerr"
)

func FindEol(store store.Store, d *linux.Release, matchers []matcher.Matcher, packages []pkg.Package, failOnEolFound bool, eolMatchDate time.Time) (match.Matches, error) {
	matches := matcher.FindMatches(store, d, matchers, packages, failOnEolFound, eolMatchDate)
	var err error
	if failOnEolFound && matches.Count() > 0 {
		err = xeolerr.ErrEolFound
	}
	return matches, err
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
