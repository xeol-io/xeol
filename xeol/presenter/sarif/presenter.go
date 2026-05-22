package sarif

import (
	"fmt"
	"io"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/xeol-io/xeol/internal"
	"github.com/xeol-io/xeol/internal/version"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/presenter/models"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	matches   match.Matches
	packages  []pkg.Package
	context   pkg.Context
	appConfig interface{}
	dbStatus  interface{}
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		matches:   pb.Matches,
		packages:  pb.Packages,
		context:   pb.Context,
		appConfig: pb.AppConfig,
		dbStatus:  pb.DBStatus,
	}
}

// Present creates a SARIF-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := models.NewDocument(pres.packages, pres.context, pres.matches, pres.appConfig, pres.dbStatus)
	if err != nil {
		return err
	}

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI(internal.ApplicationName, "https://github.com/xeol-io/xeol")
	run.Tool.Driver.WithVersion(version.FromBuild().Version)

	for _, match := range doc.Matches {
		ruleId := "EOL-PACKAGE"
		message := fmt.Sprintf("Package %s version %s reached End-Of-Life on %s", match.Artifact.Name, match.Artifact.Version, match.Cycle.Eol)

		run.AddRule(ruleId).
			WithDescription(message).
			WithHelpURI("https://github.com/xeol-io/xeol").
			WithShortDescription(sarif.NewMultiformatMessageString(fmt.Sprintf("%s is EOL", match.Artifact.Name)))

		result := sarif.NewRuleResult(ruleId).
			WithMessage(sarif.NewMessage().WithText(message)).
			WithLevel("warning")

		for _, loc := range match.Artifact.Locations {
			result.AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(
							sarif.NewSimpleArtifactLocation(loc.RealPath),
						),
				),
			)
		}

		if len(match.Artifact.Locations) == 0 {
			result.AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(
							sarif.NewSimpleArtifactLocation("image"),
						),
				),
			)
		}

		run.AddResult(result)
	}

	report.AddRun(run)

	return report.PrettyWrite(output)
}
