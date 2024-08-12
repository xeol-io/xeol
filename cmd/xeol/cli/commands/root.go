package commands

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/cmd/xeol/cli/options"
	"github.com/xeol-io/xeol/internal"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/format"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/internal/stringutil"
	"github.com/xeol-io/xeol/internal/xeolio"
	"github.com/xeol-io/xeol/xeol"
	"github.com/xeol-io/xeol/xeol/db"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/event/parsers"
	"github.com/xeol-io/xeol/xeol/matcher"
	distroMatcher "github.com/xeol-io/xeol/xeol/matcher/distro"
	pkgMatcher "github.com/xeol-io/xeol/xeol/matcher/packages"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/policy"
	"github.com/xeol-io/xeol/xeol/policy/types"
	"github.com/xeol-io/xeol/xeol/presenter/models"
	"github.com/xeol-io/xeol/xeol/report"
	"github.com/xeol-io/xeol/xeol/store"
	"github.com/xeol-io/xeol/xeol/xeolerr"
)

func Root(app clio.Application) *cobra.Command {
	opts := options.DefaultXeol(app.ID())

	return app.SetupRootCommand(&cobra.Command{
		Use:   fmt.Sprintf("%s [IMAGE]", app.ID().Name),
		Short: "A scanner for end-of-life (EOL) software in container images, filesystems, and SBOMs",
		Long: stringutil.Tprintf(`A scanner for end-of-life (EOL) software in container images, filesystems, and SBOMs.

Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a Docker daemon
    {{.appName}} path/to/yourproject                a Docker tar, OCI tar, OCI directory, SIF container, or generic filesystem directory

You can also explicitly specify the scheme to use:
    {{.appName}} podman:yourrepo/yourimage:tag          explicitly use the Podman daemon
    {{.appName}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Podman or otherwise)
    {{.appName}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} singularity:path/to/yourimage.sif      read directly from a Singularity Image Format (SIF) container on disk
    {{.appName}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} sbom:path/to/syft.json                 read Syft JSON from path on disk
    {{.appName}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
    {{.appName}} purl:path/to/purl/file                 read a newline separated file of purls from a path on disk

You can also pipe in Syft JSON directly:
	syft yourimage:tag -o json | {{.appName}}

`, map[string]interface{}{
			"appName": app.ID().Name,
		}),
		Args:          validateRootArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			userInput := ""
			if len(args) > 0 {
				userInput = args[0]
			}
			return runXeol(app, opts, userInput)
		},
		ValidArgsFunction: dockerImageValidArgsFunction,
	}, opts)
}

//nolint:funlen,gocognit
func runXeol(app clio.Application, opts *options.Xeol, userInput string) error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		defer bus.Exit()

		writer, err := format.MakeScanResultWriter(opts.Outputs, opts.File)
		if err != nil {
			errs <- err
			return
		}

		checkForAppUpdate(app.ID(), opts)

		var str *store.Store
		var status *db.Status
		var dbCloser *db.Closer
		var packages []pkg.Package
		var s *sbom.SBOM
		var pkgContext pkg.Context
		var wg = &sync.WaitGroup{}
		var loadedDB, gatheredPackages bool
		var policies []policy.Policy
		var certificates string
		x := xeolio.NewXeolClient(opts.APIKey)

		wg.Add(3)
		go func() {
			defer wg.Done()
			log.Debug("Fetching organization policies")
			if opts.APIKey != "" {
				policies, err = x.FetchPolicies()
				if err != nil {
					errs <- fmt.Errorf("failed to fetch policy: %w", err)
					return
				}
				certificates, err = x.FetchCertificates()
				if err != nil {
					errs <- fmt.Errorf("failed to fetch certificate: %w", err)
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			log.Debug("loading DB")
			str, status, dbCloser, err = xeol.LoadEolDB(opts.DB.ToCuratorConfig(), opts.DB.AutoUpdate)
			if err = validateDBLoad(err, status); err != nil {
				errs <- err
				return
			}
			loadedDB = true
		}()

		go func() {
			defer wg.Done()
			log.Debugf("gathering packages")
			// packages are xeol.Package, not syft.Package
			// the SBOM is returned for downstream formatting concerns
			// xeol uses the SBOM in combination with syft formatters to produce cycloneDX
			// with vulnerability information appended
			packages, pkgContext, s, err = pkg.Provide(userInput, getProviderConfig(opts))
			if err != nil {
				errs <- fmt.Errorf("failed to catalog: %w", err)
				return
			}
			gatheredPackages = true
		}()

		wg.Wait()
		if !loadedDB || !gatheredPackages {
			return
		}

		if dbCloser != nil {
			defer dbCloser.Close()
		}

		applyDistroHint(packages, &pkgContext, opts)

		eolMatcher := xeol.EolMatcher{
			Store:          *str,
			Matchers:       getMatchers(opts),
			FailOnEolFound: opts.FailOnEolFound,
			EolMatchDate:   opts.EolMatchDate,
			LinuxRelease:   pkgContext.Distro,
		}

		allMatches, err := eolMatcher.FindEol(packages)
		if err != nil {
			errs <- err
			if !errors.Is(err, xeolerr.ErrEolFound) {
				return
			}
		}

		var failScan bool
		var imageVerified bool
		var sourceIsImageType bool
		if _, ok := s.Source.Metadata.(source.ImageMetadata); ok {
			sourceIsImageType = true
		}

		for _, p := range policies {
			switch p.GetPolicyType() {
			case types.PolicyTypeNotary:
				// Notary policy is only applicable to images
				if !sourceIsImageType {
					continue
				}
				shouldFailScan, res := p.Evaluate(allMatches, opts.ProjectName, userInput, certificates)
				imageVerified = res.GetVerified()
				if shouldFailScan {
					failScan = true
				}

			case types.PolicyTypeEol:
				shouldFailScan, _ := p.Evaluate(allMatches, opts.ProjectName, "", "")
				if shouldFailScan {
					failScan = true
				}
			}
		}

		if opts.APIKey != "" {
			buf := new(bytes.Buffer)
			bom := cyclonedxhelpers.ToFormatModel(*s)
			enc := cyclonedx.NewBOMEncoder(buf, cyclonedx.BOMFileFormatJSON)
			if err := enc.Encode(bom); err != nil {
				errs <- fmt.Errorf("failed to encode sbom: %w", err)
				return
			}

			eventSource, err := xeolio.NewEventSource(s.Source)
			if err != nil {
				errs <- fmt.Errorf("failed to create event source: %w", err)
				return
			}

			if err := x.SendEvent(report.XeolEventPayload{
				Matches:       allMatches.Sorted(),
				Packages:      packages,
				Context:       pkgContext,
				AppConfig:     opts,
				EventSource:   eventSource,
				ImageVerified: imageVerified,
				Sbom:          base64.StdEncoding.EncodeToString(buf.Bytes()),
			}); err != nil {
				errs <- fmt.Errorf("failed to send eol event: %w", err)
				return
			}
		}

		if err := writer.Write(models.PresenterConfig{
			Matches:   allMatches,
			Packages:  packages,
			Context:   pkgContext,
			SBOM:      s,
			AppConfig: opts,
			DBStatus:  status,
		}); err != nil {
			errs <- err
		}

		if failScan {
			errs <- xeolerr.ErrPolicyViolation
			return
		}
	}()

	return readAllErrors(errs)
}

func readAllErrors(errs <-chan error) (out error) {
	for {
		if errs == nil {
			break
		}
		err, isOpen := <-errs
		if !isOpen {
			errs = nil
			continue
		}
		if err != nil {
			out = multierror.Append(out, err)
		}
	}
	return out
}

func applyDistroHint(pkgs []pkg.Package, context *pkg.Context, opts *options.Xeol) {
	if opts.Distro != "" {
		log.Infof("using distro: %s", opts.Distro)

		split := strings.Split(opts.Distro, ":")
		d := split[0]
		v := ""
		if len(split) > 1 {
			v = split[1]
		}
		context.Distro = &linux.Release{
			PrettyName: d,
			Name:       d,
			ID:         d,
			IDLike: []string{
				d,
			},
			Version:   v,
			VersionID: v,
		}
	}

	hasOSPackage := false
	for _, p := range pkgs {
		switch p.Type {
		case syftPkg.AlpmPkg, syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.KbPkg:
			hasOSPackage = true
		}
	}

	if context.Distro == nil && hasOSPackage {
		log.Warnf("Unable to determine the OS distribution " +
			"You may specify a distro using: --distro <distro>:<version>")
	}
}

func checkForAppUpdate(id clio.Identification, opts *options.Xeol) {
	if !opts.CheckForAppUpdate {
		return
	}

	version := id.Version
	isAvailable, newVersion, err := isUpdateAvailable(version)
	if err != nil {
		log.Errorf(err.Error())
	}
	if isAvailable {
		log.Infof("new version of %s is available: %s (currently running: %s)", id.Name, newVersion, version)

		bus.Publish(partybus.Event{
			Type: event.CLIAppUpdateAvailable,
			Value: parsers.UpdateCheck{
				New:     newVersion,
				Current: id.Version,
			},
		})
	} else {
		log.Debugf("no new %s update available", id.Name)
	}
}

func getMatchers(opts *options.Xeol) []matcher.Matcher {
	return matcher.NewDefaultMatchers(matcher.Config{
		Packages: pkgMatcher.MatcherConfig(opts.Match.Packages),
		Distro:   distroMatcher.MatcherConfig(opts.Match.Distro),
	})
}

func getProviderConfig(opts *options.Xeol) pkg.ProviderConfig {
	cfg := syft.DefaultCreateSBOMConfig().WithCatalogerSelection(
		pkgcataloging.NewSelectionRequest().WithRemovals(
			// the dotnet-executable-parser has myriad issues with naming as well as
			// incorrect versioning, excluding it for now until the quality is better.
			// https://github.com/xeol-io/xeol/pull/232
			"dotnet-portable-executable-cataloger",
		).WithAdditions(
			"alpm-db-cataloger",
			"apk-db-cataloger",
			"cargo-auditable-binary-cataloger",
			"cocoapods-cataloger",
			"conan-cataloger",
			"dart-pubspec-lock-cataloger",
			"dotnet-deps-cataloger",
			"dpkg-db-cataloger",
			"javascript-package-cataloger",
			"javascript-lock-cataloger",
			"elixir-mix-lock-cataloger",
			"erlang-rebar-lock-cataloger",
			"go-module-file-cataloger",
			"go-module-binary-cataloger",
			"graalvm-native-image-cataloger",
			"haskell-cataloger",
			"java-archive-cataloger",
			"java-gradle-lockfile-cataloger",
			"java-pom-cataloger",
			"linux-kernel-cataloger",
			"nix-store-cataloger",
			"php-composer-installed-cataloger",
			"php-composer-lock-cataloger",
			"portage-cataloger",
			"python-package-cataloger",
			"python-installed-package-cataloger",
			"rpm-db-cataloger",
			"rpm-archive-cataloger",
			"ruby-gemfile-cataloger",
			"ruby-installed-gemspec-cataloger",
			"rust-cargo-lock-cataloger",
			"sbom-cataloger",
		))

	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:        opts.Registry.ToOptions(),
			SBOMOptions:            cfg,
			Platform:               opts.Platform,
			Name:                   opts.Name,
			DefaultImagePullSource: opts.DefaultImagePullSource,
		},
		SynthesisConfig: pkg.SynthesisConfig{},
	}
}

func validateDBLoad(loadErr error, status *db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load EOL db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine the status of the EOL db")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
	}
	return nil
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	isStdinPipeOrRedirect, err := internal.IsStdinPipeOrRedirect()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		isStdinPipeOrRedirect = false
	}

	if len(args) == 0 && !isStdinPipeOrRedirect {
		// in the case that no arguments are given and there is no piped input we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}
