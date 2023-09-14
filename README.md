<h1 align="center">Xeol</h1>

<div align="center">
  <img src="https://s3.amazonaws.com/static.xeol.io/xeol-logo/logo-white-bg.png" width="100px" />

  **A scanner for end-of-life (EOL) packages in container images, filesystems, and SBOMs**

  <a href="https://goreportcard.com/report/github.com/xeol-io/xeol"><img src="https://goreportcard.com/badge/github.com/xeol-io/xeol" alt="Go Report Card"/></a>
  <a href="https://github.com/xeol-io/xeol/releases/latest"><img src="https://img.shields.io/github/release/xeol-io/xeol.svg" alt="GitHub release"/></a>
  <a href="https://github.com/xeol-io/xeol"><img src="https://img.shields.io/github/go-mod/go-version/xeol-io/xeol.svg" alt="GitHub go.mod Go version"/></a>
  <a href="https://github.com/xeol-io/xeol/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache-2.0"/></a>
  <a href="https://api.securityscorecards.dev/projects/github.com/xeol-io/xeol"><img src="https://api.securityscorecards.dev/projects/github.com/xeol-io/xeol/badge" alt="OpenSSF Scorecard"/></a>
  <a href="https://img.shields.io/github/downloads/xeol-io/xeol/total.svg"><img src="https://img.shields.io/github/downloads/xeol-io/xeol/total.svg" alt="Github All Releases"/></a>
  <a href="https://discord.gg/23ucxwsb"><img src="https://dcbadge.vercel.app/api/server/23ucxwsb?style=flat" alt="Discord"/></a>

  <img src="https://user-images.githubusercontent.com/4740147/216162986-2c3add2b-af9f-4d9d-97eb-4c1617da3a71.gif" width="800px" />
</div>

## Installation

### Recommended

```bash
curl -sSfL https://raw.githubusercontent.com/xeol-io/xeol/main/install.sh | sh -s -- -b /usr/local/bin
```

Check installation or check version of xeol
```
xeol version
```

You can also choose another destination directory and release version for the installation. The destination directory doesn't need to be `/usr/local/bin`, it just needs to be a location found in the user's PATH and writable by the user that's installing xeol.

```
curl -sSfL https://raw.githubusercontent.com/xeol-io/xeol/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

### Homebrew

```bash
brew tap xeol-io/xeol
brew install xeol
```

### GitHub Actions

If you're using GitHub Actions, you can simply use the [Xeol GitHub action](https://github.com/marketplace/actions/xeol-end-of-life-eol-scan) to run EOL scans on your code or container images during your CI workflows.

## Getting started

[Install the binary](#installation), and make sure that `xeol` is available in your path. To scan for EOL packages in an image:

```
xeol <image>
```

The above command scans for EOL packages that are visible in the container (i.e., the squashed representation of the image). To include software from all image layers in the vulnerability scan, regardless of its presence in the final image, provide `--scope all-layers`:

```
xeol <image> --scope all-layers
```

To run xeol from a Docker container so it can scan a running container, use the following command:

```yml
docker run --rm \
--volume /var/run/docker.sock:/var/run/docker.sock \
--name xeol noqcks/xeol:latest \
$(ImageName):$(ImageTag)
```

### Supported sources

xeol can scan a variety of sources beyond those found in Docker.

```
# scan a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
xeol path/to/image.tar

# scan a Singularity Image Format (SIF) container
xeol path/to/image.sif

# scan a directory
xeol dir:path/to/dir
```

Sources can be explicitly provided with a scheme:

```
podman:yourrepo/yourimage:tag          use images from the Podman daemon
docker:yourrepo/yourimage:tag          use images from the Docker daemon
docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
singularity:path/to/yourimage.sif      read directly from a Singularity Image Format (SIF) container on disk
dir:path/to/yourproject                read directly from a path on disk (any directory)
sbom:path/to/syft.json                 read Syft JSON from path on disk
registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
att:attestation.json --key cosign.pub  explicitly use the input as an attestation
```

Use SBOMs for even faster EOL scanning in xeol:

```
# Then scan for new EOL packages as frequently as needed
xeol sbom:./sbom.json

# (You can also pipe the SBOM into xeol)
cat ./sbom.json | xeol
```

xeol supports input of [Syft](https://github.com/xeol-io/xeol), [SPDX](https://spdx.dev/), and [CycloneDX](https://cyclonedx.org/)
SBOM formats. If Syft has generated any of these file types, they should have the appropriate information to work properly with xeol.


### Lookahead

By default, xeol will match any package that has an EOL date that is less than the current date + 30d. In order to set a custom lookahead matching time, you can use `--lookahead <duration>`. where `<duration>` is like `1w`, `30d` or `1y`.

### Gating on EOL packages found

You can have xeol exit with an error if it finds any EOL packages. This is useful for CI/CD pipelines. To do this, use the `--fail-on-eol-found` CLI flag.

```
xeol <image> --fail-on-eol-found
```

## What is EOL software?

End of Life (EOL) means the vendor has decided the software in question has reached the end of its
“useful lifespan.” After this particular date, the manufacturer no longer markets, sells, provides technical support, sustains, enhances, or fixes the product. Note that End of Life (EOL) and End of Support (EOS) are being treated as the same by xeol, even though various vendors may use these terms differently. EOL Software is a security risk because it is no longer being maintained and receiving security updates.

The data that xeol uses to determine if a package is EOL is sourced from [endoflife.date](https://endoflife.date/). While endoflife.date includes extended support dates, xeol does not currently support this and we only match on the standard EOL support dates from vendors.

## xeol's database


When xeol performs a scan for EOL packages, it does so using a database that's stored on your local filesystem, which is constructed by pulling data from [endoflife.date](https://endoflife.date/).

By default, xeol automatically manages this database for you. xeol checks for new updates to the database to make sure that every scan uses up-to-date EOL information. This behavior is configurable. For more information, see the Managing xeeol's database section.

### How database updates work

xeol's eol database is a SQLite file, named `xeol.db`. Updates to the database are atomic: the entire database is replaced and then treated as "readonly" by xeol.

xeol's first step in a database update is discovering databases that are available for retrieval. xeol does this by requesting a "listing file" from a public endpoint:

`https://data.xeol.io/xeol/databases/listing.json`

The listing file contains entries for every database that's available for download.

Here's an example of an entry in the listing file:

```json
{
  "built": "2021-10-21T08:13:41Z",
  "version": 3,
  "url": "https://data.xeol.io/xeol/databases/eol-db_v3_2021-10-21T08:13:41Z.tar.gz",
  "checksum": "sha256:8c99fb4e516f10b304f026267c2a73a474e2df878a59bf688cfb0f094bfe7a91"
}
```

With this information, xeol can select the correct database (the most recently built database with the current schema version), download the database, and verify the database's integrity using the listed `checksum` value.

### Managing xeol's database

> **Note:** During normal usage, _there is no need for users to manage xeol's database!_ xeol manages its database behind the scenes. However, for users that need more control, xeol provides options to manage the database more explicitly.

#### Local database cache directory

By default, the database is cached on the local filesystem in the directory `$XDG_CACHE_HOME/xeol/db/<SCHEMA-VERSION>/`. For example, on macOS, the database would be stored in `~/Library/Caches/xeol/db/3/`. (For more information on XDG paths, refer to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html).)

You can set the cache directory path using the environment variable `XEOL_DB_CACHE_DIR`.

#### Data staleness

xeol needs up-to-date vulnerability information to provide accurate matches. By default, it will fail execution if the local database was not built in the last 5 days. The data staleness check is configurable via the environment variable `XEOL_DB_MAX_ALLOWED_BUILT_AGE` and `XEOL_DB_VALIDATE_AGE` or the field `max-allowed-built-age` and `validate-age`, under `db`. It uses [golang's time duration syntax](https://pkg.go.dev/time#ParseDuration). Set `XEOL_DB_VALIDATE_AGE` or `validate-age` to `false` to disable staleness check.

#### Offline and air-gapped environments

By default, xeol checks for a new database on every run, by making a network call over the Internet. You can tell xeol not to perform this check by setting the environment variable `XEOL_DB_AUTO_UPDATE` to `false`.

As long as you place xeol's `vulnerability.db` and `metadata.json` files in the cache directory for the expected schema version, xeol has no need to access the network. Additionally, you can get a listing of the database archives available for download from the `xeol db list` command in an online environment, download the database archive, transfer it to your offline environment, and use `xeol db import <db-archive-path>` to use the given database in an offline capacity.

If you would like to distribute your own xeol databases internally without needing to use `db import` manually you can leverage xeol's DB update mechanism. To do this you can craft your own `listing.json` file similar to the one found publically (see `xeol db list -o raw` for an example of our public `listing.json` file) and change the download URL to point to an internal endpoint (e.g. a private S3 bucket, an internal file server, etc). Any internal installation of xeol can receive database updates automatically by configuring the `db.update-url` (same as the `XEOL_DB_UPDATE_URL` environment variable) to point to the hosted `listing.json` file you've crafted.

#### CLI commands for database management

xeol provides database-specific CLI commands for users that want to control the database from the command line. Here are some of the useful commands provided:

`xeol db status` — report the current status of xeol's database (such as its location, build date, and checksum)

`xeol db check` — see if updates are available for the database

`xeol db update` — ensure the latest database has been downloaded to the cache directory (xeol performs this operation at the beginning of every scan by default)

`xeol db list` — download the listing file configured at `db.update-url` and show databases that are available for download

`xeol db import` — provide xeol with a database archive to explicitly use (useful for offline DB updates)

Find complete information on xeol's database commands by running `xeol db --help`.

## Shell completion

xeol supplies shell completion through its CLI implementation ([cobra](https://github.com/spf13/cobra/blob/master/shell_completions.md)). Generate the completion code for your shell by running one of the following commands:

- `xeol completion <bash|zsh|fish>`
- `go run main.go completion <bash|zsh|fish>`

This will output a shell script to STDOUT, which can then be used as a completion script for xeol. Running one of the above commands with the
`-h` or `--help` flags will provide instructions on how to do that for your chosen shell.

## Private Registry Authentication

### Local Docker Credentials

When a container runtime is not present, xeol can still utilize credentials configured in common credential sources (such as `~/.docker/config.json`).
It will pull images from private registries using these credentials. The config file is where your credentials are stored when authenticating with private registries via some command like `docker login`.
For more information see the `go-containerregistry` [documentation](https://github.com/google/go-containerregistry/tree/main/pkg/authn).

An example `config.json` looks something like this:

```
// config.json
{
	"auths": {
		"registry.example.com": {
			"username": "AzureDiamond",
			"password": "hunter2"
		}
	}
}
```

You can run the following command as an example. It details the mount/environment configuration a container needs to access a private registry:

`docker run -v ./config.json:/config/config.json -e "DOCKER_CONFIG=/config" noqcks/xeol:latest <private_image>`

### Docker Credentials in Kubernetes

The below section shows a simple workflow on how to mount this config file as a secret into a container on kubernetes.

1.  Create a secret. The value of `config.json` is important. It refers to the specification detailed [here](https://github.com/google/go-containerregistry/tree/main/pkg/authn#the-config-file).
    Below this section is the `secret.yaml` file that the pod configuration will consume as a volume.
    The key `config.json` is important. It will end up being the name of the file when mounted into the pod.
    ``` # secret.yaml

        apiVersion: v1
        kind: Secret
        metadata:
          name: registry-config
          namespace: xeol
        data:
          config.json: <base64 encoded config.json>
        ```

        `kubectl apply -f secret.yaml`

2.  Create your pod running xeol. The env `DOCKER_CONFIG` is important because it advertises where to look for the credential file.
    In the below example, setting `DOCKER_CONFIG=/config` informs xeol that credentials can be found at `/config/config.json`.
    This is why we used `config.json` as the key for our secret. When mounted into containers the secrets' key is used as the filename.
    The `volumeMounts` section mounts our secret to `/config`. The `volumes` section names our volume and leverages the secret we created in step one.
    ``` # pod.yaml

        apiVersion: v1
        kind: Pod
        spec:
          containers:
            - image: noqcks/xeol:latest
              name: xeol-private-registry-demo
              env:
                - name: DOCKER_CONFIG
                  value: /config
              volumeMounts:
              - mountPath: /config
                name: registry-config
                readOnly: true
              args:
                - <private_image>
          volumes:
          - name: registry-config
            secret:
              secretName: registry-config
        ```

        `kubectl apply -f pod.yaml`

3.  The user can now run `kubectl logs xeol-private-registry-demo`. The logs should show the xeol analysis for the `<private_image>` provided in the pod configuration.

Using the above information, users should be able to configure private registry access without having to do so in the `xeol` or `syft` configuration files.
They will also not be dependent on a docker daemon, (or some other runtime software) for registry configuration and access.

## Configuration

Configuration search paths:

- `.xeol.yaml`
- `.xeol/config.yaml`
- `~/.xeol.yaml`
- `<XDG_CONFIG_HOME>/xeol/config.yaml`


## Pronunciation

Xeol is pronounced "zee-oh-el", like EOL but with a Z in front :-)

## Help

Join our discord for help or feedback! [![](https://dcbadge.vercel.app/api/server/23ucxwsb?style=flat)](https://discord.gg/23ucxwsb)
