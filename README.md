# Black Duck Scan Action
A [GitHub Action](https://github.com/features/actions) for launching a Black Duck scan as part of a GitHub CI/CD workflow, offering a number of workflow use cases:
- Break the build if a security policy is not met
- Run fast, incremental scans on a pull request, only reporting newly introduced components
- Leave comments on a pull request that identify vulnerable components and offer upgrade guidance
- Import Black Duck vulnerabilities as code scanning alerts via SARIF
- Open a fix pull request for vulnerable components with an available upgrade

This script is provided under an OSS license (specified in the LICENSE file) and has been developed by Synopsys field engineers as a contribution to the Synopsys user community. Please direct questions and comments to the [Black Duck Integrations Forum](https://community.synopsys.com/s/topic/0TO34000000gGZnGAM/black-duck-integrations) in the Synopsys user community.

The following technology stacks are currently supported:
- Javascript.Node.js/NPM
- Java/Maven
- .NET/NuGet (in progress)

## Usage

The action runs as a Docker container, supporting GitHub-hosted and Self-hosted Linux runners. You can use the Action as follows:

```yaml
name: Scan a project with Black Duck

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]
  workflow_dispatch:

jobs:
  blackduck:
    runs-on: ubuntu-latest
    steps:
    
    - name: Checkout the code
      uses: actions/checkout@v2
      
    # Runs a Black Duck intelligent scan on commits to master
    # This will run a "full" or "intelligent" scan, logging new components in the Black Duck Hub server
    # in order to provide real time notifications when new vulnerabilities are reported.
    - name: Run Baseline Black Duck Scan (manual, workflow dispatch)
      if: ${{github.event_name == 'workflow_dispatch'}}
      uses: synopsys-sig-community/blackduck-scan-action@v1
      with:
        url: ${{ secrets.BLACKDUCK_URL }}
        token: ${{ secrets.BLACKDUCK_TOKEN }}
        mode: intelligent
        
    # Runs a Black Duck rapid scan on push
    # This will run a "rapid" scan on pushes to a main branch, and attempt to file a fix pull request
    # for vulnerable components if there is a suitable upgrade path
    - name: Run Black Duck security scan (push)
      if: ${{github.event_name == 'push'}}
      uses: synopsys-sig-community/blackduck-scan-action@v1
      with:
        url: ${{ secrets.BLACKDUCK_URL }}
        token: ${{ secrets.BLACKDUCK_TOKEN }}
        # Generate SARIF output
        sarif: blackduck-sarif.json
        # Use "rapid" mode for a fast scan appropriate for CI/CD pipeline
        mode: rapid
        # Generate fix pull requests when upgarde guidance
        fix_pr: true
      # Must continue on error in order to reach SARIF import
      continue-on-error: true
      env:
        # Pass the GitHub token to the script in order to create PRs
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        
     - name: Upload SARIF file (push)
      if: ${{github.event_name == 'push'}}
      uses: github/codeql-action/upload-sarif@v1
      with:
        # Path to SARIF file relative to the root of the repository
        sarif_file: blackduck-sarif.json

    # Runs a Black Duck rapid scan on pull request
    # This will run a "rapid" scan on pull requests, only reporting components that have been introduced since the
    # last full or intelligent scan, abd comment 
    - name: Run Black Duck security scan (pull_request)
      if: ${{github.event_name == 'pull_request'}}
      uses: synopsys-sig-community/blackduck-scan-action@v1
      with:
        url: ${{ secrets.BLACKDUCK_URL }}
        token: ${{ secrets.BLACKDUCK_TOKEN }}
        # Generate SARIF output
        sarif: blackduck-sarif.json
        # Use "rapid" mode for a fast scan appropriate for CI/CD pipeline
        mode: rapid
        # Leave feedback through a comment on the PR
        comment_on_pr: true
        # Only report newly introduced components
        incremental_results: true
      # Must continue on error in order to reach SARIF import
      continue-on-error: true
      env:
        # Pass the GitHub token to the script in order to create PRs
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

     - name: Upload SARIF file (pull_request)
      if: ${{github.event_name == 'pull_request'}}
      uses: github/codeql-action/upload-sarif@v1
      with:
        # Path to SARIF file relative to the root of the repository
        sarif_file: blackduck-sarif.json

```

## Inputs

The Black Duck Scanning action has a number of input parameters that can be passed using `with`.

| Property | Default | Description |
| --- | --- | --- |
| incremental_results | false | ... |

