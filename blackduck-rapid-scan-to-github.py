import argparse
import glob
import hashlib
import json
import os
import random
import re
import shutil
import sys
import zipfile

import networkx as nx
from BlackDuckUtils import BlackDuckOutput as bo
from BlackDuckUtils import Utils as bu
from BlackDuckUtils import bdio as bdio
from BlackDuckUtils import globals as bdglobals

from BlackDuckUtils import MavenUtils
from BlackDuckUtils import NpmUtils

from blackduck import Client
from github import Github

import globals


def github_create_pull_request_comment(g, github_repo, pr, pr_commit, comments_markdown, comments_markdown_footer):
    if (globals.debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (globals.debug): print(repo)

    body = f'''
Synopsys Black Duck found the following vulnerabilities in Pull Reuqest #{pr.number}:

'''
    body = body + "\n".join(comments_markdown) + "\n\n" + comments_markdown_footer

    if (globals.debug): print(f"DEBUG: Get issue for pull request #{pr.number}")
    issue = repo.get_issue(number = pr.number)
    if (globals.debug): print(issue)

    if (globals.debug): print(f"DEBUG: Create pull request review comment for pull request #{pr.number} with the following body:\n{body}")
    issue.create_comment(body)

def github_commit_file_and_create_fixpr(g, github_token, github_api_url, github_repo, github_branch, files_to_commit, fix_pr_node):
    if (globals.debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (globals.debug): print(repo)

    if (globals.debug): print(f"DEBUG: Get HEAD commit from '{github_repo}'")
    commit = repo.get_commit('HEAD')
    if (globals.debug): print(commit)

    new_branch_seed = '%030x' % random.randrange(16**30)
    #new_branch_seed = secrets.token_hex(15)
    new_branch_name = github_branch + "-snps-fix-pr-" + new_branch_seed
    if (globals.debug): print(f"DEBUG: Create branch '{new_branch_name}'")
    ref = repo.create_git_ref("refs/heads/" + new_branch_name, commit.sha)
    if (globals.debug): print(ref)

    commit_message = f"Update {fix_pr_node['componentName']} to fix known security vulnerabilities"

    for file_to_patch in files_to_patch:
        if (globals.debug): print(f"DEBUG: Get SHA for file '{file_to_patch}'")
        file = repo.get_contents(file_to_patch)

        if (globals.debug): print(f"DEBUG: Upload file '{file_to_patch}'")
        try:
            with open(files_to_patch[file_to_patch], 'r') as fp:
                file_contents = fp.read()
        except:
            print(f"ERROR: Unable to open package file '{files_to_patch[file_to_patch]}'")
            sys.exit(1)

        if (globals.debug): print(f"DEBUG: Update file '{file_to_patch}' with commit message '{commit_message}'")
        file = repo.update_file(file_to_patch, commit_message, file_contents, file.sha, branch=new_branch_name)

    pr_body = f'''
Pull request submitted by Synopsys Black Duck to upgrade {fix_pr_node['componentName']} from version {fix_pr_node['versionFrom']} to {fix_pr_node['versionTo']} in order to fix the known security vulnerabilities:

'''
    pr_body = pr_body + "\n".join(fix_pr_node['comments_markdown']) + "\n\n" + fix_pr_node['comments_markdown_footer']
    if (globals.debug):
        print(f"DEBUG: Submitting pull request:")
        print(pr_body)
    pr = repo.create_pull(title=f"Black Duck: Upgrade {fix_pr_node['componentName']} to version {fix_pr_node['versionTo']} fix known security vulerabilities", body=pr_body, head=new_branch_name, base="master")


def get_pull_requests(g, github_repo):
    if (globals.debug): print(f"DEBUG: Index pull requests, Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (globals.debug): print(repo)

    pull_requests = []

    # TODO Should this handle other bases than master?
    pulls = repo.get_pulls(state='open', sort='created', base='master', direction="desc")
    for pull in pulls:
        if (globals.debug): print(f"DEBUG: Pull request number: {pull.number}: {pull.title}")
        pull_requests.append(pull.title)

    return pull_requests


def get_comps(bd, pv):
    comps = bd.get_json(pv + '/components?limit=5000')
    newcomps = []
    complist = []
    for comp in comps['items']:
        if 'componentVersionName' not in comp:
            continue
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if comp['ignored'] is False and cname not in complist:
            newcomps.append(comp)
            complist.append(cname)
    return newcomps

def get_projver(bd, projname, vername):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return ''
    # projects = bd.get_resource('projects', params=params)
    for proj in projects['items']:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == vername:
                return ver['_meta']['href']
    print("ERROR: Version '{}' does not exist in project '{}'".format(projname, vername))
    return ''

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                description='Generate GitHub SARIF file from Black Duck Rapid Scan')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--url', required=True, help='Black Duck Base URL')
parser.add_argument('--token', required=True, help='Black Duck API Token')
parser.add_argument('--output_directory', required=True, help='Rapid Scan output directory')
parser.add_argument('--output', required=True, help='File to output SARIF to')
parser.add_argument('--upgrade_major', default=False, action='store_true', help='Upgrade beyond current major version')
parser.add_argument('--fix_pr', default=False, action='store_true', help='Create Fix PR for upgrade guidance')
parser.add_argument('--comment_on_pr', default=False, action='store_true', help='Comment on the pull request being scanned')
parser.add_argument('--all_comps', default=False, action='store_true', help='Report on ALL components, not just newly introduced')
parser.add_argument('--upgrade_indirect', default=False, action='store_true', help='Attemp to upgrade indirect dependencies')

args = parser.parse_args()

globals.debug = int(args.debug)
bdglobals.debug = globals.debug
# TODO Better to read BD API Token from environment variable
#bd_apitoken = os.getenv("BLACKDUCK_TOKEN")
#if (bd_apitoken == None or bd_apitoken == ""):
#    print("ERROR: Please set BLACKDUCK_TOKEN in environment before running")
#    sys.exit(1)
bd_apitoken = args.token
bd_url = args.url
bd_output_dir = args.output_directory
upgrade_major = args.upgrade_major
sarif_output_file = args.output
fix_pr = args.fix_pr
comment_pr = args.comment_on_pr
allcomps = args.all_comps
upgrade_indirect = args.upgrade_indirect

fix_pr_annotation = ""

bd = Client(token=bd_apitoken,
        base_url=bd_url,
        timeout=300)

project_baseline_name, project_baseline_version, detected_package_files = bo.get_blackduck_status(bd_output_dir)

print(f"INFO: Running for project '{project_baseline_name}' version '{project_baseline_version}'")

# Look up baseline data
pvurl = get_projver(bd, project_baseline_name, project_baseline_version)
baseline_comp_cache = dict()
if (not allcomps):
    if (pvurl == ''):
        print(f"WARN: Unable to find project '{project_baseline_name}' version '{project_baseline_version}' - will not present incremental results")
    else:
        if (globals.debug): print(f"DEBUG: Project Version URL: {pvurl}")
        baseline_comps = get_comps(bd, pvurl)
        #if (globals.debug): print(f"DEBUG: Baseline components=" + json.dumps(baseline_comps, indent=4))
        #sys.exit(1)
        # Can't cache the component Id / external id very easily here as it's not top-level,
        # and may have multiple origins
        for comp in baseline_comps:
            if (not comp['componentName'] in baseline_comp_cache): baseline_comp_cache[comp['componentName']] = dict()
            #if (baseline_comp_cache[comp['componentName']] == None): baseline_comp_cache[comp['componentName']] = dict()
            baseline_comp_cache[comp['componentName']][comp['componentVersionName']] = 1
            #baseline_comp_cache[comp['componentName']] = comp['componentVersionName']
        if (globals.debug): print(f"DEBUG: Baseline component cache=" + json.dumps(baseline_comp_cache, indent=4))
        if (globals.debug): print(f"DEBUG: Generated baseline component cache")

bdio_graph, bdio_projects = bdio.get_bdio_dependency_graph(bd_output_dir)

if (len(bdio_projects) == 0):
    print("ERROR: Unable to find base project in BDIO file")
    sys.exit(1)

rapid_scan_data = bo.get_rapid_scan_results(bd_output_dir, bd)

# Prepare SARIF output structures
runs = []
run = dict()

component_match_types = dict()
components = dict()

tool_rules = []
results = []

fix_pr_data = dict()
comment_on_pr_comments = []

for item in rapid_scan_data['items']:
    if (globals.debug):
        print(f"DEBUG: Component: {item['componentIdentifier']}")
        #print(item)
        #sys.exit(1)

    comp_ns, comp_name, comp_version = bu.parse_component_id(item['componentIdentifier'])

    # If comparing to baseline, look up in cache and continue if already exists
    if (not allcomps and item['componentName'] in baseline_comp_cache):
        if (item['versionName'] in baseline_comp_cache[item['componentName']] and baseline_comp_cache[item['componentName']][item['versionName']] == 1):
            if (globals.debug): print(f"DEBUG:   Skipping component {item['componentName']} version {item['versionName']} because it was already seen in baseline")
            continue
        else:
            if (globals.debug): print(f"DEBUG:   Including component {item['componentName']} version {item['versionName']} because it was not seen in baseline")

    # Is this a direct dependency?
    dependency_type = "Direct"

    # Track the root dependencies
    dependency_paths = []
    direct_ancestors = dict()

    if (globals.debug): print(f"DEBUG: Looking for {item['componentIdentifier']}")
    if (globals.debug):
        print(f"DEBUG: comp_ns={comp_ns} comp_name={comp_name} comp_version={comp_version}")

    # Matching in the BDIO requires an http: prefix
    if (comp_ns == "npmjs"):
        node_http_name = NpmUtils.convert_to_bdio(item['componentIdentifier'])
    elif (comp_ns == "maven"):
        node_http_name = MavenUtils.convert_to_bdio(item['componentIdentifier'])
    else:
        print(f"ERROR: Domain '{comp_ns}' not supported yet")
        sys.exit(1)

    if (globals.debug): print(f"DEBUG: Looking for {node_http_name}")
    ans = nx.ancestors(bdio_graph, node_http_name)
    ans_list = list(ans)
    if (globals.debug): print(f"DEBUG:   Ancestors are: {ans_list}")
    pred = nx.DiGraph.predecessors(bdio_graph, node_http_name)
    pred_list = list(pred)
    if (globals.debug): print(f"DEBUG:   Predecessors are: {ans_list}")
    if (len(ans_list) != 1):
        dependency_type = "Transitive"

        # If this is a transitive dependency, what are the flows?
        for proj in bdio_projects:
            dep_paths = nx.all_simple_paths(bdio_graph, source=proj, target=node_http_name)
            if (globals.debug): print(f"DEBUG: Paths to '{node_http_name}'")
            paths = []
            for path in dep_paths:
                # First generate a string for easy output and reading
                path_modified = path
                path_modified.pop(0)
                # Subtract http:<domain>/
                path_modified_trimmed = [re.sub(r'http\:.*?\/', '', path_name) for path_name in path_modified]
                # Change / to @
                path_modified_trimmed = [re.sub(r'\/', '@', path_name) for path_name in path_modified_trimmed]
                pathstr = " -> ".join(path_modified_trimmed)
                if (globals.debug): print(f"DEBUG:   path={pathstr}")
                dependency_paths.append(pathstr)
                if upgrade_indirect:
                    # Then log the direct dependencies directly
                    direct_dep = path_modified_trimmed[0]
                    direct_name = direct_dep.split('@')[0]
                    direct_version = direct_dep.split('@')[1]

                    direct_ancestors[direct_dep] = 1
                    if (globals.debug): print(f"DEBUG: Direct ancestor: {direct_dep} is of type {node_domain}")
                    if (comp_ns == "npmjs"):
                        NpmUtils.attempt_indirect_upgrade(comp_ns, comp_version, direct_name, direct_version)
                    else:
                        if (globals.debug): print(f"DEBUG: Domain '{comp_ns}' cannot be auto upgraded")

    # Get component upgrade advice
    shortTerm, longTerm = bu.get_upgrade_guidance(bd, item['componentIdentifier'])

    upgrade_version = None
    if (upgrade_major):
        if (longTerm != None):
            upgrade_version = longTerm
    else:
        if (shortTerm != None):
            upgrade_version = shortTerm

    if (globals.debug): print(f"DEUBG: Detected package files={detected_package_files} item={item}")
    package_file, package_line = bu.detect_package_file(detected_package_files, item['componentIdentifier'], item['componentName'])

    if (globals.debug): print(f"DEBUG: package file for {item['componentIdentifier']} is {package_file} on line {package_line} type is {dependency_type}")

    if (dependency_type == "Direct" and upgrade_version != None):
        fix_pr_node = dict()
        fix_pr_node['componentName'] = comp_name
        fix_pr_node['versionFrom'] = comp_version
        fix_pr_node['versionTo'] = upgrade_version
        fix_pr_node['ns'] = comp_ns
        fix_pr_node['filename'] = bu.remove_cwd_from_filename(package_file)
        fix_pr_node['comments'] = []
        fix_pr_node['comments_markdown'] = ["| ID | Severity | Description | Vulnerable version | Upgrade to |", "| --- | --- | --- | --- | --- |"]
        fix_pr_node['comments_markdown_footer'] = ""

    # Loop through policy violations and append to SARIF output data

    if (globals.debug):
        print(f"DEBUG: Loop through policy violations")
        print(item['policyViolationVulnerabilities'])

    for vuln in item['policyViolationVulnerabilities']:
        if (upgrade_version != None):
            message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* Recommended to upgrade to version {upgrade_version}. {dependency_type} dependency."
            message_markdown = f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {comp_version} | {upgrade_version} | "
            comment_on_pr = f"| {vuln['name']} | {dependency_type} | {vuln['name']} |  {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {comp_version} | {upgrade_version} |"
        else:
            message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* No upgrade available at this time. {dependency_type} dependency."
            message_markdown = f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {comp_version} | {upgrade_version} | "
            comment_on_pr = f"| {vuln['name']} | {dependency_type} | {vuln['name']} | {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {comp_version} | N/A |"

        if (dependency_type == "Direct"):
            message = message + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
            message_markdown_footer = f"**Fix in package file '{bu.remove_cwd_from_filename(package_file)}'**"
        else:
            if (len(dependency_paths) > 0):
                message = message + f"Find dependency in {dependency_paths[0]}"
                message_markdown_footer = f"**Find dependency in {dependency_paths[0]}**"

        print("INFO: " + message)
        comment_on_pr_comments.append(comment_on_pr)

        # Save message to include in Fix PR
        if (dependency_type == "Direct" and upgrade_version != None):
            fix_pr_node['comments'].append(message)
            fix_pr_node['comments_markdown'].append(message_markdown)
            fix_pr_node['comments_markdown_footer'] = message_markdown_footer

        result = dict()
        result['ruleId'] = vuln['name']
        message = dict()
        message['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {comp_name}."
        result['message'] = message
        locations = []
        loc = dict()
        loc['file'] = bu.remove_cwd_from_filename(package_file)
        # TODO: Can we reference the line number in the future, using project inspector?
        loc['line'] = package_line

        tool_rule = dict()
        tool_rule['id'] = vuln['name']
        shortDescription = dict()
        shortDescription['text'] = f"{vuln['name']} - {vuln['vulnSeverity']} severity vulnerability in {comp_name}"
        tool_rule['shortDescription'] = shortDescription
        fullDescription = dict()
        fullDescription['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {comp_name}"
        tool_rule['fullDescription'] = fullDescription
        rule_help = dict()
        rule_help['text'] = ""
        if (upgrade_version != None):
            rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nRecommended to upgrade to version {upgrade_version}.\n\n"
        else:
            rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nNo upgrade available at this time.\n\n"

        if (dependency_type == "Direct"):
            rule_help['markdown'] = rule_help['markdown'] + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
        else:
            if (len(dependency_paths) > 0):
                rule_help['markdown'] = rule_help['markdown'] + f" Find dependency in **{dependency_paths[0]}**."

        tool_rule['help'] = rule_help
        defaultConfiguration = dict()

        if (vuln['vulnSeverity'] == "CRITICAL" or vuln['vulnSeverity'] == "HIGH"):
            defaultConfiguration['level'] = "error"
        elif (vuln['vulnSeverity'] == "MEDIUM"):
            defaultConfiguration['level'] = "warning"
        else:
            defaultConfiguration['level'] = "note"

        tool_rule['defaultConfiguration'] = defaultConfiguration
        properties = dict()
        properties['tags'] = ["security"]
        properties['security-severity'] = str(vuln['overallScore'])
        tool_rule['properties'] = properties
        tool_rules.append(tool_rule)

        location = dict()
        physicalLocation = dict()
        artifactLocation = dict()
        artifactLocation['uri'] = loc['file']
        physicalLocation['artifactLocation'] = artifactLocation
        region = dict()
        region['startLine'] = loc['line']
        physicalLocation['region'] = region
        location['physicalLocation'] = physicalLocation
        locations.append(location)
        result['locations'] = locations

        # Calculate fingerprint using simply the CVE/BDSA - the scope is the project in GitHub, so this should be fairly accurate for identifying a unique issue.
        # Guidance from https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
        # and https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012611
        # TODO Should this just leave it alone and let GitHub calculate it?
        partialFingerprints = dict()
        primaryLocationLineHash = hashlib.sha224(b"{vuln['name']}").hexdigest()
        partialFingerprints['primaryLocationLineHash'] = primaryLocationLineHash
        result['partialFingerprints'] = partialFingerprints

        results.append(result)

        if (dependency_type == "Direct" and upgrade_version != None):
            fix_pr_data[comp_name + "@" + comp_name] = fix_pr_node
            #fix_pr_data.append(fix_pr_node)

run['results'] = results
runs.append(run)

tool = dict()
driver = dict()
driver['name'] = "Synopsys Black Duck"
driver['organization'] = "Synopsys"
driver['rules'] = tool_rules
tool['driver'] = driver
run['tool'] = tool

code_security_scan_report = dict()
code_security_scan_report['runs'] = runs
code_security_scan_report['$schema'] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
code_security_scan_report['version'] = "2.1.0"
code_security_scan_report['runs'] = runs

if (globals.debug):
    print("DEBUG: SARIF Data structure=" + json.dumps(code_security_scan_report, indent=4))
try:
    with open(sarif_output_file, "w") as fp:
        json.dump(code_security_scan_report, fp, indent=4)
except:
    print(f"ERROR: Unable to write to SARIF output file '{sarif_output_file}'")
    sys.exit(1)

# Optionally generate Fix PR

fix_pr_components = dict()
if (fix_pr and len(fix_pr_data.values()) > 0):
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_branch = os.getenv("GITHUB_REF")
    github_api_url = os.getenv("GITHUB_API_URL")

    if (github_token == None or github_repo == None or github_branch == None or github_api_url == None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF and/or GITHUB_API_URL in the environment - are you running from a GitHub action?")
        sys.exit(1)

    if (globals.debug): print(f"DEBUG: Connect to GitHub at {github_api_url}")
    g = Github(github_token, base_url=github_api_url)

    print("DEBUG: Generating Fix Pull Requests")

    pulls = get_pull_requests(g, github_repo)

    for fix_pr_node in fix_pr_data.values():
        if (globals.debug): print(f"DEBUG: Fix '{fix_pr_node['componentName']}' version '{fix_pr_node['versionFrom']}' in file '{fix_pr_node['filename']}' using ns '{fix_pr_node['ns']}' to version '{fix_pr_node['versionTo']}'")

        pull_request_title = f"Black Duck: Upgrade {fix_pr_node['componentName']} to version {fix_pr_node['versionTo']} fix known security vulerabilities"
        if pull_request_title in pulls:
            if (globals.debug): print(f"DEBUG: Skipping pull request for {fix_pr_node['componentName']}' version '{fix_pr_node['versionFrom']} as it is already present")
            continue

        if (fix_pr_node['ns'] == "npmjs"):
            files_to_patch = NpmUtils.upgrade_npm_dependency(fix_pr_node['filename'], fix_pr_node['componentName'], fix_pr_node['versionFrom'], fix_pr_node['versionTo'])
            if (globals.debug): print(f"DEBUG: Files to patch are: {files_to_patch}")

            github_commit_file_and_create_fixpr(g, github_token, github_api_url, github_repo, github_branch, files_to_patch, fix_pr_node)
        elif (fix_pr_node['ns'] == "maven"):
            files_to_patch = MavenUtils.upgrade_maven_dependency(fix_pr_node['filename'], fix_pr_node['componentName'], fix_pr_node['versionFrom'], fix_pr_node['versionTo'])
            if (globals.debug): print(f"DEBUG: Files to patch are: {files_to_patch}")
            github_commit_file_and_create_fixpr(g, github_token, github_api_url, github_repo, github_branch,
                                                files_to_patch, fix_pr_node)
        else:
            print(f"INFO: Generating a Fix PR for packages of type '{fix_pr_node['ns']}' is not supported yet")

# Optionally comment on the pull request this is for

if (comment_pr and len(comment_on_pr_comments) > 0):
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_ref = os.getenv("GITHUB_REF")
    github_api_url = os.getenv("GITHUB_API_URL")
    github_sha = os.getenv("GITHUB_SHA")

    if (github_token == None or github_repo == None or github_ref == None or github_api_url == None or github_sha == None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF, GTIHUB_SHA and/or GITHUB_API_URL in the environment - are you running from a GitHub action?")
        sys.exit(1)

    if (globals.debug): print(f"DEBUG: Connect to GitHub at {github_api_url}")
    g = Github(github_token, base_url=github_api_url)

    if (globals.debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (globals.debug): print(repo)

    if (globals.debug): print(f"DEBUG: Look up GitHub ref '{github_ref}'")
    # Remove leading refs/ as the API will prepend it on it's own
    # Actually look pu the head not merge ref to get the latest commit so
    # we can find the pull request
    ref = repo.get_git_ref(github_ref[5:].replace("/merge", "/head"))
    if (globals.debug):
        print(ref)

    # Look for this pull request by finding the first commit, and then looking for a
    # PR that matches
    # TODO Safe to assume that there are at least one commit?
    github_sha = ref.object.sha
    #for commit in ref:
    #    if (commit['object']['type'] == "commit"):
    #        github_sha = commit['object']['sha']
    #        break

    #if (github_sha == None):
    #    print(f"ERROR: Unable to find any commits for ref '{github_ref}'")
    #    sys.exit(1)

    print(f"DEBUG: Found Git sha {github_sha} for ref '{github_ref}'")

    # TODO Should this handle other bases than master?
    pulls = repo.get_pulls(state='open', sort='created', base='master', direction="desc")
    pr = None
    pr_commit = None
    if (globals.debug): print(f"DEBUG: Pull requests:")
    pull_number_for_sha = 0
    for pull in pulls:
        if (globals.debug): print(f"DEBUG: Pull request number: {pull.number}")
        # Can we find the current commit sha?
        commits = pull.get_commits()
        for commit in commits.reversed:
            if (globals.debug): print(f"DEBUG:   Commit sha: " + str(commit.sha))
            if (commit.sha == github_sha):
                if (globals.debug): print(f"DEBUG:     Found")
                pull_number_for_sha = pull.number
                pr = pull
                pr_commit = commit
                break
        if (pull_number_for_sha != 0): break

    if (pull_number_for_sha == 0):
        print(f"ERROR: Unable to find pull request for commit '{github_sha}'")
        sys.exit(1)

    # Tricky here, we want everything all in one comment. So prepare a header, then append each of the comments and
    # create a comment
    comments_markdown = ["| Component | Type | Vulnerability | Severity |  Description | Vulnerable version | Upgrade to |",
                                        "| --- | --- | --- | --- | --- | --- | --- |"]

    for comment in comment_on_pr_comments:
        comments_markdown.append(comment)

    if (globals.debug): print(f"DEUBG: Comment on Pull Request #{pr.number} for commit {github_sha}")
    github_create_pull_request_comment(g, github_repo, pr, pr_commit, comments_markdown, "")

if (len(comment_on_pr_comments) > 0):
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_ref = os.getenv("GITHUB_REF")
    github_api_url = os.getenv("GITHUB_API_URL")
    github_sha = os.getenv("GITHUB_SHA")

    if (github_token == None or github_repo == None or github_ref == None or github_api_url == None or github_sha == None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF, GTIHUB_SHA and/or GITHUB_API_URL in the environment - are you running from a GitHub action?")
        sys.exit(1)

    if (globals.debug): print(f"DEBUG: Set check status for commit '{github_sha}', connect to GitHub at {github_api_url}")
    g = Github(github_token, base_url=github_api_url)

    if (globals.debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (globals.debug): print(repo)

    status = repo.get_commit(sha=github_sha).create_status(
        state="error",
        target_url="https://FooCI.com",
        description="Black Duck security scan found vulnerabilities",
        context="Synopsys Black Duck"
    )
    if (globals.debug):
        print(f"DEBUG: Status:")
        print(status)

    print(f"INFO: Vulnerable components found, returning exit code 1")
    sys.exit(1)
else:
    print(f"INFO: No new components found, nothing to report")
    sys.exit(0)