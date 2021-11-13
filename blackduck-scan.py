#!/usr/bin/env python

import argparse
import json
import sys
import os
import subprocess
import BlackDuckUtils
import WorkflowUtils
import globals


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run Black Duck Security Scan")
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')
    parser.add_argument("--url", required=True, type=str, help="Black Duck Hub URL")
    parser.add_argument("--token", required=True, type=str, help="Black Duck Hub Token")
    parser.add_argument("--project", type=str, help="Project name")
    parser.add_argument("--mode", default="intelligent", type=str,
                        help="Black Duck scanning mode, either intelligent or rapid")
    parser.add_argument("--output", default="blackduck-output", type=str, help="Output directory")
    parser.add_argument("--fix_pr", type=str, default="false", help="Create a Fix PR, true or false")
    parser.add_argument("--upgrade_major", type=str, default="false", help="Offer upgrades to major versions, true or false")
    parser.add_argument("--comment_on_pr", type=str, default="false", help="Generate a comment on pull request, true or false")
    parser.add_argument("--sarif", type=str, default="blackduck-sarif.json", help="SARIF output file")
    parser.add_argument("--incremental_results", default="false", type=str, help="Incremental output file")
    parser.add_argument("--upgrade_indirect", default="false", type=str, help="Attempt upgrade for indirect dependencies")
    parser.add_argument('--skip_detect', default=False, action='store_true', help='Skip running of detect')

    args = parser.parse_args()

    url = args.url
    token = args.token
    if (url == None or token == None):
        print(f"ERROR: Must specify Black Duck Hub URL and API Token")
        sys.exit(1)
    project = args.project
    mode = args.mode
    if (mode != "intelligent" and mode != "rapid"):
        print(f"ERROR: Scanning mode must be intelligent or rapid")
        sys.exit(1)
    output = args.output

    debug = int(args.debug)

    fix_pr = args.fix_pr
    upgrade_major = args.upgrade_major
    comment_on_pr = args.comment_on_pr
    sarif = args.sarif
    incremental_results = args.incremental_results
    upgrade_indirect = args.upgrade_indirect

    skip_detect = args.skip_detect

    runargs = []
    runargs.extend(["--blackduck.url="+url, "--blackduck.api.token="+token, "--detect.blackduck.scan.mode="+mode,
                    "--detect.policy.check.fail.on.severities=NONE",
                    "--detect.detector.buildless=true",
                    "--detect.output.path="+output, "--detect.cleanup="+"false"])

    if (project != None):
        runargs.extend(["--detect.project.name", project])

    print(f"INFO: Running Black Duck detect with the following options: {runargs}")

    pvurl, projname, vername, detect_return_code = BlackDuckUtils.run_detect(globals.detect_jar, runargs)

    print(f"INFO: Done with Black Duck run, return value {detect_return_code}")
    if (detect_return_code > 0 and detect_return_code != 3):
        print(f"ERROR: Black Duck detect returned exit code {detect_return_code}")
        sys.exit(detect_return_code)

    if (mode == "intelligent"):
        sys.exit(0)

    runargs = []
    runargs.extend(["--url=" + url, "--token=" + token, "--output_directory=" + output,
                    "--output=" + sarif, "--debug=" + str(debug)])
    if (fix_pr == "true"):
        runargs.append("--fix_pr")
    if (upgrade_major == "true"):
        runargs.append("--upgrade_major")
    if (comment_on_pr == "true"):
        runargs.append("--comment_on_pr")
    if (incremental_results == "false"):
        runargs.extend(["--all_comps"])
    if (upgrade_indirect == "true"):
        runargs.extend(["--upgrade_indirect"])


    print(f"INFO: Running Black Duck advanced workflow with the following options: {runargs}")
    workflow_return_code = WorkflowUtils.run_workflow(globals.workflow_script, runargs)

    if (workflow_return_code != 0):
        print(f"ERROR: Black Duck advanced workflow returned exit code {workflow_return_code}")

    sys.exit(workflow_return_code)
