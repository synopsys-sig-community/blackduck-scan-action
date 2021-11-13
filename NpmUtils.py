import os
import re
import shutil
import sys

import globals

from BlackDuckUtils import run_detect


def foo(bar):
    return bar


def parse_component_id(component_id):
    comp_domain = ""
    comp_name = ""
    comp_version = ""

    # Example: npmjs:trim-newlines/2.0.0
    comp_domain = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1]
    comp_name = comp_name_and_version.split('/')[0]
    comp_version = comp_name_and_version.split('/')[1]

    return comp_domain, comp_name, comp_version

def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id, 1)
    return bdio_name

def upgrade_npm_dependency(package_file, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename
    files_to_patch = dict()

    dirname = "snps-patch-" + component_name + "-" + component_version
    os.mkdir(dirname)
    shutil.copy2(package_file, dirname + "/" + package_file)
    os.chdir(dirname)

    cmd = "npm install " + component_name + "@" + component_version
    print(f"INFO: Executing NPM to update component: {cmd}")
    err = os.system(cmd)
    if (err > 0):
        print(f"ERROR: Error {err} executing NPM command")
        os.chdir("..")
        return None

    os.chdir("..")
    # Keep files so we can commit them!
    #shutil.rmtree(dirname)

    files_to_patch["package.json"] = dirname + "/package.json"
    files_to_patch["package-lock.json"] = dirname + "/package-lock.json"

    return files_to_patch

def attempt_indirect_upgrade(node_name, node_version, direct_name, direct_version):
    print(f"INFO: Attempting to upgrade indirect dependency {node_name}@{node_version} via {direct_name}@{direct_version}")

    ok = False

    dirname = "snps-upgrade-" + direct_name + "-" + direct_version
    os.mkdir(dirname)
    os.chdir(dirname)

    cmd = "npm install " + direct_name + "@" + direct_version
    print(f"INFO: Executing NPM to install component: {cmd}")
    err = os.system(cmd)
    if (err > 0):
        print(f"ERROR: Error {err} executing NPM command")
        os.chdir("..")
        return False

    pvurl, projname, vername, retval = run_detect(globals.detect_jar, [ "--blackduck.url=https://testing.blackduck.synopsys.com",
        "--blackduck.api.token=MDI0YTUxNzEtNWRlOS00ZWVjLWExMjgtYWJiODk4YjRjYjJlOjM4Mzk5Y2ZlLTJmOWItNDg1NC1hZTM4LWE4YjQwYjA4YzE2Yg==",
        "--detect.blackduck.scan.mode=rapid"])

    os.chdir("..")

    #sys.exit(1)

    if (retval > 0):
        return False

    return True

