import os
import re
import shutil
import globals
import sys

import xml.etree.ElementTree as ET

from BlackDuckUtils import run_detect

class MyTreeBuilder(ET.TreeBuilder):
   def comment(self, data):
       self.start(ET.Comment, {})
       self.data(data)
       self.end(ET.Comment)


def parse_component_id(component_id):
    comp_domain = ""
    comp_org = ""
    comp_name = ""
    comp_version = ""

    # Example: maven:org.springframework:spring-webmvc:4.2.3.RELEASE
    comp_domain = component_id.split(':')[0]
    comp_org = component_id.split(':')[1]
    comp_name = component_id.split(':')[2]
    comp_version = component_id.split(':')[3]

    return comp_domain, comp_name, comp_version

def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id)
    return bdio_name


def upgrade_maven_dependency(package_file, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename
    files_to_patch = dict()

    dirname = "snps-patch-" + component_name + "-" + component_version
    os.mkdir(dirname)

    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))

    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")

    tree = ET.parse(package_file, parser=ET.XMLParser(target=MyTreeBuilder()))
    root = tree.getroot()

    nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

    if (globals.debug): print(f"DEBUG: Search for maven dependency {component_name}@{component_version}")

    for dep in root.findall('.//m:dependencies/m:dependency', nsmap):
        groupId = dep.find('m:groupId', nsmap).text
        artifactId = dep.find('m:artifactId', nsmap).text
        version = dep.find('m:version', nsmap).text

        # TODO Also include organization name?
        if (artifactId == component_name):
            if (globals.debug): print(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
            dep.find('m:version', nsmap).text = component_version

    xmlstr = ET.tostring(root, encoding='utf8', method='xml')
    with open(dirname + "/" + package_file, "wb") as fp:
        fp.write(xmlstr)

    print(f"INFO: Updated Maven component in: {package_file}")

    files_to_patch[package_file] = dirname + "/" + package_file

    return files_to_patch

def attempt_indirect_upgrade(node_name, node_version, direct_name, direct_version):
    print(f"INFO: Attempting to upgrade indirect dependency {node_name}@{node_version} via {direct_name}@{direct_version}")
    return False

    ok = False

    dirname = "snps-upgrade-" + direct_name + "-" + direct_version
    os.mkdir(dirname)
    os.chdir(dirname)

    cmd = "npm install " + direct_name + "@" + direct_version
    print(f"INFO: Executing NPM to install component: {cmd}")
    err = os.system(cmd)
    if (err > 0):
        print(f"ERROR: Error {err} executing NPM command")
        return False

    pvurl, projname, vername, retval = run_detect(globals.detect_jar, [ "--blackduck.url=https://testing.blackduck.synopsys.com",
        "--blackduck.api.token=MDI0YTUxNzEtNWRlOS00ZWVjLWExMjgtYWJiODk4YjRjYjJlOjM4Mzk5Y2ZlLTJmOWItNDg1NC1hZTM4LWE4YjQwYjA4YzE2Yg==",
        "--detect.blackduck.scan.mode=rapid"])

    sys.exit(1)

    if (retval > 0):
        return False

    return True

