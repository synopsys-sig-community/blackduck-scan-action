import subprocess


def run_workflow(workflow_script_file, runargs):
    print('INFO: Running Black Duck advanced workflow')

    args = ['python3', workflow_script_file]
    args += runargs
    print("DEBUG: Command = ")
    print(args)
    proc = subprocess.Popen(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
        outp = proc.stdout.readline()
        if proc.poll() is not None and outp == '':
            break
        if outp:
            print(outp.strip())
    retval = proc.poll()

    if retval != 0:
        print('ERROR: Workflow returned non-zero value')
        #sys.exit(2)

    return retval
