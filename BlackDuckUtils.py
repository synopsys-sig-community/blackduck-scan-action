import subprocess

def run_detect(jarfile, runargs):
    print('INFO: Running Black Duck Detect')

    args = ['java', '-jar', jarfile]
    args += runargs
    print("DEBUG: Command = ")
    print(args)

    proc = subprocess.Popen(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pvurl = ''
    projname = ''
    vername = ''
    while True:
        outp = proc.stdout.readline()
        if proc.poll() is not None and outp == '':
            break
        if outp:
            print(outp.strip())
            bomstr = ' --- Black Duck Project BOM:'
            projstr = ' --- Project name:'
            verstr = ' --- Project version:'
            # noinspection PyTypeChecker
            if outp.find(bomstr) > 0:
                pvurl = outp[outp.find(bomstr) + len(bomstr) + 1:].rstrip()
            if outp.find(projstr) > 0:
                projname = outp[outp.find(projstr) + len(projstr) + 1:].rstrip()
            if outp.find(verstr) > 0:
                vername = outp[outp.find(verstr) + len(verstr) + 1:].rstrip()
    retval = proc.poll()

    if retval != 0:
        print('ERROR: detect_wrapper - Detect returned non-zero value')
        #sys.exit(2)

    if projname == '' or vername == '':
        print('ERROR: detect_wrapper - No project or version identified from Detect run')
        #sys.exit(3)

    return '/'.join(pvurl.split('/')[:8]), projname, vername, retval
