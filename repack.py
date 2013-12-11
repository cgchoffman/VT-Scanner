#!/usr/bin/env python

import zipfile
import subprocess as sub
import os
MAX_ARCH_SIZE= 50000000
home = os.path.expanduser("~")
# XXX This should get passed in as an arguement
installername = "Komodo-Edit-7.1.3-11027.msi"
installpath = os.path.join(home,"VT-scanner", "TEMP")
if not os.path.exists(installpath):
    os.makedirs(installpath)
command = "msiexec /qb /a %s TARGETDIR=%s" %(installername, installpath)
sub.call(command.split())
def getBuild(filename):
    return filename[filename.find("-") + 1:filename.rfind(".")]
def pack(path, batch):
    batch.write(path)
def createZip(name):
    try:
        import zlib
        mode= zipfile.ZIP_DEFLATED
    except:
        mode= zipfile.ZIP_STORED
    return zipfile.ZipFile(name, "a", mode)

arch_size = 0
batch_cycle = 5
batch_version = getBuild(installername)
zipbasename = "batch-%s" % batch_version
zipname  = zipbasename + "-%s.zip" % batch_cycle
zipbatch = createZip(zipname)
zipFileNames = []
for d, dirs, files in os.walk("TEMP"):
    for f in files:
        if arch_size <= MAX_ARCH_SIZE:
            if f != None:
                filepath = os.path.join(d,f)
                fPath = os.stat(filepath)
                pack(filepath, zipbatch)
                arch_size += fPath.st_size
        else:
            zipbatch.close()
            zipFileNames.append(zipbatch.filename)
            arch_size = 0
            batch_cycle += 1
            zipname = zipbasename + "-%s.zip" % batch_cycle
            zipbatch = createZip(zipname)

import uploadFile
import time
def get_report(filename):
    report = uploadFile.get_report(filename)
    if report !=  None and report != 1:
        return report
    else:
        get_report(filename)

for f in zipFileNames:
    # submit the files
    uploadFile.scan_file(f)
time.sleep(60)
allreports = []
for f in zipFileNames:
    # try to retrieve the reports
    allreports.append(get_report(f))
print allreports

print "done!"

#z.extractall("Komodo-Edit-7.1.3-11027.msi")