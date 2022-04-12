#
# Author: Alex Sullivan, Peter Green
# Version: 1.2
# Usage:
# python3 tldr.py --log /path/to/blackduck_bds.zip
# python3 tldr.py --log /path/to/blackduck_bds
# Optional properties:
# --size SMALL/STANDARD
# --string "StringToSearch"
# --scanid "ID to search/analyze"
# --skip-summary true
# --fuzzy-search "String to fuzzy search"
# --keywords "comma,delimited,list,of,words,to,search,for"
# Comment for IO testing purpose

import sys
import argparse
from zipfile import ZipFile
import zipfile
import os
import re
from glob import glob
from shutil import copyfile
from pathlib import Path
import datetime
from fuzzywuzzy import fuzz

parser = argparse.ArgumentParser("Parse anomalies from BD logs")
parser.add_argument("--log", dest="logPath", required=True, help="Path to log directory or zip")
parser.add_argument("--size", dest='pkgSize', required=False, help="Set which size logs to examine")
parser.add_argument("--string", dest='string', required=False, help="Set string for string searching")
parser.add_argument("--scanid", dest='scanid', required=False, help="Set string for scanID searching")
parser.add_argument("--skip-summary", dest='skipsum', required=False, help="Set to skip log summary")
parser.add_argument("--fuzzy-search", dest='fuzz', required=False,
                    help="Set string to fuzzy search against log package")
parser.add_argument("--keywords", dest='keywords', required=False,
                    help="Quote wrapped comma delimited list of keywords to search against log package.")
parser.add_argument("--isCoverity", dest='isCoverity', required=False,
                    help="If set to TRUE, will disable Black Duck specific features like ")
args = parser.parse_args()

if str(args.isCoverity).upper() == "TRUE":
    isCoverity = True
else:
    isCoverity = False

logPath = str(args.logPath)
logName = os.path.basename(os.path.splitext(logPath)[0])
pkgSize = args.pkgSize
stringPattern = str(args.string)
targetScanId = str(args.scanid)
skipSum = str(args.skipsum)
fuzzString = str(args.fuzz)
keywords = str(args.keywords)

api_pattern = r"limit=[3-9]\d{2,}"
pattern = "WARN|ERROR|^\tat |Exception|^Caused by: |\t... \d+ more"
grepString = re.compile(pattern)
cwd = os.getcwd()
logDir = (cwd + "/" + logName)
currentTime = datetime.datetime.now()
timestamp = currentTime.timestamp()
tldrDir = (cwd + "/tldr-" + logName + "-" + str(int(timestamp)))


def printError():
    print("Error: " + str(sys.exc_info()[0]))


if os.path.isdir(logPath):
    logDir = logPath

if not os.path.exists(logDir):
    try:
        os.mkdir(logDir)
    except IOError:
        printError()

if not os.path.exists(tldrDir):
    os.mkdir(tldrDir)


def banner():
    print("----------------------------------")
    print(" _____ _    ____________  ")
    print("|_   _| |   |  _  \ ___ \ ")
    print("  | | | |   | | | | |_/ / ")
    print("  | | | |   | | | |    /  ")
    print("  | | | |___| |/ /| |\ \  ")
    print("  \_/ \_____/___/ \_| \_| ")
    print("----------------------------------")
    print("Black Duck / Coverity Log Summary Tool")
    print("----------------------------------")


def unpack(size):
    sizestr = str(size)
    if os.path.isdir(logPath):
        try:
            if sizestr.upper() == 'SMALL':
                print("Unpacking small.zip")
                if os.path.isfile(logDir + "/small.zip"):
                    with ZipFile(logDir + "/small.zip", 'r') as logs:
                        logs.extractall(logDir)
            elif sizestr.upper() == 'STANDARD':
                print("Unpacking standard.zip")
                print("WARNING: parsing standard.zip may take longer than expected.")
                if os.path.isfile(logDir + "/standard.zip"):
                    with ZipFile(logDir + "/standard.zip", 'r') as logs:
                        logs.extractall(logDir)
            else:
                print('No size configured. Defaulting to small')
                if os.path.isfile(logDir + "/small.zip"):
                    with ZipFile(logDir + "/small.zip", 'r') as logs:
                        logs.extractall(logDir)
        except IOError:
            printError()
    if zipfile.is_zipfile(logPath):
        try:
            with ZipFile(args.logPath, 'r') as zipObj:
                zipObj.extractall(logName)
            if sizestr.upper() == 'SMALL':
                print("Unpacking small.zip")
                if os.path.isfile(logDir + "/small.zip"):
                    with ZipFile(logDir + "/small.zip", 'r') as logs:
                        logs.extractall(logDir)
            elif sizestr.upper() == 'STANDARD':
                print("Unpacking standard.zip")
                print("WARNING: parsing standard.zip may take longer than expected.")
                if os.path.isfile(logDir + "/standard.zip"):
                    with ZipFile(logDir + "/standard.zip", 'r') as logs:
                        logs.extractall(logDir)
            else:
                print('No size configured. Defaulting to small')
                if os.path.isfile(logDir + "/small.zip"):
                    with ZipFile(logDir + "/small.zip", 'r') as logs:
                        logs.extractall(logDir)
        except IOError:
            printError()
        finally:
            print("----------------------------------")


def summarize():
    print("Summarizing Errors, Warns, Exceptions, Stack traces...")
    print("----------------------------------")
    if str(isCoverity).upper() == "TRUE":
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.txt*'))])
    else:
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log*'))])
    for i in result:
        print(i[len(logDir) + 1:len(i)])
        container = str(os.path.basename(os.path.normpath(Path(i).resolve().parents[1])))
        try:
            file = open(i, "r")
            output = open(tldrDir + "/" + container + ".log", "a")
            output.write("\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\nFILE: " + str(
                i[len(logDir) + 1:len(i)]) + "\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n\n")
            for line in file:
                if re.findall(grepString, line):
                    try:
                        output.write(line)
                    except IOError:
                        printError()
            output.close()
            file.close()
        except IOError:
            printError()
    print("----------------------------------")


def stringSearch(pattern):
    print("Running string search on: \"" + pattern + "\"")
    print("----------------------------------")
    result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log'))])
    for i in result:
        print(i[len(logDir) + 1:len(i)])
        try:
            file = open(i, "r")
            output = open(tldrDir + "/string.log", "a")
            output.write("\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\nFILE: " + str(
                i[len(logDir) + 1:len(i)]) + "\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n")
            for line in file:
                if re.findall(pattern, line):
                    try:
                        output.write(line)
                    except IOError:
                        printError()
            output.close()
            file.close()
        except IOError:
            printError()
    print("----------------------------------")

def api_problem_calls(api_pattern):
    print("Running api search on: \"" + api_pattern + "\"")
    print("----------------------------------")
    result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log'))])
    include_pattern = "hub-webserver"
    include = re.compile(include_pattern)
    exclude_pattern = "app-log|gc-log|nginx-errors|scansummary|debug"
    exclude = re.compile(exclude_pattern)
    try:
        for i in result:
            if not re.findall(include, i):
                continue
            if re.findall(exclude, i):
                continue
            print(i)
            file = open(i, "r")
            output = open(tldrDir + "/suspect_api_calls.log", "a")
            output.write("\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\nFILE: " + str(
                i[len(logDir) + 1:len(i)]) + "\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n")
            for line in file:
                if re.findall(api_pattern, line):
                    try:
                        output.write(line)
                    except IOError:
                        printError()
            output.close()
            file.close()
    except IOError:
        printError()
    print("----------------------------------")


# Thanks Madhu
def scanTimeToComplete():
    print("Analyzing time to completion per scan")
    print("----------------------------------")
    underTen = []
    overTen = []
    overFifteen = []
    allTime = []

    result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log*'))])
    for i in result:
        try:
            file = open(i, "r")
            output = open(tldrDir + "/scanTime.log", "a")
            for line in file:
                if re.findall("updated to status COMPLETE", line):
                    splitString = line.split(" ")
                    splitString1 = line.split("updated to status COMPLETE ")
                    scanID = (splitString[9])
                    scanTime = str(re.findall("\d+\.\d+", splitString1[1]))[2:-2]
                    try:
                        output.write("ScanID:  " + scanID + "\n" + "Time to completion: " + scanTime + " seconds\n\n")
                        if float(scanTime) < 600:
                            underTen.append(scanID)
                            allTime.append(float(scanTime))
                        elif 600 <= float(scanTime) < 895:
                            overTen.append(scanID)
                            allTime.append(float(scanTime))
                        elif 895 <= float(scanTime):
                            overFifteen.append(scanID)
                            allTime.append(float(scanTime))
                    except IOError:
                        printError()
            output.close()
            file.close()
        except IOError:
            printError()
    print("Number of scans under 10min: " + str(len(underTen)))
    print("Number of scans over 10min: " + str(len(overTen)))
    print("Number of scans over 15min: " + str(len(overFifteen)))
    allTime.sort(reverse=True)
    if len(overFifteen) == 0:
        print("No scans exceeded the Detect timeout")
    else:
        print("Suggested timeout limit to allow under 1% of failure: " + str(
            round(float(allTime[int(len(allTime) / 100)]))) + " seconds")
    try:
        print("Longest scan time: " + str(round(float(allTime[0]))) + " seconds")
    except IndexError:
        print("Did not find any scans.")


def searchScanId(scanid):
    print("Searching for scan ID: " + scanid)
    print("----------------------------------")
    if str(isCoverity).upper() == "TRUE":
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.txt*'))])
    else:
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log*'))])
    dates = []
    includePattern = "hub-scan|blackduck-bomengine|blackduck-matchengine|rabbitmq|jobrunner"
    include = re.compile(includePattern)
    excludePattern = "access-log|scansummary|debug"
    exclude = re.compile(excludePattern)
    try:
        for i in result:
            if not re.findall(include, i):
                continue
            if re.findall(exclude, i):
                continue
            print(i)
            file = open(i, "r")
            output = open(tldrDir + "/scanid.log", "a")
            for line in file:
                if re.findall(scanid, line):
                    try:
                        splitline = line.split(" ")
                        dates.append([splitline[1], splitline[2], splitline[0], line])
                    except IOError:
                        printError()

            file.close()
    except IOError:
        printError()
    print("----------------------------------")
    if not len(dates):
        print("No instances of scan ID: " + str(scanid))
    else:
        sorteddates = sorted(dates, key=lambda x: x[1])
        print("First instance of scan: " + str(sorteddates[0][-1]))
        print("Last instance of scan: " + str(sorteddates[-1][-1]))
        output = open(tldrDir + "/scanid.log", "a")
        count = 0
        for i in sorteddates:
            output.write(str(sorteddates[count][-1]))
            count += 1
    output.close()
    print("----------------------------------")


def sysinfo():
    print("Grabbing system, scan, and job info...")
    print("----------------------------------")
    debugDir = logName + "/debug/"
    try:
        for file in os.listdir(debugDir):
            if file.startswith("sysinfo"):
                copyfile(debugDir + file, tldrDir + "/sysinfo.log")
            if file.startswith("jobinfo"):
                copyfile(debugDir + file, tldrDir + "/jobinfo.log")
            if file.startswith("scaninfo"):
                copyfile(debugDir + file, tldrDir + "/scaninfo.log")
        for file in os.listdir(logDir):
            if file.startswith("systemcheck"):
                copyfile(logDir + "/" + file, tldrDir + "/" + file)
    except FileNotFoundError:
        print("File not found.")


def keywordSearch(kwords):
    keywordList = kwords.split(",")
    keywordPattern = kwords.replace(",", "|")
    keywordString = re.compile(keywordPattern)
    print("Keywords: ")
    for i in keywordList:
        print(i)
    print("----------------------------------")
    if str(isCoverity).upper() == "TRUE":
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.txt*'))])
    else:
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log*'))])
    for i in result:
        try:
            print(i[len(logDir) + 1:len(i)])
            file = open(i, "r")
            output = open(tldrDir + "/keywordSearch.log", "a")
            output.write("\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\nFILE: " + str(
                i[len(logDir) + 1:len(i)]) + "\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n")
            for line in file:
                try:
                    if re.findall(keywordString, line):
                        output.write(line)
                except IOError:
                    printError()
        except IOError:
            printError()
        output.close()
        file.close()
    print("----------------------------------")


def fuzzySearch(searchString):
    print("Running fuzzy search on: \"" + searchString + "\"")
    print("----------------------------------")
    if str(isCoverity).upper() == "TRUE":
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.txt*'))])
    else:
        result = sorted([y for x in os.walk(logDir) for y in glob(os.path.join(x[0], '*.log*'))])
    for i in result:
        print(i[len(logDir) + 1:len(i)])
        try:
            file = open(i, "r")
            output = open(tldrDir + "/fuzzySearch.log", "a")
            output.write("\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\nFILE: " + str(
                i[len(logDir) + 1:len(i)]) + "\n*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n")
            for line in file:
                if fuzzString.count(" ") > 0 and fuzz.partial_ratio(fuzzString.upper(), line.upper()) > 76:
                    try:
                        output.write(line)
                    except IOError:
                        printError()
                else:
                    subline = str(re.sub("[^0-9a-zA-Z]+", " ", line))
                    splitLine = subline.split(" ")
                    if fuzz.partial_ratio(searchString.upper(), subline.upper()) > 50:
                        for word in splitLine:
                            word = str(re.sub("[^0-9a-zA-Z]+", " ", word))
                            if fuzz.partial_ratio(fuzzString.upper(), word.upper()) > 75:
                                if len(word) < len(fuzzString) and fuzz.ratio(fuzzString.upper(), word.upper()) < 75:
                                    continue
                                if re.findall("^\tat", line):
                                    continue
                                try:
                                    output = open(tldrDir + "/fuzzySearch.log", "a")
                                    output.write(line)
                                    break
                                except IOError:
                                    printError()
        except IOError:
            printError()
        output.close()
        file.close()
    print("----------------------------------")


if __name__ == '__main__':
    banner()
    unpack(pkgSize)
    if skipSum.upper() != "TRUE":
        summarize()
    if stringPattern != "None":
        stringSearch(stringPattern)
    if targetScanId != "None":
        searchScanId(targetScanId)
    if keywords != "None":
        keywordSearch(keywords)
    if fuzzString != "None":
        fuzzySearch(fuzzString)
    if str(isCoverity).upper() != "TRUE":
        sysinfo()
        scanTimeToComplete()
        api_problem_calls(api_pattern)
    print("----------------------------------")
    print("All scans complete.")
