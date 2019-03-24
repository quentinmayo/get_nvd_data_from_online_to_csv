#!/usr/bin/env python3

# Quick Script to covert NVD information to CVE records
# Removed the need to store xml and zip files on the disk 

# In[90]:

__author__ = "Quentin Mayo"
__copyright__ = "None"
__credits__ = ["Quentin Mayo"]
__license__ = "None"
__version__ = "1.0.0"
__maintainer__ = "Quentin Mayo"
__email__ = "N/A"
__status__ = "Production"


#Imports 
import os
import re
import io
import csv
import ssl
import glob
import time
import zipfile
import requests
import argparse
import urllib.request
from datetime import date
from zipfile import ZipFile
from bs4 import BeautifulSoup


# Command Line Section

class RawTextArgumentDefaultsHelpFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawTextHelpFormatter
    ):
        pass

parser = argparse.ArgumentParser(
    formatter_class=RawTextArgumentDefaultsHelpFormatter,description='''This program simplifies the process of converting nvd data into an csv. The goal was to make this program
    robust enough that anyone could find use out of this script.  If you goal is to get all CVE information in an cve or due some filtering based on this month, this program can handle
    that task. Though this tool can be used by a layman, to get the most out of this tool, some understanding of xml and the raw nvd data will be very helpful.  This script 
    was built with apis in mind.
 '''


)
data_map_string ='CVE|vuln:cve-id,vulnerable-configuration|cpe-lang:fact-ref,vulnerable-software-list|vuln:product,cvss:score|cvss:score,cvss:access-vector|cvss:access-vector,cvss:access-complexity|cvss:access-complexity,cvss:confidentiality-impact|cvss:confidentiality-impact,cvss:integrity-impact|cvss:integrity-impact,cvss:availability-impact|cvss:availability-impact,cvss:source|cvss:source,vuln:summary|vuln:summary'

parser.add_argument('-cve_information_path', default="cve_information.csv", help='''Output csv file. You can also provide a path(example:results/cve_information.csv''')
parser.add_argument('-custom_filter_string', default="", help='''Setting this value will allow you to filter a given column via regex. The default reserve spacer is 
[|], you can override this by setting the custom_filter_string_spacer. 

Example 'CVE[|]2019' will filter everything in the column CVE defined in -data_map_string by the regex 2019.
''')
parser.add_argument('-custom_filter_string_spacer', default="[|]", help='''View -custom_filter_string''')
parser.add_argument('-date_range_string', default="2002|today", help='''Set the date range for loading the NVD xml files. the NVD files are broken up into years. 
    "type is keyword that will return that year. If you want just one year, you will need to say that year twice(ex: 2002|2002). pipe (|) is the breaker between the beginning and ending year''')


parser.add_argument('-data_map_string', default=data_map_string, help='''
    This an advance setting but it allows any to customize the csv output. This command require some understanding of 
    the nvd xml format and Python's beautifulsoup library.cve_information is string input that is seperated by pipes(|).
    Each item denotes a column in the csv.

    index [0]
        This column is the csv column name
    index =[1]
        This column tells the output. it will output the value if available . THe currently supported items are below
            cpe-lang:logical-test -->  this will return a list seperated by ","  of vulnerable-configurations
            vuln:vulnerable-software-list -->  this will return a list seperated by ","  of vulnerable-products
            [others] --> if want to something else out, just provide the tag name. the script will automationly pull out
                the string(ex: vuln:cve-id will give you back CVE-1999-0002 )


            A sample Entry is below:

                <entry id="CVE-1999-0002">
                    <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
                    <cpe-lang:logical-test operator="OR" negate="false">
                        <cpe-lang:fact-ref name="cpe:/o:bsdi:bsd_os:1.1"/>
                        <cpe-lang:fact-ref name="cpe:/o:caldera:openlinux:1.2"/>
                    </cpe-lang:logical-test>
                    </vuln:vulnerable-configuration>
                    <vuln:vulnerable-software-list>
                    <vuln:product>cpe:/o:bsdi:bsd_os:1.1</vuln:product>
                    <vuln:product>cpe:/o:caldera:openlinux:1.2</vuln:product>
                    </vuln:vulnerable-software-list>
                    <vuln:cve-id>CVE-1999-0002</vuln:cve-id>
                    <vuln:published-datetime>1998-10-12T00:00:00.000-04:00</vuln:published-datetime>
                    <vuln:last-modified-datetime>2009-01-26T00:00:00.000-05:00</vuln:last-modified-datetime>
                    <vuln:cvss>
                    <cvss:base_metrics>
                        <cvss:score>10.0</cvss:score>
                        <cvss:access-vector approximated="true">NETWORK</cvss:access-vector>
                        <cvss:access-complexity approximated="true">LOW</cvss:access-complexity>
                        <cvss:authentication approximated="true">NONE</cvss:authentication>
                        <cvss:confidentiality-impact approximated="true">COMPLETE</cvss:confidentiality-impact>
                        <cvss:integrity-impact approximated="true">COMPLETE</cvss:integrity-impact>
                        <cvss:availability-impact approximated="true">COMPLETE</cvss:availability-impact>
                        <cvss:source>http://nvd.nist.gov</cvss:source>
                        <cvss:generated-on-datetime>2004-01-01T00:00:00.000-05:00</cvss:generated-on-datetime>
                    </cvss:base_metrics>
                    </vuln:cvss>
                    <vuln:security-protection>ALLOWS_ADMIN_ACCESS</vuln:security-protection>
                    <vuln:cwe id="CWE-119"/>
                    <vuln:references xml:lang="en" reference_type="UNKNOWN">
                    <vuln:source>SGI</vuln:source>
                    <vuln:reference href="ftp://patches.sgi.com/support/free/security/advisories/19981006-01-I" xml:lang="en">19981006-01-I</vuln:reference>
                    </vuln:references>
                    <vuln:references xml:lang="en" reference_type="UNKNOWN">
                    <vuln:source>CIAC</vuln:source>
                    <vuln:reference href="http://www.ciac.org/ciac/bulletins/j-006.shtml" xml:lang="en">J-006</vuln:reference>
                    </vuln:references>
                    <vuln:references xml:lang="en" reference_type="VENDOR_ADVISORY">
                    <vuln:source>BID</vuln:source>
                    <vuln:reference href="http://www.securityfocus.com/bid/121" xml:lang="en">121</vuln:reference>
                    </vuln:references>
                    <vuln:summary>Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.</vuln:summary>
                </entry>

         
''' )

# Functions 

# make dir
def mkdir(path):
    try:
        os.makedirs(path)
    except OSError:
        pass

def soup_get_attribute_text(entry,attribute,default_missing_message="None Found"):
    if(entry.find(attribute)):
        return entry.find(attribute).text
    return default_missing_message

def extract_zip(input_zip):
    input_zip=ZipFile(input_zip)
    return [input_zip.read(name) for name in input_zip.namelist()]
        
def get_year(year):
    if year == "today":
        return date.today().year
    return int(year)

def get_nvd_data(soup,data_map,custom_filter_map):
    # Wall time: 1min 25s
    cve_information = []
    for entry in soup.find_all("entry"):
        if(entry.find("vuln:cve-id")):
            temp_entry = {}
            for item  in data_map:
                if(item[1] == "cpe-lang:fact-ref"): temp_entry[item[0]] = ",".join([x["name"] for x in entry.find_all("cpe-lang:fact-ref")])
                elif(item[1] == "vuln:product"):
                    temp_entry[item[0]] = ",".join([x.text for x in entry.find_all("vuln:product")])
                else: temp_entry[item[0]] = soup_get_attribute_text(entry,item[1])
                    
            if(len(custom_filter_map)==2):
                if(re.match(custom_filter_map[1], temp_entry[custom_filter_map[0]])):
                    cve_information+=[temp_entry]
            else:
                cve_information+=[temp_entry]
    return cve_information



def main(parser):
    # parser.print_help()
    args = parser.parse_args()
    print("Data from args:")
    print("cve_information_path:%s" % args.cve_information_path)
    print("data_map_string:%s" % args.data_map_string)
    print("custom_filter_string:%s" % args.custom_filter_string)
    print("date_range_string:%s" % args.date_range_string)
    print("custom_filter_string_spacer:%s" % args.custom_filter_string_spacer)
    print("Load Args into Variables")
    get_nvd_data_from_online(args.cve_information_path,args.data_map_string,args.custom_filter_string,args.date_range_string,args.custom_filter_string_spacer,outfile=True)

def get_nvd_data_from_online(cve_information_path,data_map_string,custom_filter_string,date_range_string,custom_filter_string_spacer,outfile=False):
    print("Clean Up user data")
    data_map = list(map(lambda x:x.split("|") ,data_map_string.split(",")))
    keys = list(map(lambda x:x.split("|")[0] ,data_map_string.split(",")))
    custom_filter_map = custom_filter_string.split(custom_filter_string_spacer)
    date_range = date_range_string.split("|")
    cve_data  = []    
    # Fix ssl issue with nvd.nist.gov 
    ssl._create_default_https_context = ssl._create_unverified_context

    for index,year in enumerate(range(get_year(date_range[0]),get_year(date_range[1])+1)):
        start = time.time()
        url = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.zip" %(year)
        # this is loaded statement, it takes the output form xml zip, converts 
        #     it ot Byte IO stream, unzip it, and then send
        #     that information to BeatuifulSoup which is a xml parser
        print("Loading(%s):%s"%(index,url))
        soup_data = BeautifulSoup(extract_zip(io.BytesIO(requests.get(url, stream=True).content))[0], 'lxml')
        print("Extracting Data from Data(%s)"%(index))
        cve_data.extend(get_nvd_data(soup_data,data_map,custom_filter_map))
        print("Total Compute Time(s) forData(%s) = %s"%(index,time.time() - start))


    # Output to file
    if(outfile):
        mkdir(os.path.split(cve_information_path)[0])
        with open(cve_information_path, 'w',newline='') as csvFile:
            writer = csv.writer(csvFile)
            writer.writerow(keys)
            writer.writerows([[x[y] for y in keys] for x in cve_data])
    return cve_data
if __name__ == "__main__":
    main(parser)