# README

This program simplifies the process of converting nvd data into an csv. The goal was to make this program     robust enough that anyone could find use out of this script.  If you goal is to get all CVE information in an cve or due some filtering based on this month, this program can handle that task. Though this tool can be used by a layman, to get the most out of this tool, some understanding of xml and the raw nvd data will be very helpful.  This script  was built with apis in mind. 


# New Features!

  - None Yet. . .



### Tech

this script was built using Python 3.7.1, Inc.. However,  the script should still run on Python 2.7 if you have BeautifulSoup installed. 

The script pulls NVD data from https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-[year].xml.zip. Unzips it in memory and converts that data into a beautifulsoup object for parsing.  

### Installation

get_nvd_data_from_online requires [Python](https://www.python) to run. Note installing [Anaconda's Python](https://www.anaconda.com/) will come default will the required dependencies. 


### How to Run

to see all the commands, run 
```
PS E:\Projects\python\get_nvd_data_from_online_to_csv> python .\get_nvd_data_from_online.py -h
usage: get_nvd_data_from_online.py [-h]
                                   [-cve_information_path CVE_INFORMATION_PATH]
                                   [-custom_filter_string CUSTOM_FILTER_STRING]
                                   [-custom_filter_string_spacer CUSTOM_FILTER_STRING_SPACER]
                                   [-date_range_string DATE_RANGE_STRING]
                                   [-data_map_string DATA_MAP_STRING]

This program simplifies the process of converting nvd data into an csv. The goal was to make this program     robust enough that anyone could find use out of this script.  If you goal is to get all CVE information in an cve or due some filtering based on this month, this program can handle that task. Though this tool can be used by a layman, to get the most out of this tool, some understanding of xml and the raw nvd data will be very helpful.
 This script     was built with apis in mind.


optional arguments:
  -h, --help            show this help message and exit
  -cve_information_path CVE_INFORMATION_PATH
                        Output csv file. You can also provide a path(example:results/cve_information.csv (default: cve_information.csv)
  -custom_filter_string CUSTOM_FILTER_STRING
                        Setting this value will allow you to filter a given column via regex. The default reserve spacer is
                        [|], you can override this by setting the custom_filter_string_spacer.

                        Example 'CVE[|]2019' will filter everything in the column CVE defined in -data_map_string by the regex 2019.
                         (default: )
  -custom_filter_string_spacer CUSTOM_FILTER_STRING_SPACER
                        View -custom_filter_string (default: [|])
  -date_range_string DATE_RANGE_STRING
                        Set the date range for loading the NVD xml files. the NVD files are broken up into years.
                            "type is keyword that will return that year. If you want just one year, you will need to say that year twice(ex: 2002|2002). pipe (|) is the breaker between the beginning and ending year (default: 2002|today)
  -data_map_string DATA_MAP_STRING

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


                         (default: CVE|vuln:cve-id,vulnerable-configuration|cpe-lang:fact-ref,vulnerable-software-list|vuln:product,cvss:score|cvss:score,cvss:access-vector|cvss:access-vector,cvss:access-complexity|cvss:access-complexity,cvss:confidentiality-impact|cvss:confidentiality-impact,cvss:integrity-impact|cvss:integrity-impact,cvss:availability-impact|cvss:availability-impact,cvss:source|cvss:source,vuln:summary|vuln:summary)
PS E:\Projects\python\get_nvd_data_from_online_to_csv>
```
to run the program using default settings, just run the command below
```Powershell
$  python .\get_nvd_data_from_online.py
```

This will output cve_information.csv into the current directory with the folowing information for all CVEs 



| CVE           | vulnerable-configuration | vulnerable-software-list | cvss:score | cvss:access-vector | cvss:access-complexity | cvss:confidentiality-impact | cvss:integrity-impact | cvss:availability-impact | cvss:source         | vuln:summary                                                                                                                               |
|---------------|--------------------------|--------------------------|------------|--------------------|------------------------|-----------------------------|-----------------------|--------------------------|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-1999-0001 | ...                      | ...                      | 5          | NETWORK            | LOW                    | NONE                        | NONE                  | PARTIAL                  | http://nvd.nist.gov | ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets. |
| CVE-1999-0002 | ...                      | ...                      | 10         | NETWORK            | LOW                    | COMPLETE                    | COMPLETE              | COMPLETE                 | http://nvd.nist.gov | Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.    

to run the program to get all cves for this year , just run the command below
```Powershell
$  python .\get_nvd_data_from_online.py -date_range_string 'today|today'
```
