This repository includes the following projects:

* [jQuery](https://jquery.org/) (jquery-3.5.1.min.js) - [MIT License](https://jquery.org/license/)
* [DataTables](https://datatables.net/) (jquery.dataTables.min.js) - [MIT License](https://datatables.net/license/mit)
* [CellEdit](https://github.com/ejbeaty/CellEdit) (dataTables.cellEdit.js) - [MIT License](https://github.com/ejbeaty/CellEdit/blob/master/js/dataTables.cellEdit.js)
* [ssdeep](https://github.com/cloudtracer/ssdeep.js/blob/master/ssdeep.js) (ssdeep.js) (optional) - [MIT License](https://github.com/cloudtracer/ssdeep.js/blob/master/LICENSE)

# Catscan

Use Catscan for rapid triage of web applications across large environments. Catscan can help you quickly identify unique or uncommon applications (by MD5 hash) or targets of interest (by HTML title or the presence of a login form). Catscan is designed to fit into your existing workflow and help optimize targeting. It is not intended to replace tools like [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) or [gowitness](https://github.com/sensepost/gowitness), but can save you from scrolling through hundreds of IIS7 server splash pages.

Catscan takes as input a list of hostnames / IP addresses or an Nmap .xml file. It produces a searchable, sortable HTML file with three tables:

* All hosts by URI (including title, response code, login, response hash, and redirect)
* Hosts grouped by title (including count)
* Hosts grouped by content (including title and count)

Additional features include:

* Multithreaded
* Scan for login forms
* Take notes on the HTML report
* Export HTML tables to CSV, including notes
* Use "fuzzy hashes" [(context triggered piecewise hashes, CTPH)](https://ssdeep-project.github.io/ssdeep/index.html) to identify similar sites
* Single-click searching between tables

Catscan's utility comes from the HTML report, which uses [DataTables](https://datatables.net/), a [jQuery](https://jquery.com/) plug-in, and [CellEdit](https://github.com/ejbeaty/CellEdit).

![All hosts](https://raw.githubusercontent.com/WJDigby/catscan/master/screens/catscan1.png)
* List all scanned hosts by URI
* Links to hosts open in new window
* Search hosts by any field
* Export displayed table to CSV
* Take notes if -n / --notes option is used (notes included in CSV)

![Hosts by title](https://raw.githubusercontent.com/WJDigby/catscan/master/screens/catscan2.png)
* Sort hosts by title or count
* Quickly search all hosts table by clicking any element in this table

![Hosts by content](https://raw.githubusercontent.com/WJDigby/catscan/master/screens/catscan3.png)
* Identify unique (or common) responses by hash
* Quickly search all hosts table by clicking any element in this table

![Fuzzy hash comparison](https://raw.githubusercontent.com/WJDigby/catscan/master/screens/catscan4.png)
* Identify similar sites based on fuzzy hash values
* Set threshold for comparison

# Installation

Consider installing and running in a virtual environment:

`python3 -m venv ./`

`source ./bin/activate`

Clone the repository and install the requirements:

`git clone https://github.com/WJDigby/catscan.git`

`pip3 install -r requirements.txt`

Non-standard libraries included in the current version are jinja2, lxml, requests, xmltodict, and ssdeep.

ssdeep computes fuzzy hashes. This feature is optional in Catscan, so the ssdeep libraries are not required (and therefore not included in requirements.txt). To install ssdeep, follow the instructions on these sites:

* [Installation - python-ssdeep 3.3 documentation](https://python-ssdeep.readthedocs.io/en/latest/installation.html)
* [ssdeep - PyPI](https://pypi.org/project/ssdeep/)

The repository includes the JavaScript files (DataTables, jQuery, CellEdit, and ssdeep) and CSS so that Catscan can be run offline (for example, during an internal penetration test where you lack internet access).

Make sure I didn't put anything shady in the javascript files:

```
#jQuery
curl https://code.jquery.com/jquery-3.5.1.min.js --silent | md5sum 


curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/jquery-3.5.1.min.js --silent | md5sum



#dataTables
curl cdn.datatables.net/1.10.20/js/jquery.dataTables.min.js --silent | md5sum 


curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/jquery.dataTables.min.js --silent | md5sum



#cellEdit
curl https://raw.githubusercontent.com/ejbeaty/CellEdit/master/js/dataTables.cellEdit.js --silent | md5sum
4c995255f0e426b527729ce31d360343  -

curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/dataTables.cellEdit.js --silent | md5sum
4c995255f0e426b527729ce31d360343  -


#ssdeep
curl https://raw.githubusercontent.com/cloudtracer/ssdeep.js/master/ssdeep.js --silent | md5sum
ca2b2517d7747f243c31e73c15a45f41  -

curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/ssdeep.js --silent | md5sum
ca2b2517d7747f243c31e73c15a45f41  -


curl cdn.datatables.net/1.10.20/css/jquery.dataTables.min.css --silent | md5sum


curl https://raw.githubusercontent.com/WJDigby/catscan/master/css/jquery.dataTables.min.css --silent | md5sum

```

# Use

Catscan's only required input is a source file. The file can be either a text file of hostnames or IPs, separated by line, or an Nmap XML file.

Catscan parses text files and adds the protocol (HTTP or HTTPS) and port as necessary. Default ports are 80 and 443. If an entry on the list includes a specfic port, Catscan accepts that entry as is and does *not* add ports specified on the command line. 

For Nmap XML files, Catscan will scan all hosts in the XML that are listening on ports specified on the command line (defaults 80 and 443).

When using the fuzzy hashes feature, the Python ssdeep library calculates hash values, while the JavaScript ssdeep library compares selected hashes within the HTML report. Note that the similarity ratio produced by ssdeep.js seems more generous than the ssdeep C libraries or Python implementation (I opened an issue [here](https://github.com/cloudtracer/ssdeep.js/issues/1)) but it still provides a basis for comparison.

To compare site cotent based on fuzzy hashes, copy and paste or type a URI from the "All hosts" table into the "URI:" bar under the "Fuzzy Hash Comparisons" table, set a threshold with the dropdown, and click "Compare Fuzzy Hashes." This table only appears when you execute Catscan with the -f / --fuzzy option.

# Examples:

Scan a list of hosts from a text file on ports 80 and 443:

`python3 catscan -l hosts.txt`

Scan hosts from an Nmap XML file on ports 80, 8080, 443, and 8443. Note that ports are separated by a space, not a comma:

`python3 catscan -x nmap.xml -p 80 8080 443 8443`

Scan hosts from a text file, name the HTML report "test.html", and add a "Notes" column on the HTML report:

`python3 catscan -l hosts.txt -o test.html -n`

Scan hosts from an Nmap XML file on default ports, set threads to 20, use verbose output, and add fuzzy hash comparisons:

`python3 catscan -x nmap.xml -t 20 -v -f`

A complete list of arguments is as follows:

```
-t / --threads - Number of threads to use, default 10
-T / --timeout - Timeout in seconds. Default is 5; reduce this on internal networks for faster results.
-o / --output - Set the name for the html output. By default, reports are named "catscan_report_day_ddmmmyyyy_hhmm.html"
-u / --user-agent - Set a user agent. The default is "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
-r / --no-redirect - Do not follow redirects. By default, Catscan follows redirects and indicates in the resulting output whether a redirect was followed.
-k / --validate - Validate certificates. Generally not recommended, especially for internal environments with lots of self-signed certificates.
-n / --notes - Add a Notes column to the HTML tables to take notes on the HTML report.
-f / --fuzzy - Use "fuzzy" hashes to identify similar sites.
-v / --verbose - More verbose output 
```

Use of the HTML report should be intuitive. Datatables allows each table to be sorted by any row or searched by any field. Clicking any table element in the second (Hosts by Title) or third (Hosts by Content) tables populates the search bar for the first table. So, if you want a list of all hosts with a specific hash, use the third table to identify that hash, then click the hash to search for it in the first table. 

Exporting tables to CSV exports the rows that are currently visible. 
