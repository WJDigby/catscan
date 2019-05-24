This repository includes the following projects:

* [jQuery](https://jquery.org/) (jquery-3.3.1.min.js) - [MIT License](https://jquery.org/license/)
* [DataTables](https://datatables.net/) (jquery.dataTables.min.js) - [MIT License](https://datatables.net/license/mit)
* [CellEdit](https://github.com/ejbeaty/CellEdit) (dataTables.cellEdit.js) - [MIT License](https://github.com/ejbeaty/CellEdit/blob/master/js/dataTables.cellEdit.js)

# Catscan

Use Catscan for rapid triage of web applications across large environments. Catscan can help you quickly identify unique or uncommon applications (by MD5 hash) or targets of interest (by HTML title). Catscan is designed to fit into your existing workflow and help optimize targeting. It is not intended to replace tools like [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) or [gowitness](https://github.com/sensepost/gowitness), but can save you from scrolling through hundreds of IIS7 server splash pages.

Catscan takes as input a list of hostnames / IP addresses or an Nmap .xml file. It produces a searchable, sortable HTML file with three tables:

* All hosts by URI (including title, response code, response hash, and redirect)
* Hosts grouped by title (including count)
* Hosts grouped by content (including title and count)

Additional features include:

* Multithreaded
* Take notes on the HTML report
* Export HTML tables to CSV, including notes
* Single-click searching between tables

Catscan's utility comes from the HTML report, which uses [DataTables](https://datatables.net/), a [jQuery](https://jquery.com/) plug-in, and [CellEdit](https://github.com/ejbeaty/CellEdit).

# Installation

Consider installing and running in a virtual environment:

`python3 -m venv ./`

`source ./bin/activate`

Clone the repository and install the requirements:

`git clone https://github.com/WJDigby/catscan.git`

`pip3 install -r requirements.txt`

Non-standard libraries included in the current version are jinja2, lxml, requests, and xmltodict.

The repository includes the JavaScript files (DataTables, jQuery, and CellEdit) and CSS so that Catscan can be run offline (for example, during an internal penetration test where you lack internet access).

Make sure I didn't put anything shady in the javascript files:

```
#jQuery
curl https://code.jquery.com/jquery-3.3.1.min.js --silent | md5sum 
a09e13ee94d51c524b7e2a728c7d4039  -

curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/jquery-3.3.1.min.js --silent | md5sum
a09e13ee94d51c524b7e2a728c7d4039  -


#dataTables
curl https://cdn.datatables.net/1.10.18/js/jquery.dataTables.min.js --silent | md5sum 
4d2910ca45f9cea3f35e87065a1be139  -

curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/jquery.dataTables.min.js --silent | md5sum
4d2910ca45f9cea3f35e87065a1be139  -


#cellEdit
curl https://raw.githubusercontent.com/ejbeaty/CellEdit/master/js/dataTables.cellEdit.js --silent | md5sum
4c995255f0e426b527729ce31d360343  -

curl https://raw.githubusercontent.com/WJDigby/catscan/master/js/dataTables.cellEdit.js --silent | md5sum
4c995255f0e426b527729ce31d360343  -



#dataTables CSS
curl https://cdn.datatables.net/v/dt/dt-1.10.18/datatables.min.css --silent | md5sum 
6ae5fd80e0b4ead65b8f2a0e585bc585  -
```

# Use

Catscan's only required input is a source file. The file can be either a text file of hostnames or IPs, separated by line, or an Nmap XML file.

Catscan parses text files and adds the protocol (HTTP or HTTPS) and port as necessary. Default ports are 80 and 443. If an entry on the list includes a specfic port, Catscan accepts that entry as is and does *not* add ports specified on the command line. 

For Nmap XML files, Catscan will scan all hosts in the XML that are listening on ports specified on the command line (defaults 80 and 443).

# Examples:

Scan a list of hosts from a text file on ports 80 and 443:

`python3 catscan -l hosts.txt`

Scan hosts from an Nmap XML file on ports 80, 8080, 443, and 8443:

`python3 catscan -x nmap.xml -p 80 8080 443 8443`

Scan hosts from a text file, name the HTML report "test.html", and add a "Notes" column on the HTML report:

`python3 catscan -l hosts.txt -o test.html -n`

A complete list of arguments is as follows:

```
-t / --threads - Number of threads to use, default 10
-T / --timeout - Timeout in seconds. Default is 5; reduce this on internal networks for faster results.
-o / --output - Set the name for the html output. By default, reports are named "catscan_report_day_ddmmmyyyy_hhmm.html"
-u / --user-agent - Set a user agent. The default is "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
-r / --no-redirect - Do not follow redirects. By default, Catscan follows redirects and indicates in the resulting output whether a redirect was followed.
-k / --validate - Validate certificates. Generally not recommended, especially for internal environments with lots of self-signed certificates.
-n / --notes - Add a Notes column to the HTML tables to take notes on the HTML report.
-v / --verbose - More verbose output 
```

Use of the HTML report should be intuitive. Datatables allows each table to be sorted by any row or searched by any field. Clicking any table element in the second (Hosts by Title) or third (Hosts by Content) tables populates the search bar for the first table. So, if you want a list of all hosts with a specific hash, use the third table to identify that hash, then click the hash to search for it in the first table. 

Exporting tables to CSV exports the rows that are currently visible. 
