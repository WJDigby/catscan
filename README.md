# Catscan

Catscan is a tool to triage web applications in large environments. Use it to quickly identify unique or uncommon applications that may be interesting, or identify targets of interest based on title. Catscan is not intended to replace tools like [eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) or [gowitness](https://github.com/sensepost/gowitness), but it can save one from scrolling through hundreds of IIS7 server splash pages or printer admin pages. 

Catscan's utility comes from its use of [DataTables](https://datatables.net/), which is a [jQuery](https://jquery.com/) plug-in. DataTables makes HTML tables highly functional, able to be searched for any text or sorted by any column.

Catscan takes as input either a list of IP addresses / URLS or an Nmap .xml file. The output is an HTML page with three tables:
* All hosts by IP/URL
* Unique hosts by title
* Unique hosts by content (unique content is determined by MD5 hashing the page response)

## Installation

Clone the repositoriy and install the requirements:

    git clone https://github.com/WJDigby/catscan.git
    pip3 install -r requirements.txt
    
Presently the only non-standard libraries required (the only ones included in requirements.txt) are requests and lxml.

## Use

Catscan's only required inputs are a source file and number of threads.

Catscan can accept a text file of IPs or URLs separated by line using the -l/--list parameter:

    python3 catscan.py -l <ips.txt> -t 5
    
By default Catscan checks ports 80 and 443, but this can be overridden with the -p/--ports parameter:

    python3 catscan.py -l <ips.txt> -p 80 8000 8080 443 8443 -t 5
    
The input file can contain IP addresses with or without a protocol (e.g. https://192.168.0.1 or 192.168.0.1) or URLs with our without a protocol (e.g. http://www.example.com or www.example.com). Catscan does not currently handle lines already including a port number (e.g. 192.168.0.1:80).
    
Alternatively, Catscan can accept an Nmap .xml file. Catscan will parse the .xml and scan open ports in the list 80, 443, 8000, 8008, 8080, and 8443. 

    python3 catscan.py -x <nmap.xml> -t 5
    
In addition, Catscan has several optional arguments:
* -T / --timeout - Timeout in seconds. Default is 5; reduce this on internal networks for faster results.
* -o / --output - Set the name for the html output. By default, reports are named "catscan_report_day_ddmmmyyyy_hhmm.html"
* -u / --user-agent - Set a user agent. The default is "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
* -r / --no-redirect - Do **not** follow redirects. By default, Catscan follows redirects and indicates in the resulting output whether a redirect was followed.
* -k / --validate - Validate certificates. Generally not recommended, especially for internal environments with lots of self-signed certificates. 

Use of the HTML report should be intuitive. As noted, the report presents three tables:
* All hosts by IP/URL
* Unique hosts by title
* Unique hosts by content (unique content is determined by MD5 hashing the page response)

Note that clicking any table element in the second or third table populates the search bar of the first table. So, if you want a quick link to a site with unique content, click its title or hash in the bottom table to search for that host in the first table. 
