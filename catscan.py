# TODO: Socks proxies (needs to be tested)
# TODO: Double check how redirects and status codes are stored
# TODO: Way to determine from outfile whether allow_redirects enabled / disabled
#      (e.g. ensure report built with appropriate options)
# TODO: Test verbosity
# TODO: Test proxy w/ beacon
# TODO: Build out decoder function exceptions through testing


from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import partial
import hashlib
import json
from os import getcwd, path
from queue import Queue
import re
from threading import Thread
import urllib3

import click
import jinja2
from lxml import html, etree
import requests
try:
    import ssdeep
except ImportError:
    ssdeep = None
from tqdm import tqdm


USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)' \
             ' Chrome/101.0.4951.67 Safari/537.36'
# Accept -h or --help to print help menu
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], max_content_width=200)

cwd = getcwd()
datatables_css = f'<link rel="stylesheet" type="text/css" href="{cwd}/css/jquery.dataTables.min.css">'
jquery = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/jquery-3.5.1.min.js"></script>'
datatables = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/jquery.dataTables.min.js"></script>'
datatables_celledit = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/dataTables.cellEdit.js"></script>'
ssdeep_js = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/ssdeep.js"></script>'

jinja_env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "template.html"
template = templateEnv.get_template(TEMPLATE_FILE)


class Host:
    def __init__(self, uri, scheme=None, netloc=None, port=None, title=None, login=None, redirect=None,
                 status_code=None, md5_hash=None, fuzzy_hash=None, scan_time=None):
        self.uri = uri
        # I know urllib.parse.urlparse exists, but I don't care about paths, params, queries, or fragments
        # but I do care about ports
        separated = uri.split(':')
        self.scheme = separated[0]
        self.netloc = separated[1][2:]
        self.port = separated[2]
        self.title = title if title else None
        self.login = login if login else None
        self.redirect = redirect if redirect else None
        self.status_code = status_code if status_code else None
        self.md5_hash = md5_hash if md5_hash else None
        self.fuzzy_hash = fuzzy_hash if fuzzy_hash else None
        self.scan_time = scan_time if scan_time else None


def decoder(content):
    """ Try multiple decodings for content returned by requests."""
    encodings = ('utf-8', 'latin-1')
    for encoding in encodings:
        try:
            return content.decode(encoding)
        except Exception as err:
            print(err)


def build_list_from_nmap_xml(root, scan_ports, scan_by_ip):
    """Read an XML file produced by Nmap, prepend protocol and append port as necessary.
    catscan.py will scan ports that are (1) included by the operator with the -p / --ports parameter,
    and (2) marked in the Nmap XML as open.

    Catscan.py builds a scan list including hostnames as well as IP addresses unless the operator
    passes the -i / --scan-by-ip flag.

    Return a set for scanning.
    """

    scan_set = set()
    scan_ports = [str(port) for port in scan_ports]
    hosts = [child for child in root.getchildren() if child.tag == 'host']

    for host in hosts:

        for child in host.getchildren():

            if child.tag == 'address':
                address = child.get('addr')

            if child.tag == 'hostnames':
                names = [child.get('name') for child in child.getchildren()]

            if child.tag == 'ports':
                nmap_ports = [child.get('portid') for child in child.getchildren() if
                              (child.tag == 'port' and child.getchildren()[0].get('state') == 'open')]

        for nmap_port in nmap_ports:
            if nmap_port in scan_ports:
                uri = 'http://' + address + ':' + nmap_port
                scan_set.add(uri)

                if scan_by_ip:
                    break

                for name in names:
                    uri = 'http://' + name + ':' + nmap_port
                    scan_set.add(uri)

    scan_set = {uri.replace('http://', 'https://') if uri.endswith('443') else uri for uri in scan_set}
    return scan_set


def build_list_from_text(infile, ports):
    """Read a text file of IPs or URLs, prepend protocol and append port as necessary.
    If the list includes a host with a port not provided by the -p / --ports parameter,
    catscan.py will honor that port and include it in the list to scan.
    Return a set for scanning
    """

    regex = re.compile(r"^(https?:\/\/)?.+?(:[0-9]{0,5})?$")
    scan_set = set()
    lines = [line.rstrip().decode() for line in infile.readlines()]
    for line in lines:
        line = re.match(regex, line)
        if not line:
            pass
        elif line[1] and line[2]:  # protocol and port
            scan_set.add(line[0])

        elif line[1] and not line[2]:  # protocol no port
            if line[1] == 'https://':
                scan_set.add(line[0] + ':443')  # For consistency
            else:
                for port in ports:
                    # Convert http://example.com:443 to https://example.com:443
                    if str(port).endswith('443'): # Include 443 and (for example) 8443
                        uri = line[0].replace('http://', 'https://') + ':' + str(port)
                        scan_set.add(uri)
                    else:
                        uri = line[0] + ':' + str(port)
                        scan_set.add(uri)

        elif not line[1] and line[2]:  # no protocol but port
            if line[2].endswith('443'): # Include 443 and, for example, 8443
                uri = 'https://' + line[0]
            else:
                uri = 'http://' + line[0]
            scan_set.add(uri)

        elif not line[1] and not line[2]:  # neither protocol nor port
            for port in ports:
                if str(port).endswith('443'):  # Include 443 and, for example, 8443
                    uri = 'https://' + line[0] + ':' + str(port)
                else:
                    uri = 'http://' + line[0] + ':' + str(port)
                scan_set.add(uri)

    return scan_set


def print_good(statement):
    click.secho('[+] ' + statement, fg='green', bold=True)


def print_error(statement):
    click.secho('[-] ' + statement, fg='red', bold=True)
    exit(1)


def print_status(statement):
    click.secho('[*] ' + statement, fg='blue', bold=True)


def print_warning(statement):
    click.secho('[!] ' + statement, fg='yellow', bold=True)


def prompt(question, default=None):
    # Adapted from https://stackoverflow.com/a/3041990 - thanks fmark
    """Ask a yes/no question via input() and return answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        choice = " [y/n] "
    elif default == "yes":
        choice = " [Y/n] "
    elif default == "no":
        choice = " [y/N] "
    else:
        raise ValueError(f'Invalid default answer: {default}')

    while True:
        print(question + choice)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print('[*] Please respond with "[y]es" or "[n]o".')


def scan(timeout, validate_certs, allow_redirects, proxies, user_agent, fuzzy, verbose, q, uri):
    """Make requests to the provided URIs and save attributes of the responses
    within a Host class object.

    Returns nothing; places Host objects in Queue for writing to file.
    """

    headers = {'User-Agent': user_agent}
    regex = re.compile(r"type=[\"|\']password[\"|\']", re.IGNORECASE)
    # Build parser so multiple threads don't use a global parser
    parser = etree.HTMLParser()
    error = None
    host = Host(uri, scan_time=datetime.now().strftime("%a_%d%b%Y_%H%M"))
    try:
        resp = requests.get(uri, headers=headers, timeout=timeout, verify=validate_certs,
                            allow_redirects=allow_redirects, proxies=proxies)

        host.status_code = resp.status_code

        if not allow_redirects and resp.is_redirect:
            host.redirect = resp.headers['Location']
            q.put(host)

        if resp.content:
            host.md5_hash = hashlib.md5(resp.content).hexdigest()
            host.status_code = resp.status_code
            tree = html.fromstring(resp.content, parser=parser)
            try:
                # Strip newline characters if it's depicted in HTML with line breaks
                # those break javascript arrays built later.
                title = tree.find('.//title').text.strip()
                # If title contains comma, wrap in quotes for CSV export
                host.title = '"' + title + '"' if ',' in title else title
            except AttributeError:
                if verbose:
                    print(f'[-] {uri} - attribute error; page may lack title element')

            login = re.search(regex, decoder(resp.content))
            host.login = True if login else False

            host.fuzzy_hash = ssdeep.hash(resp.content) if fuzzy else None

        if resp.url.strip('/') != host.uri:
            host.redirect = resp.url

        q.put(host)

    except requests.exceptions.ConnectTimeout:
        error = 'Connection timeout.'
        host.title = error
        q.put(host)
    except requests.exceptions.ReadTimeout:
        error = 'Read timeout.'
        host.title = error
        q.put(host)
    except requests.exceptions.SSLError:
        error = 'Certificate verification failed.'
        host.title = error
        q.put(host)
    except requests.exceptions.TooManyRedirects:
        error = 'Too many redirects - probably caught in a redirect loop.'
        host.title = error
        q.put(host)
    # Since requests uses other libraries (socket, httplib, urllib3) a requests ConnectionError
    # can be any number of errors raised by those libraries.
    except requests.exceptions.ConnectionError as err:
        err_msg = str(err.args[0])
        if 'BadStatusLine' in err_msg:
            error = 'Malformed page - consider visiting manually'
            host.title = error
        elif 'Connection refused' in err_msg:
            error = 'Connection refused.'
            host.title = error
        elif 'Connection reset by peer' in err_msg:
            error = 'Connection reset by peer.'
            host.title = error
        elif 'Failed to establish a new connection' in err_msg:
            error = 'Failed to establish new connection.'
            host.title = error
        else:  # Catch all the others
            host.title = err_msg

        q.put(host)

    if verbose and error:
        print_error(f'[-] Error scanning {uri}: {error}')


def validate_outfile(outfile):
    """Validate a catscan output file and return a list of hosts.
    Used for report_only option or to resume scanning. Takes path to an outfile.
    Returns
    """

    if not path.isfile(outfile):
        print_error(f'{outfile} is not a valid path.')

    with open(outfile, 'r') as f:
        lines = f.readlines()
        try:
            hosts = [Host(**json.loads(line)) for line in lines]
        except Exception as err:
            print_error(f'Encountered error loading {outfile}: {err}')

    return hosts

    # Alternative method validates the JSON as we go
    # with open(outfile, 'r') as f:
    #     js = f.readlines()
    #     try:
    #         # A little jank
    #         existing = json.loads('[' + ','.join(js) + ']')
    #     except json.decoder.JSONDecodeError as err:
    #         print_error(f'[-] Failed to load {outfile}: {err}')


def write_output(host_queue, scan_list, handle):
    """Write scanned host data to a file in a thread-safe manner.

    This function writes each object as a JSON blob. However, the resulting file
    is not valid JSON since the individual objects are not wrapped in a list and
    comma-separated. Could also consider writing as CSV or to SQLite database.
    """

    progress_bar = tqdm(total=len(scan_list), desc='Scanning and saving data')
    while True:
        host = host_queue.get()
        handle.write(json.dumps(host.__dict__) + '\n')
        # progress_bar.desc = f'Saving data for {host.uri}'
        progress_bar.update(1)
        host_queue.task_done()


def write_report(hosts, outfile, allow_redirects, notes, fuzzy):
    """Write the report in user-friendly HTML format.
    Takes iterable of hosts objects.
    Returns nothing but writes HTML file.
    """

    # Harder to read comprehensions
    # {(h['title'], [h['title'] for h in hosts_json].count(h['title'])) for h in hosts_json}
    title_counts, content_counts = {}, {}
    for host in hosts:
        if host.title in title_counts:
            title_counts[host.title] += 1
        else:
            title_counts[host.title] = 1
        if host.md5_hash in content_counts:
            content_counts[host.md5_hash][0] += 1
        else:
            content_counts[host.md5_hash] = [1, host.title]  # Save title since same hash means same title

    # If the outfile has an extension, replace it with .html extension.
    if '.' in outfile:
        report_filename = '.'.join(outfile.split('.')[0:-1]) + '.html'
    # Otherwise just append .html extension.
    else:
        report_filename = outfile + '.hmtl'
    with open(report_filename, 'w') as html_report:
        html_report.write(template.render(
            datatables_css=datatables_css,
            jquery=jquery,
            datatables=datatables,
            datatables_celledit=datatables_celledit,
            ssdeep_js=ssdeep_js,
            redirect_column=allow_redirects,
            notes_column=notes,
            fuzzy=fuzzy,
            hosts=hosts,
            title_counts=title_counts,
            content_counts=content_counts
        ))

    print_good(f'Report written to {report_filename}')


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-f', '--fuzzy', help='Generate "fuzzy" hashes to help identify similar sites.', is_flag=True)
@click.option('-r', '--no-redirect', help='Do not follow redirects. Catscan follows redirects by default.', is_flag=True)
@click.option('-n', '--notes', help='Add a writable "notes" column to the HTML report.', is_flag=True)
@click.option('-o', '--outfile', help='Name of output file and HTML report. Default based on date/time.')
@click.option('-p', '--ports', help='List of ports to scan. Default 80 and 443.', default="80, 443")
@click.option('-P', '--proxy', help='Use an HTTP(S) or SOCKS (4/4a/5) proxy in format <protocol>://<ip>:<port>')
@click.option('-R', '--report-only', help='Do not scan, just build the report. Requires -o / --outfile.', is_flag=True)
@click.option('-i', '--scan-by-ip', help='Build scan lists by IP only (not hostname). '
                                         'Only relevant with Nmap XML files.', is_flag=True)
@click.option('-t', '--threads', help='Number of threads. Default 10.', type=int, default=10)
@click.option('-T', '--timeout', help='Timeout in seconds. Default 5.', type=int, default=5)
@click.option('-u', '--user-agent', help=f'User-Agent string. Defaults to {USER_AGENT}.')
@click.option('-k', '--validate-certs', help='Validate TLS certificates. Default False.', is_flag=True)
@click.option('-v', '--verbose', help='Produce more verbose output.', is_flag=True)
@click.argument('infile', type=click.File('rb'))
def main(fuzzy, no_redirect, notes, outfile, ports, proxy, report_only, scan_by_ip, threads, timeout,
         user_agent, validate_certs, verbose, infile):
    """Scan a list of IPs or hostnames on given ports to return searchable and sortable information
    about websites in an HTML report.

    INPUT can be either a .txt file with a list of IPs or hostnames, separated by line,
    or an Nmap XML file.
    """

    allow_redirects = False if no_redirect else True

    # If report_only, just generate a catscan HTML report from a catscan output and exit
    if report_only:
        if not outfile:
            print_error('The -R / --report-only flag requires -o / --outfile with previous catscan output'
                        'from which to build a report.')
        hosts = validate_outfile(outfile)
        write_report(hosts, outfile, allow_redirects, notes, fuzzy)
        exit(0)

    # Validate parameters
    if fuzzy and not ssdeep:
        print_warning('ssdeep library not found - disabling fuzzy scanning.')
        fuzzy = False

    user_agent = user_agent if user_agent else USER_AGENT

    try:
        ports = {int(port) for port in ports.split(',') if port}
    except ValueError:
        print_error('Please provide a comma-separated list of valid integers, e.g. 80,8000,8080,443.')

    if proxy:
        if (proxy.split('://')[0] == proxy) or (len(proxy.split(':')) != 3):
            print_error(f'Provide proxy in format <protocol>://<host or IP>:<port>')

        proxy_types = ['http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h']
        if not any([proxy.lower().split('://')[0] == pt for pt in proxy_types]):
            print_error(f'Proxy must be one of {", ".join([pt for pt in proxy_types])}.')

        proxies = {'http': proxy, 'https': proxy}
    else:
        proxies = None

    try:
        root = etree.fromstring(infile.read())
        scan_set = build_list_from_nmap_xml(root, ports, scan_by_ip)
    except etree.XMLSyntaxError:
        infile.seek(0)
        if scan_by_ip:
            print_warning('The -i / --scan-by-ip option is only relevant when ingesting Nmap XML files.')
        scan_set = build_list_from_text(infile, ports)

    # If operator provides an existing file, resume progress from that file and/or append new URIs
    if outfile:
        hosts = validate_outfile(outfile)
        print_status(f'Using existing {outfile}')
        scanned_set = {host.uri for host in hosts}
        original_length, existing_length = len(scan_set), len(scanned_set)
        scan_set = scan_set - scanned_set
        print_good(f'Found {existing_length} hosts in {outfile} - '
                   f'{len(scan_set)} of {original_length} remaining to scan.')

    if not outfile:
        outfile = f'catscan_{datetime.now().strftime("%a_%d%b%Y_%H%M").lower()}.json'

    # Perform the scanning
    with open(outfile, 'a') as handle:
        host_queue = Queue()
        writer = Thread(target=write_output, args=(host_queue, scan_set, handle), daemon=True)
        writer.start()

        func = partial(scan, timeout, validate_certs, allow_redirects, proxies, user_agent, fuzzy, verbose, host_queue)
        with ThreadPoolExecutor(threads) as executor:
            executor.map(func, scan_set)

        host_queue.join()

    hosts = validate_outfile(outfile)
    write_report(hosts, outfile, allow_redirects, notes, fuzzy)
    exit(0)


if __name__ == '__main__':
    # Disable "InsecureRequestWarning: Unverified HTTPS request is being made.
    # Adding certificate verification is strongly advised." warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
