import argparse
from argparse import RawDescriptionHelpFormatter
import requests
import hashlib
from lxml import html, etree
import urllib3
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
from datetime import datetime

results = {}
datatables_css = '<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/jquery.dataTables.min.css">'
jquery = '<script src="https://code.jquery.com/jquery-3.3.1.slim.js" integrity="sha256-fNXJFIlca05BIO2Y5zh1xrShK3ME+/lYZ0j+ChxX2DA=" crossorigin="anonymous"></script>'
datatables = '<script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js"></script>'


def parse_nmap_xml(nmap_file):
    """Parse an Nmap .xml file for open HTTP(S) ports and return a list"""
    ips_to_scan = []
    http = (80, 443, 8000, 8008, 8080, 8443)
    with open(nmap_file) as f:
        xml = f.read()
        xml = bytes(bytearray(xml, encoding='utf-8'))
    root = etree.fromstring(xml)
    for host in root:
        for host_attribute in host:
            tag = host_attribute.tag
            if tag == 'address':
                ipv4_addr = host_attribute.attrib['addr']
            for host_port in host_attribute:
                tag = host_port.tag
                if tag == 'port' and int(host_port.attrib['portid']) in http:
                    port = host_port.attrib['portid']
                    for port_attribute in host_port:
                        tag = port_attribute.tag
                        if tag == 'state' and port_attribute.attrib['state'] == 'open':
                            if port == '443':
                                ips_to_scan.append('https://{}:{}'.format(ipv4_addr, port))
                            else:
                                ips_to_scan.append('http://{}:{}'.format(ipv4_addr, port))
    host_count = len(ips_to_scan)
    return ips_to_scan, host_count


def build_list(ip_list, ports):
    """Read a text file of IPs or URLs, append ports, and return a list for scanning"""
    ips_to_scan = []
    with open(ip_list) as f:
        ips = f.readlines()
        for ip in ips:
            if '://' in ip:
                ip = ip.split('://', 1)[1]
            if ip not in ips_to_scan:
                for port in ports:
                    if str(port) == '443':
                        if not ip.startswith('https://'):
                            ips_to_scan.append('https://{}'.format(ip.rstrip()))
                        else:
                            ips_to_scan.append(ip.rstrip())
                    else:
                        if not ip.startswith('http://'):
                            ips_to_scan.append('http://{}:{}'.format(ip.rstrip(), str(port)))
                        else:
                            ips_to_scan.append('{}:{}'.formati(ip.rstrip(), str(port)))
    host_count = len(ips_to_scan)
    return ips_to_scan, host_count


def scan(timeout, validate_certs, no_redirect, user_agent, ip):
    """Make requests to the provided IPs and save attributes of the responses."""
    headers = {'User-Agent': user_agent}
    parser = etree.HTMLParser()  # Build parser to ensure multiple threads aren't using a global parser
    try:
        resp = requests.get(ip, headers=headers, timeout=timeout, verify=validate_certs,
                            allow_redirects=no_redirect)  # if response empty, don't add
        content = resp.content

        if resp.content:
            resp_hash = hashlib.md5(resp.content).hexdigest()
            tree = html.fromstring(content, parser=parser)
            try:
                title = tree.find('.//title').text
            except AttributeError:
                title = '<none>'
                print('[-] {} - attribute error; page may lack title element'.format(ip))
            if no_redirect is False:
                results[ip] = [title, resp.status_code, resp_hash]
            elif no_redirect is True:
                if resp.url.strip('/') != ip:
                    results[ip] = [title, resp.status_code, resp_hash, '<a href="{}"</a>{}'.format(resp.url, resp.url)]
                elif resp.url.strip('/') == ip:
                    results[ip] = [title, resp.status_code, resp_hash, 'No redirect.']
        else:
            results[ip] = ['<none>', resp.status_code, '<no page content>', '<no page content>']

    except requests.exceptions.ConnectTimeout:
        print('[-] {} - connection timeout'.format(ip))
        results[ip] = ['Connection timeout.'] * 4
    except requests.exceptions.ReadTimeout:
        print('[-] {} - read timeout'.format(ip))
        results[ip] = ['Read timeout.'] * 4
    except requests.exceptions.SSLError:
        print('[-] {} - certificate verification failed'.format(ip))
        results[ip] = ['Certificate error.'] * 4
    # Since requests uses other libraries (socket, httplib, urllib3) a requests ConnectionError can actually be any number of errors raised by those libraries.
    except requests.exceptions.ConnectionError as e:
        if 'BadStatusLine' in str(e.args[0]):
            print('[-] {} - malformed page (consider visiting manually)'.format(ip))
            results[ip] = ['Malformed page.'] * 4
        elif 'Connection refused' in str(e.args[0]):
            print('[-] {} - connection refused'.format(ip))
            results[ip] = ['Connection refused.'] * 4
        elif 'Connection reset by peer' in str(e.args[0]):
            print('[-] {} - connection reset by peer'.format(ip))
            results[ip] = ['Connection reset by peer.'] * 4
        else:  # Catch all the others
            print('[-] {} - unhandled exception: {}'.format(ip, str(e)))
            results[ip] = ['Unhandled exception.'] * 4


def report(start_time, datatables_css, jquery, datatables, no_redirect, output):
    """Generate the HTML report using JQuery and Datatables."""
    title_counts, content_counts = {}, {}
    all_hosts_table, unique_titles_table, unique_content_table = [], [], []
    for key, value in results.items():
        if value[0] in title_counts:
            title_counts[value[0]] += 1
        else:
            title_counts[value[0]] = 1
        if value[2] in content_counts:
            content_counts[value[2]][0] += 1
        else:
            content_counts[value[2]] = [1, value[0]]
        if no_redirect is False:
            # Passing all values as str() is a kluge to account for NoneTypes that should be handled better elsewhere
            redirect_column = ''
            all_hosts_table.append('<tr><td><a href="{}" target="_blank"</a>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.
                                   format(key, key, str(value[0]), str(value[1]), str(value[2])))
            html_all_hosts_table = '\n'.join(all_hosts_table)
        elif no_redirect is True:
            redirect_column = "<th>Redirect</th>"
            all_hosts_table.append('<tr><td><a href="{}" target="_blank"</a>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.
                                   format(key, key, str(value[0]), str(value[1]), str(value[2]), str(value[3])))
            html_all_hosts_table = '\n'.join(all_hosts_table)

    for key, value in title_counts.items():
        unique_titles_table.append('<tr><td>{}</td><td>{}</td></tr>'.format(key, str(value)))
        html_unique_titles_table = '\n'.join(unique_titles_table)

    for key, value in content_counts.items():
        unique_content_table.append('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(str(key), str(value[1]), str(value[0])))
        html_unique_content_table = '\n'.join(unique_content_table)

    html = """
        <html>
          <head>
            <title>Catscan Report for {start_time}</title>
            {datatables_css}
            <style type="text/css" class="init">
                body {{font-family:Arial;
                }}
            </style>
            {jquery}
            {datatables}
            <script type="text/javascript" class="init">
              $(document).ready( function () {{
                $('#all_hosts').DataTable( {{
                  "pageLength": 100
                }} );
                $('#unique_titles').DataTable();
                $('#unique_content').DataTable();
                $("a").attr("target", "_blank");                 
              }} );
            </script>
          </head>
          <body>
            <h1 align="center">All Hosts</h1>
            <table id="all_hosts" class="display">
              <thead>
                <tr>
                  <th>URI</th>
                  <th>Page title</th>
                  <th>Response Code</th>
                  <th>MD5 Hash</th>
                  {redirect_column}
                </tr>
              <tbody>
              {all_hosts_table}
              </tbody>
            </table>
            <br><br>
            <h1 align="center">Unique Hosts by Title</h1>
            <table id="unique_titles" class="display">
              <thead>
                <tr>
                  <th>Page Title</th>
                  <th>Count</th>
                </tr>
              <tbody>
              {titles_table}
               </tbody>
            </table>
            <br><br>
            <h1 align="center">Unique Hosts by Content</h1>
            <table id="unique_content" class="display">
              <thead>
                <tr>
                  <th>MD5 Hash</th>
                  <th>Title</th>
                  <th>Count</th>
                </tr>
              <tbody>
              {content_table}
              </tbody>
            </table>
          </body>
        </html>
        """.format(start_time=start_time.strftime('%A %d %B %Y %H:%M'), datatables_css=datatables_css, jquery=jquery,
                   datatables=datatables, redirect_column=redirect_column, all_hosts_table=html_all_hosts_table,
                   titles_table=html_unique_titles_table, content_table=html_unique_content_table)

    if type(output) is datetime:
        output = 'catscan_report_{}.html'.format(output.strftime('%a_%d%b%Y_%H%M').lower())

    html_report = open(output, 'w')
    html_report.write(html)
    html_report.close()
    print('[+] Report written to {}'.format(output))


def main():
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36'

    parser = argparse.ArgumentParser(description='Scan and categorize web servers using a searchable / sortable HTML report.',
                                     epilog='list input: python3 catscan.py -l <ips.txt> -p 80 443 -t 5\n'
                                            'Nmap xml:   python3 catscan.py -x <nmap.xml> -t 5',
                                     formatter_class=RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-x', '--xml', dest='nmap_xml', required=False, help='Use an Nmap XML file as input.')
    group.add_argument('-l', '--list', dest='ip_list', required=False, help='Text file containing list of IPs, separated by line.')
    parser.add_argument('-p', '--ports', dest='ports', nargs='+', required=False, default=[80, 443],
                        help='List of ports to scan. Default 80 and 443. Use with --list option.')
    parser.add_argument('-t', '--threads', dest='threads', type=int, required=True, help='Number of threads.')
    parser.add_argument('-T', '--timeout', dest='timeout', type=int, default=5, help='Timeout in seconds. Default 5.')
    parser.add_argument('-o', '--output', dest='output', required=False, help='Name of HTML report. Default based on date/time.')
    parser.add_argument('-u', '--user-agent', dest='user_agent', required=False, default=user_agent, help='User-Agent string.')
    parser.add_argument('-r', '--no-redirect', dest='no_redirect', required=False, default=True, action='store_false',
                        help='Do not follow redirects. Catscan follows redirects by default.')
    parser.add_argument('-k', '--validate', dest='validate_certs', required=False, default=False, action='store_true',
                        help='Validate certificates. Default false.')
    args = parser.parse_args()

    nmap_xml = args.nmap_xml
    ip_list = args.ip_list
    ports = args.ports
    timeout = args.timeout
    threads = args.threads
    output = args.output
    user_agent = args.user_agent
    no_redirect = args.no_redirect
    validate_certs = args.validate_certs
    start_time = datetime.now()
    if not output:
        output = start_time
    if nmap_xml:
        ips_to_scan, host_count = parse_nmap_xml(nmap_xml)
    elif ip_list:
        ips_to_scan, host_count = build_list(ip_list, ports)
    func = partial(scan, timeout, validate_certs, no_redirect, user_agent)
    pool = ThreadPool(threads)
    pool.map(func, ips_to_scan)
    pool.close()
    pool.join()
    end_scan_time = datetime.now()
    print('[*] Scan time: %g seconds' % (end_scan_time - start_time).total_seconds())
    print('[*] {} hosts scanned'.format(str(host_count)))
    report(start_time, datatables_css, jquery, datatables, no_redirect, output)
    end_run_time = datetime.now()
    print('[*] Total run time: %g seconds' % (end_run_time - start_time).total_seconds())


if __name__ == '__main__':
    # Disable "InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised."
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
