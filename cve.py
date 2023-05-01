#!/usr/bin/python3
import argparse
from bs4 import BeautifulSoup as bs
import concurrent.futures
import textwrap
from urllib.request import urlopen, Request
import random
import signal
import sys


def random_header(file):
    pairs = []
    with open(file, 'rt') as file:
        lines = [line.rstrip('\n') for line in file]
    
    pairs = [('User-Agent', line) for line in lines]
    rand = random.choice(pairs)
    header = dict([(rand)])
    return header


def display(date, desc, score, refs):
    
    print(f'\n\tPublished on:\n\n{date}\n\n')
    
    print('\tDescription:\n')
    wrapped = textwrap.wrap(desc, width=80)
    print('\n'.join(wrapped), '\n\n')
    
    print(f'\tBase Score:\n\n{score}\n\n')
    
    print('\tRefrences:\n')
    for r in refs:
        print(r)

    print('\n')


def signal_handler(sig, frame):
    sys.exit(0)


def mitre(cve):
    
    url = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}'
    req = Request(url, headers=random_header('user-agents'))
    page = urlopen(req, timeout=60)
    html = page.read().decode('utf-8')
    soup = bs(html, 'html.parser')
    
    err = soup.find('h2').text
    if err.startswith('ERROR'):
        print(err)
        raise SystemExit

    matches = [m.text for m in soup.find_all('td', {'colspan': '2'}) if '  ' not in m.text]
    desc = matches[0]
    if desc.startswith('** RESERVED **'):
        wrap = textwrap.wrap(desc, width=81)
        print('\n', '\n'.join(wrap))
        raise SystemExit
    
    links = [m.text for m in soup.find_all('a', {'target': '_blank'}) if 'https' in m.text]
    refs = set()
    for link in links:
        idx = link.index(':')
        link = link[idx+1:]
        refs.add(link)
    return (desc, refs)


def nvd(cve):

    url = f'https://nvd.nist.gov/vuln/detail/{cve}'
    req = Request(url, headers=random_header('user-agents'))
    page = urlopen(req, timeout=60)
    html = page.read().decode('utf-8')
    soup = bs(html, 'html.parser')
    score = soup.find('span', {'class': 'severityDetail'})
    if not score:
        raise SystemExit
    score = score.find('a').text
    date = soup.find('span', {'data-testid': 'vuln-published-on'}).text

    return (date, score)


def main(argv):
    p = argparse.ArgumentParser(description='quick CVE info aggregator')
    p.add_argument('-c', '--cve', action='store', required=True)
    args = p.parse_args(args=argv)
    cve = args.cve
    cve = cve.split('-')
    cve[0] = 'CVE'
    cve = '-'.join(cve)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        t1 = executor.submit(mitre, cve)
        t2 = executor.submit(nvd, cve)
        date, score = t2.result()
        desc, ref = t1.result()
        
    display(date, desc, score, ref)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])
