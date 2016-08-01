import csv
import sys
import requests
import tldextract
from os import listdir
import pandas as pd

# Function that deletes the queries of an url
def delete_queries(url):
    path = str(url).split('?',1)[0]
    return path

def extract_urls_override(files_dir, column):
    urls = []
    files = listdir(files_dir)
    for f in files:
        try:
            links = pd.read_csv(files_dir + f, usecols=[int(column)-1]).values.T.tolist()[0]
        except (IndexError,ValueError) as e:
            sys.exit("Column number is out of range.")
        contains_urls = check_column(links)
        if(contains_urls):
            links = list(map(delete_queries,links))
            urls += links
        else:
            sys.exit("Chosen column has a diffrent format than expected.")
    return urls

def extract_urls_default(files_dir):
    urls = []
    files = listdir(files_dir)
    for f in files:
        rows = pd.read_csv(files_dir + f)
        contains_urls, index = get_url_column(rows)
        if(contains_urls):
            links = pd.read_csv(files_dir + f, usecols=[index]).values.T.tolist()[0]
            links = list(map(delete_queries,links))
            urls += links
    return urls

def get_url_column(rows):
    row = rows.iloc[0].values.tolist()
    for elem in row:
        cell = tldextract.extract(elem)
        if(cell.domain != ""):
            return True, row.index(elem)
    return False, -1

def check_column(column):
    for row in column:
        cell = tldextract.extract(row)
        if(cell.domain == ""):
            return False
    return True

# Function that extracts the domains from a list of urls
def extract_domains(urls):
    domains = []
    for url in urls:
        ext = tldextract.extract(url)
        if ext.subdomain != "": # Checks if link has subdomain and registered_domain
            domain = ext.subdomain + "." + ext.registered_domain
            domains.append(domain)
        elif ext.domain != "": # If no subdomain, then only extract the registered_domain
            domains.append(ext.registered_domain)
        # else: # Otherwise, the parameter given is not an url
        #     print("URL is not valid: " + url)
    return domains
