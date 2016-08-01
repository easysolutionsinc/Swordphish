import requests
import json
import re
import time
import sys
from os import listdir
import pandas as pd
from colorama import Fore
from extract_urls import *

SWORDPHISH_API = 'https://api.easysol.io/swordphish/'
SWORDPHISH_APIKEY = '' # Please specify your API KEY

def call_swordphish(apikey,params):
    headers = {'apikey': apikey, 'content-type': 'application/json'} # Assign headers
    r = requests.post(SWORDPHISH_API, data=json.dumps(params), headers=headers) # Makes request to the API
    dga_scores, phishing_score, malware_score, url_list, rank_list = [], [], [], [], []
    # Checks if the request was recieved succesfully
    if (r.status_code == 200):
        for item in r.content.decode("utf-8").split("\n"):
            if "\"dga\": " in item: # Extracts DGA predicted result
                dga_scores.append(item.strip().split("\"dga\": ")[1][:-1])
            if "\"malware\": " in item: # Extracts MALWARE predicted result
                malware_score.append(item.strip().split("\"malware\": ")[1][:-1])
            if "\"phishing\": " in item: # Extracts PHISHING predicted result
                phishing_score.append(item.strip().split("\"phishing\": ")[1][:-1])
            if "\"rank\": " in item: # Extracts RANK of the url
                rank_list.append(item.strip().split("\"rank\": ")[1][:-1])
            if "\"url\": " in item: # Extracts the URL
                url_list.append(item.strip().split("\"url\": ")[1][1:-1])
    # If the request fails, then returns the message given by the API
    else:
        result = "System failed to calculate the phishing probability"
        return r.content.decode("utf-8")
    # Joins all the collected results
    results = zip(url_list, rank_list, phishing_score, dga_scores, malware_score)
    return list(results)

# Function that puts together all the other methods, and decides type of information is going to be used
def initialize(type, array):
    # Chooses URLS to make the calculations with Swordphish
    if(type=="urls"):
        print(".:: TESTING LOGS WITH FULL URLS ::." + "\n")
        chosen_array = array
        chosen_array = pd.DataFrame(chosen_array)
        chosen_array.columns = ['url']
    # Chooses DOMAINS to make the calculations with Swordphish
    else:
        print(".:: TESTING LOGS BY EXTRACTING DOMAINS ::." + "\n")
        chosen_array = extract_domains(array)
        chosen_array = pd.DataFrame(chosen_array)
        chosen_array.columns = ['domain']

    if(len(chosen_array) < 1):
        sys.exit('The tested .csv file does not contain urls')

    final_array = []
    length = chosen_array.shape[0]
    print("Number of urls being test: " + str(length))
    index = np.array_split(np.arange(0,length), math.ceil(length / 1000))
    for index_ in index:
        final_array.append(chosen_array.iloc[index_].values.T.tolist()[0])

    start_time = time.time() # starts cofrom colorama import Foreunting time
    final_results = []
    for batch in final_array:
        params = {
          "urlArray": batch,
          "force_clf": True
        }
        results = call_swordphish(SWORDPHISH_APIKEY, params) # calls Swordphish
        final_results += results
    sphish_time = round((time.time()-start_time)*1000,2) # ends the counter
    avg_query_time = round(sphish_time/length,2) # calculates average time per query
    print("** SWORDPHISH PROCESS TIMING ** ")
    print("-- Total time elapsed:     " + str(sphish_time) + "ms")
    print("-- Average time per query: " + str(avg_query_time) + "ms")

    phishing_stats = calculate_stats("PHISHING", 2, final_results)
    print(phishing_stats)
    dga_stats = calculate_stats("DGA", 3, final_results)
    print(dga_stats)
    malware_stats = calculate_stats("MALWARE", 4, final_results)
    print(malware_stats)
    return final_results

# Function that calculates diffrent stats for certain calculation:
    # Option 1: Calculate stats for Phishing
    # Option 2: Calculate stats for DGA
    # Option 3: Calculate stats for MALWARE
def calculate_stats(type, index, results):
    # Original message
    stats = Fore.WHITE + "** " + type + " STATS  **" + "\n"
    scores = [item[index] for item in results]
    green, yellow, red = [],[],[]
    for score in scores:
        if(int(float(score)*100) > 95): # Definetely not a safe link
            red.append(score)
        elif(int(float(score)*100) > 90): # Not 100% sure that its safe
            yellow.append(score)
        else:
            green.append(score) # Definetely a safe link
    # Calulates the precentage of links that were definetely unsafe and assings a red color when printed
    red_percent = Fore.RED + str(round(len(red)/len(results)*100,2)) + "% of the links have been categorized as " + type + ".\n"
    # Calulates the precentage of links that were not 100% sure and assings a yellow color when printed
    yellow_percent = Fore.YELLOW + str(round(len(yellow)/len(results)*100,2)) + "% of the links have not been marked completely safe." + "\n"
    # Calulates the precentage of links that were definetely safe and assings a green color when printed
    green_percent = Fore.GREEN + str(round(len(green)/len(results)*100,2)) + "% of the links are safe." + "\n"
    # Adds the stats to the original message
    stats += red_percent + yellow_percent + green_percent
    return stats, red

def create_csv(results, title):
    df_url = pd.DataFrame(results, columns = ['URL', 'Rank', 'Phishing Score', 'DGA Score', 'Malware Score'])
    df_url.to_csv('swordphish_' + title + '_results.csv')
