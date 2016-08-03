import requests
import json
import re
import time
import sys
import math
import pandas as pd
import numpy as np
from os import listdir
from colorama import Fore
from extract_urls import *


# Constants that represent the API and the APIKEY
SWORDPHISH_API = 'https://api.easysol.io/swordphish/'
SWORDPHISH_APIKEY = ''  # Please specify your API KEY
SAMPLE_DIRECTORY = 'sample/'
COLS = False


def call_swordphish(apikey,params):
    # Function that calls the Swordphish API
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


def calculate_stats(type, index, results):
    # Function that calculates diffrent stats for certain calculation:
    if type == 'PHISHING':
        red_mark = 60
        yellow_mark = 50
    elif type == 'DGA':
        red_mark = 70
        yellow_mark = 50
    else:
        red_mark = 50
        yellow_mark = 25
    stats = Fore.WHITE + "** " + type + " STATS  **" + "\n"
    scores = [item[index] for item in results]
    green, yellow, red = [],[],[]
    for score in scores:
        if(int(float(score)*100) > red_mark):  # Definetely not a safe link
            red.append(score)
        elif(int(float(score)*100) > yellow_mark):  # Not 100% sure that its safe
            yellow.append(score)
        else:
            green.append(score)  # Definetely a safe link
    # Calulates the precentage of links that were definetely unsafe and assings a red color when printed
    red_percent = Fore.RED + str(round(len(red)/len(results)*100,2)) + "% of the links have been categorized as " + type + ".\n"
    # Calulates the precentage of links that were not 100% sure and assings a yellow color when printed
    yellow_percent = Fore.YELLOW + str(round(len(yellow)/len(results)*100,2)) + "% of the links have not been marked completely safe." + "\n"
    # Calulates the precentage of links that were definetely safe and assings a green color when printed
    green_percent = Fore.GREEN + str(round(len(green)/len(results)*100,2)) + "% of the links are safe." + "\n"
    # Adds the stats to the original message
    stats += red_percent + yellow_percent + green_percent
    return stats


def classify(lis):
    # Function that classifies if the urls if they are phishing or not
    classfied_list = []
    for l in lis:
        if int(float(l[2])*100) > 60:
            tup = l + (1,)
        else:
            tup = l + (0,)
        classfied_list.append(tup)
    return classfied_list


def initialize(type, column=None):
    # Function that puts together all the other methods, and decides type of information is going to be used
    if(column == None):
        array = extract_urls_default(SAMPLE_DIRECTORY)
    else:
        array = extract_urls_override(SAMPLE_DIRECTORY,column)
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

    start_time = time.time()  # starts cofrom colorama import Foreunting time
    final_results = []
    for batch in final_array:
        params = {
          "urlArray": batch,
          "force_clf": False
        }
        results = call_swordphish(SWORDPHISH_APIKEY, params)  # calls Swordphish
        final_results += results
    sphish_time = round((time.time()-start_time)*1000,2)  # ends the counter
    avg_query_time = round(sphish_time/length,2)  # calculates average time per query
    print("** SWORDPHISH PROCESS TIMING ** ")
    print("-- Total time elapsed:     " + str(sphish_time) + "ms")
    print("-- Average time per query: " + str(avg_query_time) + "ms")

    phishing_stats = calculate_stats("PHISHING", 2, final_results)
    print(phishing_stats)
    dga_stats = calculate_stats("DGA", 3, final_results)
    print(dga_stats)
    malware_stats = calculate_stats("MALWARE", 4, final_results)
    print(malware_stats)
    final_results = classify(final_results)
    return final_results


# EXAMPLE FUNCTION TO SHOW WHAT USERS CAN DO WITH THE SOFTWARE
# Function that has as a parameter a DataFrame with two columns (IP Address, URL)
# and returns the list of IP addresses that had the highest chance of being victims of phishing
# def ip_risk(firewall_df):
#     risk_list = []
#     url_array = firewall_df[['URL']].values.T.tolist()[0][15:30] # extracts urls
#     url_array = list(map(delete_queries,url_array))
#     ip_array = firewall_df[['IP Address']].values.T.tolist()[0][15:30]
#     results = initialize(url_array, DATA_TYPE) # Runs the script
#     for r in results:
#         if float(r[2]) >= 0.9:
#             risk_list.append((ip_array[results.index(r)], url_array[results.index(r)], r[2]))
#     risk_list = sorted(risk_list, key=lambda x: x[2], reverse=True)
#     print(Fore.WHITE + "\n .: IP addresses with highest risk :. \n")
#     for risky in risk_list:
#         print(Fore.RED + str(risky) + "\n")
#     return results, risk_list


def create_csv(results, title):
    df_url = pd.DataFrame(results, columns = ['URL', 'Rank', 'Phishing Score', 'DGA Score', 'Malware Score', "Phishing Classifier"])
    df_url.to_csv('swordphish_' + title + '_results.csv')


if __name__ == '__main__':
    # Runs the code
    # Checks if the input has the first argument
    if len(sys.argv) < 1:
        sys.exit("Inputs are missing. Please try again")
    # Checks if the argument is valid
    if sys.argv[1] == 'urls' or sys.argv[1] == 'domains':
        DATA_TYPE = sys.argv[1]
    else:
        sys.exit("First argument is invalid. Options are: urls or domains")

    # Checks if the input has the second argument
    if len(sys.argv) == 3:
        if sys.argv[2].isdigit():
            column = sys.argv[2]
            COLS = True
        else:
            sys.exit("Second arugment is not a number. Please select a valid column number")

    if len(sys.argv) > 3:
        sys.exit("Too many inputs. Please try again")

    if COLS:
        results = initialize(DATA_TYPE, column)
    else:
        results = initialize(DATA_TYPE)
    create_csv(results, 'sample')
