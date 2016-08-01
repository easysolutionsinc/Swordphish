# SWORDPHISH API

## Getting Started
This is an example python script that shows how the Swordphish API can be used. It can also work as a template for users to test it with their own data.  

## Suggested Use-Cases
  1. ISP/abuse processing/triage

  2. Enterprise (big company) Malware Domain Risk Prediction

  3. Email parser, URL scanning (urls extracted from inbound emails)

## Prerequisities
 * Python 3.5 to be able to run the script
 * After installing the python version required, all you need is an API KEY to be able to run it!

## Installation
There is no need to run any command to install Swordphish, you just need the API KEY to be able to access the software.

Swordphish can be accessed with the following link: [Swordphish API](https://api.easysol.io/swordphish/)


## Running the code
The function within the code that runs the script:
```python
initialize(type, column=None)
```
There are two versions, swordphish_api.py and simple_swordphish.py
* The first one (swordphish_api.py) allows the user to input a csv file where the urls will be extracted. This script is constructed as follows:
    1. Type = specifies if the code will use the domains or the whole urls when testng the data
    2. Column = Default is none. But this argument allows the user to override the original url extraction method, and chose what column number should be used.
* The second one (simple_swordphish.py) allows the user to call the function given a url list that already exists. This script is constructed as follows:
    1. Array = List of urls the users whishes to test 
    2. Type = specifies if the code will use the domains or the whole urls when testng the data

This function returns a list of tuples that is constructed as follows:
```python
results = zip(url_list, rank_list, phishing_score, dga_scores, malware_score)
```

There are two arguments that have to been passed when calling the first script.
  1. Argument 1: Domain or URL selector. In this argument the users pick if they want the system to extract the domains from the URL array or not. If the user chooses domains, then the Swordphish will process the domains instead of the URLs. (i.e. domains or urls)
  2. Argument 2 (OPTIONAL): Column number. In case a user prefers to override the url extraction function and chose which specific column he wants, this argument must be filled in.  

The syntax is as follows:
```
python swordphish_api.py arg1 arg2
```
Some examples are:
```
python swordphish_api.py urls
```
or
```
python swordphish_api.py urls 4
```

To run the second script all you need to do is to call the initialize(array,type) function:
  1. Argument 1: Array of urls that user wishes to test.
  2. Argument 2: Domain or URL selector. In this argument the users pick if they want the system to extract the domains from the URL array or not. If the user chooses domains, then the Swordphish will process the domains instead of the URLs. (i.e. domains or urls) 

One example of this would be:
```
url_array = [url_1,url_2,url_3,url_4,url_5]
intialize(url_array, domains)
```

## Features
* Given a list of urls Swordphish calculates the probability of them being:
    1. A phishing site
    2. Malware
    3. DGA

* This specific script allows the user to see different stats such as:
  * Time taken to run the API through the whole list.
  * Time taken by the API to analyze each query.
  * Shows the results for all three different malwares, giving:
    1. Percentage of urls that are definetely malicious (Red).
    2. Percentage of urls that were not marked as completely safe (Yellow).
    3. Percentage of urls that were marked as safe (Green).
  * Prints results in a .csv file for the user to be able to manage results.

## Running own tests
* For the local tests, the user can select which test to run. Either **domains** or **urls**. One of these options has to be selected when calling the script from the terminal. And by placing the .csv file in a new folder you should create in the same directory. This folder should be calles 'sample' . e.g.  
  ```
    python swordphish_api.py domains
  ```
    or
  ```
    python swordphish_api.py urls 
  ```

## License
Copyright (C) Easy Solutions. Apache Licensed. Please refer to LICENSE file.
