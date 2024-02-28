# OSINT
OSINT: Open Source INTelligence (Inteligencia de Fuentes Abiertas) 



# Search engines

## Google Dorks and Search Engine operators

- `site:website.com` get results from a specific website
- `AND` using `keyword AND otherkeyword` will get results that have both the keywords
- `"keyword otherkeyword"` will give results with this formulation in this order
- `OR` using `keyword OR otherkeyword` will get results that have either these keywords
- We can use wildcard with `*`
- `filetype:pdf` will give results according to the filetype mentionned here for instance we will get only pdf results
- `-subdomain` will remove a specific subdomain from the search results example: `site:website.com -www`
  - Can work with any other keyword that we do not want in the search results `-keyword`
- `intext:keyword` get results with the keyword in the text
- `inurl:keyword` look for url with a specific keyword in them
- `intitle:keyword` look for title with a specific keyword in the title

## Resources
- https://www.google.com/advanced_search


# What to do with a picture

## Reverse Image Searching

- Pretty straightforward we can use this link to do reverse Image searching, you just need to upload the image you are looking for information about
  - [Google Image Search](https://images.google.com)
  - [TinEye](https://tineye.com)  
  - [Yandex](https://yandex.com/)

## Get EXIF Data

Photo have data that is tied to the device and owner of the device

### How to get this data

Using the website Jeffrey's Image Metadata Viewer (see resources) we can extract this information. This contains the device info and geolocalisation.

## Physical Location

- Using the address a customer gave us for a physical pentest mandate, we can enter it in google map and have a look at the sattelite view and street:
  - Does it have any protection
  - Where to park without looking suspicious
  - Is the entree guarded
  - Is there a smoke area (useful for social engineering)
  - Could you tailgate your way in?

## Identifying Geographical Locations

Let's say we have an image
- If there is a car: 
  - where is it parked, 
  - what brand is it, 
  - What info get we get from the license plate, 
- How is the weather
  - Is it snowing?
- Architecture around 
- Street signs


### Resources
- https://images.google.com



# Discovering Email Addresses

## Lookup using websites

- [Hunter](https://hunter.io/) 50 free searches/month
We can use this tool to look for email address with a company name for instance. It is also useful to identify patterns on how the email address are built.
- [Phonebook](https://phonebook.cz/)
- [Voilà Norbert](https://www.voilanorbert.com/)
- [Clearbit connect](https://chrome.google.com/webstore/detail/clearbit-connect-supercha/pmnhcgfcafcnkbengdcanjablaabjplo?hl=en) need to be added on google chrome, but very powerful. Lots of filters, returns lots of info as well,..

## Methodology

- Look on google "who is in this role at this company" for example
- Then we can use phonebook or hunter and try to find the email pattern
- Then we can take the email and verify it with [emailhippo](https://tools.emailhippo.com/) or [emailchecker](https://email-checker.net/)

## Other tips

- We can use password recovery or account recovery to get more info about the user


# OSINT Password

## Hunting Breached password

- We can use [dehashed](https://dehashed.com/) **cost money**
  - If a similar password pops multiple times it means it could be used somewhere else.
  - Dehashed will also allow us to lookup for password and give information on where it is coming from
- [WeLeakInfo](https://weleakinfo.to/)
- [Snusbase](https://snusbase.com/)
- [HaveIBeenPwned](https://haveibeenpwned.com/)
- [Scylla](https://scylla.so/)

## Breachparse

- Get the tool [here](https://github.com/hmaverickadams/breach-parse)
- This tool will searched through the breach data and pull down names
- `./breach-parse.sh @domain.com outfile.txt` gather breached emails and passwords from the mentionned domain and put it in a file using the name mentioned
- At the end of the execution we will get 3 files `outfile-master.txt` with email and passwords, `outfile-passwords.txt` with the pulled passwords nd `outfile-users.txt` with the users

## Other tips

- If we get hash:
  - We can try to crack it
  - It can be useful to search it and see if it ties back to something else 
- Developers often share whole sections of code on StackOverflow  (we could find leaks there)
- Github migh have private keys or secret as well


# OSINT usernames

## Hunting usernames and account

- [Name](https://namechk.com/)
- [Whatsmyname](https://whatsmyname.app/)
- [Name check up](https://namecheckup.com/)
- [kik.me/username-you-are-looking-for](https://kik.me/)
- Keep in mind that we could find a full name via username



# OSINT People

**!!! PLEASE USE RESPONSIBLY !!!**

These websites are mostly US based

- [WhitePages](https://www.whitepages.com/)
- [TruePeopleSearch](https://www.truepeoplesearch.com/)
- [FastPeopleSearch](https://www.fastpeoplesearch.com/)
- [FastBackgroundCheck](https://www.fastbackgroundcheck.com/)
- [WebMii](https://webmii.com/)
- [PeekYou](https://peekyou.com/)
- [411](https://www.411.com/)
- [Spokeo](https://www.spokeo.com/)
- [That'sThem](https://thatsthem.com/)

## Voter records (US only)

- [Voter Records](https://voterrecords.com/)

## Hunting phone numbers

- Note: be aware that these websites and google will probably keep the phone numbers you enter.
- [TrueCaller](https://www.truecaller.com/)
- [CallerID Test](https://calleridtest.com/)
- [Infobel](https://infobel.com/)
- Possible to use a phone emoji and type a specific name business next to it in the search  
- [Infobel](https://www.infobel.com/fr/world)

## Discovering birth date

- Using google dorks we could try something like this `"firstname lastname" intext:birthday`
  - we can also use the `site:` option to search

## Searching for resumes

- `""firstname lastname" resume`
  - we could also add `filetype:pdf` (or doc docx etc) or `site`




# OSINT Social media

## Twitter

### Searching from Twitter

- Filter search with latest people videos photos
- we can use quotes just like in google "sentence I am looking for"
- We can use `from:username`
- `to:username`
- `@username`
- `from:username since:YYY-MM-DD until:YYYY-MM-DD`
- `to:username since:YYY-MM-DD until:YYYY-MM-DD`
- `"sentence I am looking for" since:YYY-MM-DD until:YYYY-MM-DD`
- `from:username keyword`
- `geocode:xx.xxxx, -xx,xxx, xxkm` Identify tweets coming from a specific area
- We can also use [Twitter Advanced Search](https://twitter.com/search-advanced)

### Searching Twitter using web tools

- [Social Bearing](https://socialbearing.com/)
- [Twitonomy](https://www.twitonomy.com/)
- [Sleeping Time](http://sleepingtime.org/)
- [Mentionmapp](https://mentionmapp.com/)
- [Tweetbeaver](https://tweetbeaver.com/)
- [Spoonbill.io](http://spoonbill.io/)
- [Tinfoleak](https://tinfoleak.com/)

### Tweetdeck

- [Tweetdeck](https://tweetdeck.twitter.com)
- We can add columns and add a home page for instance
- We can add a column to track a specific user 
- We can make search with search operators and add it as a column

## Facebook

- Difficult to keep up because facebook changes all the time.
- We can search for `photos of firstname lastname` we will get photos of those who tagged the user we are interested in
- We can use tools
  - [Sowdust Github](https://sowdust.github.io/fb-search/)
  - [IntelligenceX Facebook Search](https://intelx.io/tools?tab=facebook)

## Instagram

- Check who they are following
- Do not underestimate Google "username site: instagram.com"
- [Wopita](https://wopita.com/)
- [Code of a Ninja](https://codeofaninja.com/tools/find-instagram-user-id/)
- [InstaDP](https://www.instadp.com/)
- [ImgInn](https://imginn.com/)

## Snapchat

- [Snapchat Maps](https://map.snapchat.com)

## Reddit

- we can use the reddit search
- We can search with google "username site:reddit.com"

## LinkedIn

- Check the contact info
- Do reverse image search
- Check recommendations received and given
- If we find people we can use it to make email address using a pattern we might have previously found
- Check the about section of a profile
- Check the career as well

## TikTok

- Search for a username tiktok.com/@username
- Google




# OSINT - Website

## Search

- Google: `website` or `"website"` or `site:website`
- [Domain Dossier](https://centralops.net/co/)
- [DNSlytics](https://dnslytics.com/reverse-ip)
- [SpyOnWeb](https://spyonweb.com/)
- [Virus Total](https://www.virustotal.com/)
- [Visual Ping](https://visualping.io/)
- [Back Link Watch](http://backlinkwatch.com/index.php) Where your website has been posted
- [View DNS](https://viewdns.info/)
- [Central ops](https://centralops.net/co/)

## Identify Website technology

- [BuiltWith](https://builtwith.com/) identify website technology
- [Wappalyzer](https://www.wappalyzer.com/) browser add on to identify website technology

## Hunting down subdomains

- With google we can look for a specific website using `site:name` and add `inurl:admin` or `inurl:dev` we can also remove subdomain with `-www`
- [Pentest-Tools Subdomain Finder](https://pentest-tools.com/information-gathering/find-subdomains-of-domain#)
- [Spyse](https://spyse.com/)
- [crt.sh](https://crt.sh/) we can use a wildcard to search for example `%.domain.com`
  - `curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .` output results in json
  - `curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u` remove duplicates
  - `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done`
- `dig any inlanefreight.com`
  - **A records**: We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.
  - **MX records**: The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.
  - **NS records**: These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.
  - **TXT records**: this type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as SPF, DMARC, and DKIM, which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results.

## Must to use tools

- [Shodan](https://shodan.io) we can use dorks to filter our search with words like `city:` `port:` `org:`
  - `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done` generate a list of IP addresses
  - `for i in $(cat ip-addresses.txt);do shodan host $i;done` run the list through Shodan.
- [Wayback Machine](https://web.archive.org/)

## Methodology for subdomain enum

- We look up with the tools if we can find subdomains
- We check if they are alive with a tool like httpprobe
- We check the subdomains to see what we can do, we can use a tool like Photon that will make screenshot of the list of active subdomains found. This will make our work faster.

## Automate subdomain enumeration

- We can use this code. It was made by Heath Adams on his OSINT course in TCM Security Academy. You can check out this course [here](https://academy.tcm-sec.com/p/osint-fundamentals)
- It will see whois, find subdomains. Once it finds subdomain it is going to check if the subdomains are alive and then it will screenshot the subdomains that are alive.
- It will use automated tools (subfinder, assetfinder, amass, httprobe) that you can find info
- We can make it better and more suited to our needs, like adding other subdomain enum tools, etc..
- There is also a tool called Photon that we can use for similar purposes

```bash
#!/bin/bash

# We want the first argument to be a domain it will be launch like this ./script domain.com
domain=$1
RED="\033[1;31m"
RESET="\033[0m"

info_path=$domain/info
subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots

# will create all necessary folder for our findings
if [ ! -d "$domain" ];then
    mkdir $domain
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$subdomain_path" ];then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ];then
    mkdir $screenshot_path
fi

echo -e "${RED} [+] Checkin' who it is...${RESET}"
whois $1 > $info_path/whois.txt

echo -e "${RED} [+] Launching subfinder...${RESET}"
subfinder -d $domain > $subdomain_path/found.txt

echo -e "${RED} [+] Running assetfinder...${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt

#echo -e "${RED} [+] Running Amass. This could take a while...${RESET}"
#amass enum -d $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Checking what's alive...${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt

echo -e "${RED} [+] Taking dem screenshotz...${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path/ --no-http
```



# Hunting Business info

## LinkedIn

- Check the company page. We can find name of employees.
- If names are not showed we can google the title
- search on google `site:linkedin.com/in/ "* at companyName"` 
- We can use websites like these:
  - [Open Corporates](https://opencorporates.com/)
  - [AI HIT](https://www.aihitdata.com/)


# OSINT Wireless 

- [WiGLE](https://wigle.net/)
  - We need to register and then we can see the map but we can also make advanced search by SSID name




# OSINT Tools

## Exiftool

- Tool to get information from a file (image or pdf)

### Install

- Install on kali: `sudo apt install libimage-exiftool-perl`

### Use

- `exiftool filename`

## The Harverster

- Tool to hunt emals and breached data
- Preinstalled on kali linux

### Use

- `theHarverster -d domain.com -b all` will get infos about domain.com from all search engines available with the tool.
- Can be combined with other tools such as:
  - [breach-parse](https://github.com/hmaverickadams/breach-parse)
  - h8mail

## Tools for username and Account OSINT

### whatsmyname

#### Install

- `git clone https://github.com/WebBreacher/WhatsMyName.git`
- `cd WhatsMyName`

#### Use

- `python3 web_accounts_list_checker.py -u username`

### Sherlock

#### Install

- `sudo apt install sherlock`

#### Use

- `sherlock username`

## phoneinfoga

- A tool to osint phone number

### Install

- `curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash`
- `tar -xf phoneinfoga_Linux_x86_64.tar.gz`

### Use

- `phoneinfoga serve -p 8080` will serve the gui on port 8080 then you will just have to go to http://localhost:8080 and make a research
- `phoneinfoga scan -n number` you will need to specify the cuntry code in front of the number for example for US or Canada you need to put 1

## Twint

- Tool for Twitter OSINT available [here](https://github.com/twintproject/twint).

## Use

- Upgrade
  - `pip3 install --upgrade -e git+https://github.com/twintproject/twint.git@origin/master#egg=twint`
  - `pip3 install --upgrade aiohttp_socks`
- `twint -u username`
- `twint -u username -s keyword`
- Lots of other possibilities it is worth reading the doc

## Tools for website OSINT

### Identifying website technology

#### Wappalyzer

- We can use the browser add on [Wappalyzer](https://www.wappalyzer.com/) to see the technologies used on the website

#### Whatweb

- It is preinstalled on Kali. You can find the githb page [here](https://github.com/urbanadventurer/WhatWeb)
- `whatweb webiste.com`

### Hunting subdomain

#### Sublist3r

- Tool to find subdomains. See about it [here](https://github.com/aboul3la/Sublist3r)
- `apt install sublist3r` Install it
- `sublist3r --domain [domain_name]` launch it

#### Subfinder

- Tool to find subdomains
- Available [here](https://github.com/projectdiscovery/subfinder)
- `subfinder -d domain`

#### Assetfinder

- Another tool to find subdomains
- Available [here](https://github.com/tomnomnom/assetfinder)
- `assetfinder domain` we can put our results in a file by adding `> results.txt` if you already have a file with results you can append it with `>>` instead of `>`
- 

#### Amass

- Tool for subdomain enumeration
- Available [here](https://github.com/OWASP/Amass)
- `amass enum -d domain`

#### httprobe

- After finding multiple subdomains we can use httprobe to check if they are alive or not
- Find httprobe [here](https://github.com/tomnomnom/httprobe)
- We could use a command like this `cat findings.txt | sort -u | httprobe -s -p https:443` we can limit our results to port 443
- We can put our result in a file named `alive-findings.txt` (we then need to strip `https://`, `http://` and `:443` and use it in gowitness

#### Gowitness

- We can also go through our findings and get screenshots of them using gowitness
- Find GoWitness [here](https://github.com/sensepost/gowitness/wiki/Installation)
- `gowitness file -f ./alive-findings.txt -P ./screenshots --no-http` this command will go through every finding and make a screenshot

### Burp Suite

- The community edition is preinstalled on kali
- You can get it [here](https://portswigger.net/burp)
- We can use burpsuite as well and check the response headers of our targeted website to see if it discloses any interesting information.

## OSINT Frameworks

### Recon-ng

- Find it [here](https://github.com/lanmaster53/recon-ng/wiki) along with some documentation
- `recon-ng`
- `marketplace search` see all available tools
- `marketplace install tool` install one of the tool from the market (some of them require API keys)
- `modules load tool` load the tool just installed
- `info` to see what we can do with the module
- `options set ITEM setting` to set something in the module for instance if we were playing with hackertarget we could do `options set SOURCE domain.com`
- `run` to run the module
- Some nice module on recon-ng are hackertarget (OSINT on website such as subdomain enum and ip adr finder), profiler (search for accounts with a specific userame on different websites)

### Maltego

- Preinstalled on kali
- Run for free register and account confirm it
- We will need api keys for most of the modules
- We can use it without modules also
- We can make a new graph domain for instance if we want to make website OSINT

## Hunchly

- Paid tools but free trial possible. Only runs on google chrome.
- Find Hunchly [here](https://hunch.ly)
- We can launch new case and keep them in our dashboard
- We can start the "tracking" and add it to a specific case
- We can highlight keywords, take notes on website
- It will record everything viewed



 # Write an OSINT report

- It has to be very detailed so that the person you will hand the report will be able to reproduce what you did.

## Summary

- We remind here the goals and who mandate us to do what


## Key findinds

- We can sum up here some key high level findings found during the assement (usernames, phone numbers etc.)

## Technical evidence

- Step by step what has been done to find something
- Each technical evidence can be a step.
- We can make it look like a table like this:  

|OSINT| Osint Action done for example username found on websites|
|-----|---------------------------------------------------------|
|Link| link or reference to the used technology|
|notes|explanations and details|

- Then we can add a visual evidence

