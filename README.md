<h1 align="center">
  <br>
<img src="https://user-images.githubusercontent.com/59805766/222277298-6b996410-da72-4d0d-b111-ae9d51b315de.png" alt="subtracker"></a>
</h1>
<h4 align="center">Gain the edge in hidden subdomain discovery with Subtracker.</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://github.com/ReverseTEN/subtracker/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
</p>

<p align="center">


# subtracker

Subtracker is a reconnaissance tool that uses DNS brute-forcing and a merged list of subdomains from subfinder, crt.sh, and abuseipdb to uncover even the most obscure subdomains of a target domain. 
With Subtracker, you can proactively identify hidden subdomains that could be susceptible to exploitation, staying one step ahead of other bug hunters. by automating the subdomain discovery process, Subtracker saves you time and effort while providing Valuable outcomes

Subtracker leverages automated DNS brute-forcing and a comprehensive wordlist from [Assetnote]((https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)) to efficiently explore the target domain and discover valuable subdomains that may be missed by other tools. Additionally, **Subtracker compares the results of DNS brute-forcing with the common merged subdomain list to identify subdomains that are critical to your project or research**.

But how does Subtracker determine the value of a subdomain? 

**The program compares the subdomains obtained by DNS brute-forcing with those in the common list. If a subdomain is present in the Bruteforce list but not in the common list, it means that fewer people have discovered it, making it potentially more valuable to your project or research.**



## Installation

Before running the script, ensure that the following packages are installed:

- subfinder: a subdomain discovery tool that uses various public sources to enumerate subdomains of a target domain.
- anew: a tool that filters out elements from a list that already exist in another list.
- dnsgen: a tool that generates permutations of a domain name and resolves them using a DNS server.
- alterx: fast and customizable subdomain wordlist generator using DSL.
- shuffledns: a fast and flexible DNS resolver.
- notify : notify is a lightweight and user-friendly tool that makes it easy to send notifications to messaging platforms like Slack, Discord, and Telegram. 

You can install them using the following command:

```bash

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
git clone https://github.com/ProjectAnte/dnsgen.git

```

Additionally, make sure that the following files are present in the dependency folder:

`resolvers.txt`
`wordlist.txt`


## Usage

``` bash
git clone https://github.com/ReverseTEN/subtracker.git
cd subtracker
chmod +x subtracker.sh
./subtracker.sh domain.tld

```

Replace domain.tld with the target domain.


The script will perform the following steps:

- Find subdomains using crt.sh
- Find subdomains using subfinder
- Find subdomains using abuseipdb
- Merge and remove duplicates
- **Perform DNS brute-forcing using dnsgen & alterx and shuffledns**
- **Compare the subdomains found through brute-forcing with the common merged subdomain list to identify any valuable subdomains with high potential for bug hunting**
- Save the valuable subdomains to a file
- he results will be saved in a folder with the target name.

You can use task schedulers such as Cron Job to automate the process so that as soon as a new subdomain is discovered, you will be notified through your preferred notification channel.

- Create a cronjob by running the following command: `crontab -e`
- Add the following line to the crontab file to run the script every 2 days or at any desired frequency. In this example, I am running it every 2 days.

```
0 0 */2 * * /bin/bash /path/to/subtracker/subtracker.sh domain.tld > /dev/null 2>&1
```

## Customization

You can use a custom wordlist for brute-forcing by placing it in the dependency folder with the name `wordlist.txt`.

## Notifications

notify is a lightweight and user-friendly tool that makes it easy to send notifications to messaging platforms like Slack, Discord, and Telegram. 

To set up notify for your messaging platform, you can follow the instructions on the [Project Discovery GitHub page](https://github.com/projectdiscovery/notify#provider-config).

## Disclaimer

This script is intended for educational and research purposes only. Use it at your own risk.
