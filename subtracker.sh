#!/bin/bash

################################################################################
#                                                                              #
#                             S U B T R A C K E R                              #
#                                                                              #
#                   Identify hidden subdomains with Subtracker                 #
#                                                                              #
#                           [Author: ReverseTEN]                               #
#                                                                              #
#              GitHub: https://github.com/ReverseTEN/subtracker                #
#                                                                              #
################################################################################




check_requirements() {
  # List of required packages and their installation commands
  declare -A packages=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["anew"]="go install -v github.com/tomnomnom/anew@latest"
    ["dnsgen"]="git clone https://github.com/ProjectAnte/dnsgen.git"
    ["shuffledns"]="go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    ["alterx"]="go install github.com/projectdiscovery/alterx/cmd/alterx@latest
"
  )

  # Check if required packages are installed
  for package in "${!packages[@]}"; do
    if ! command -v "${package}" >/dev/null 2>&1; then
      echo "[inf] The package '${package}' is required but not installed. Install it with: ${packages[$package]}"
      exit 1
    fi
  done

  # Check if resolvers.txt and wordlist.txt files exist in dependency folder
  if [ ! -f "dependency/resolvers.txt" ] || [ ! -f "dependency/wordlist.txt" ]; then
    echo "[err] The dependency folder does not have the required files resolvers.txt and/or wordlist.txt"
    echo "      Please make sure that the files are present in the dependency folder"
    exit 1
  fi
}


InitialCheck () {

    
    mkdir -p .tmp
    mkdir $1
    # Find subdomains using crt.sh
    echo "[+] Gathering subdomains from crt.sh"
    curl -s https://crt.sh/\?q\=\%25.${1}\&output\=json | jq . | grep 'name_value' | awk '{print $2}' | sed -e 's/"//g'| sed -e 's/,//g' |  awk '{gsub(/\\n/,"\n")}1' | sort -u > .tmp/crt-${1}

    
    # Find subdomains using subfinder

    echo "[+] Gathering subdomains from Subfinder"
    subfinder -d ${1} -silent sort -u > .tmp/subfinder-${1}

    echo "[+] Gathering subdomains from abuseipdb"
    curl -s https://www.abuseipdb.com/whois/${1} -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e 's/$/.'${1}'/' | sort -u > .tmp/abuseipdb-${1}
    
    
    echo "[+] Merging and remove Duplicate"
    #sorts and merges three different files containing subdomains discovered through various methods, then saves the result to a text file with the target name.
    sort .tmp/abuseipdb-${1} .tmp/crt-${1} .tmp/subfinder-${1} | uniq > $1/${1}-subdomains.txt
    rm -rf .tmp
    
    #line displays the number of subdomains found for the target and passes it to the next function for further processing.
    
    echo "[+] Target: $1 -> Found $(cat $1/${1}-subdomains.txt | wc -l) subdomains."

    
    #Resolve subdomains with shuffledns using a wordlist and resolvers
    echo "[+] Resolving Subdomains: *This May Take a Moment to Complete.*"
    shuffledns -silent -d $1 -w dependency/wordlist.txt -silent -r dependency/resolvers.txt -o $1/$1-dns
    #checks whether there are any valuable subdomains found from the DNS brute force and notifies the user accordingly.

    cat $1/$1-dns | anew $1/$1-subdomains.txt > $1/$1-valuable_subdomains_dns.txt
    if [ -s "$1/$1-valuable_subdomains_dns.txt" ]; then
        echo "[:globe_with_meridians:] Valuable subdomains discovered through DNS brute force for $1: $(cat $1/${1}-valuable_subdomains_dns.txt | wc -l)" | notify -silent
    else
        :
    fi    
    # Generate additional subdomains using dnsgen and combine with original list
    
    echo "[+] Generate additional subdomains using dnsgen & alterx "
    cat $1/$1-subdomains.txt | dnsgen - > $1/$1-dnsgen
    cat $1/$1-subdomains.txt | alterx -silent > $1/$1-alterx
    cat $1/$1-subdomains.txt > $1/$1-subgen
    sort $1/$1-subgen $1/$1-dnsgen $1/$1-alterx | uniq > $1/${1}-fulldns

    rm -rf $1/$1-dnsgen
    rm -rf $1/$1-subgen
    rm -rf $1/$1-alterx
    echo "[+] Resolving {Full} Subdomains: *This May Take a Moment to Complete.*"

    # Resolve subdomains again using shuffledns with newly generated list
    shuffledns -silent -d $1 -list $1/${1}-fulldns -r dependency/resolvers.txt -o $1/$1-lastdns
    
    echo "[+] Target :$1 -> $(cat $1/$1-dns | wc -l) Resolving {public} Subdomains"
    echo "[+] Target :$1 -> $(cat $1/$1-lastdns | wc -l) Resolving {private} Subdomains"
    
    #updated subdomains
    cat $1/$1-lastdns | anew $1/$1-subdomains.txt > $1/$1-valuable_subdomains.txt
    
    #checks whether there are any valuable subdomains found from the DNS brute force and notifies the user accordingly.
    if [ -s "$1/$1-valuable_subdomains.txt" ]; then
        echo "[:globe_with_meridians:] Valuable subdomains discovered through {FULL} DNS brute force for $1: $(cat $1/${1}-valuable_subdomains.txt | wc -l)" | notify -silent
        # cat $1/$1-valuable_subdomains.txt | notify -silent
    else
        :
    fi
    
    echo "[+] Found $(cat $1/$1-valuable_subdomains.txt | wc -l) high-potential targets!"


    # number of updated subdomains for the target.
    echo "[+] Update  $1 Subdomains To -> $(cat $1/${1}-subdomains.txt  | wc -l)"
    
    rm -rf $1/$1-dns
    rm -rf $1/$1-fulldns
    rm -rf $1/$1-lastdns
    

}

SecondCheck() {

    # This function checks and detects new subdomains, and updates the main subdomain list
    # which was obtained in the first_run function.
    echo "Start Check For New Subdomains "
    mkdir -p $1/.tmp
    
    echo "[+] Gathering subdomains from crt.sh "
    curl -s https://crt.sh/\?q\=\%25.${1}\&output\=json | jq . | grep 'name_value' | awk '{print $2}' | sed -e 's/"//g'| sed -e 's/,//g' |  awk '{gsub(/\\n/,"\n")}1' | sort -u > $1/.tmp/crt-${1}
    
    echo "[+] Gathering subdomains from Subfinder"
    subfinder -d ${1} -silent sort -u > $1/.tmp/subfinder-${1}
    
    # Use curl to query crt.sh for new subdomains related to the target domain,
    # and use jq and sed to extract and format the domain names.
    # Then save the results to a file in the temporary directory.
    echo "[+] Gathering subdomains from abuseipdb"
    curl -s https://www.abuseipdb.com/whois/${1} -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e 's/$/.'${1}'/' | sort -u > $1/.tmp/abuseipdb-${1}
    
    echo "[+] Merging and remove Duplicate"
    
    sort $1/.tmp/abuseipdb-${1} $1/.tmp/crt-${1} $1/.tmp/subfinder-${1} | uniq > $1/${1}-Newsubdomains.txt
    rm -rf $1/.tmp
    
    echo "[+] Target: $1 -> Found $(cat $1/${1}-Newsubdomains.txt | wc -l) new subdomains."


    echo "[+] Generate additional subdomains using dnsgen & alterx "
    
    cat $1/$1-Newsubdomains.txt | dnsgen - > $1/$1-dnsgen2
    cat $1/$1-Newsubdomains.txt | alterx -silent > $1/$1-alterx2

    # Use shuffledns to resolve the DNS records generated by dnsgen,
    # using a list of resolvers and a wordlist to generate permutations of domain names,
    # and save the results to a file.
    echo "[+] Resolving Subdomains: *This May Take a Moment to Complete.*"
    shuffledns -silent -d $1 -w dependency/wordlist.txt -r dependency/resolvers.txt -o $1/$1-dns2
    
    # Combine the original list of new subdomains with the list generated by dnsgen,
    # remove duplicates, and save the results to a file.
    cat $1/$1-Newsubdomains.txt > $1/$1-subgen2
    sort $1/$1-subgen2 $1/$1-dnsgen2 $1/$1-alterx2 | uniq > $1/${1}-fulldns2
    
    rm -rf $1/$1-dnsgen2
    rm -rf $1/$1-subgen2
    rm -rf $1/$1-alterx2

    # Use shuffledns to resolve the DNS names and save the results in a file
    echo "[+] Resolving {FULL} Subdomains: *This May Take a Moment to Complete.*"
    shuffledns -silent -d $1 -list $1/${1}-fulldns2 -r dependency/resolvers.txt -o $1/$1-lastdns2

    echo "[+] Target :$1 -> $(cat $1/$1-dns2 | wc -l) Resolving {public} Subdomains"
    echo "[+] Target :$1 -> $(cat $1/$1-lastdns2 | wc -l) Resolving {private} Subdomains"

    cat $1/$1-lastdns2 | anew $1/$1-Newsubdomains.txt > $1/$1-valuable_subdomains2.txt
        
        
    #checks whether there are any valuable subdomains found from the DNS brute force and notifies the user accordingly.
    if [ -s "$1/$1-valuable_subdomains2.txt" ]; then

        echo "[:globe_with_meridians:] Valuable subdomains discovered through DNS brute force for $1: $(cat $1/${1}-valuable_subdomains2.txt | wc -l)" | notify -silent

        cat $1/$1-valuable_subdomains2.txt | notify -silent
    else
        :
    fi

    #updated main subdomains 
    cat $1/$1-Newsubdomains.txt | anew $1/$1-subdomains.txt > $1/$1-NewTarget.txt

    if [ -s "$1/$1-NewTarget.txt" ]; then
        echo "[:globe_with_meridians:] Recently added subdomain: " | notify -silent
        cat $1/$1-NewTarget.txt | notify -silent
    else
        echo "[:globe_with_meridians:] No new subdomains have been discovered. " | notify -silent
    fi

    echo "[+] Found $(cat $1/$1-valuable_subdomains2.txt | wc -l) high-potential targets!"

    echo "[+] New subdomains found in $1: $(cat $1/${1}-NewTarget.txt | wc -l)."

    echo "[+] Update  $1 Subdomains To -> $(cat $1/${1}-Newsubdomains.txt  | wc -l)" 
    
    rm -rf $1/$1-dns2
    rm -rf $1/$1-fulldns2
    rm -rf $1/$1-lastdns2
    rm -rf $1/$1-Newsubdomains.txt
    rm -rf $1/$1-NewTarget.txt
    

}


main (){

    check_requirements
    # if the directory exists
    if [ -d "$1" ]; then
        
        SecondCheck $1
    else
        InitialCheck $1
    fi
}

main $1

