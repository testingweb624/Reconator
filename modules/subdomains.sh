#!/bin/bash
# https://github.com/gokulapap/submax
# subdomain enumeration
sudo apt install jq amass -y;
sudo apt install parallel -y;
url=$url

/app/modules/binaries/subfinder -silent -d $url > /app/sub1
curl -s "https://crt.sh/?q=$url" | grep "<TD>" | grep $url | cut -d ">" -f2 | cut -d "<" -f1 | sort -u | sed '/^*/d' > /app/sub2
curl -s "https://riddler.io/search/exportcsv?q=pld:$url" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u > /app/sub3
curl -s "https://jldc.me/anubis/subdomains/$url" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | cut -d "/" -f3 > /app/sub4
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$url/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' |sort -u > /app/sub5
echo "[+] Web.Archive.org Over => $(wc -l warchive_$url.txt|awk '{ print $url}')"
curl -s "https://dns.bufferover.run/dns?q=.$url" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$url" | sort -u > dnsbuffer_$url.txt
curl -s "https://dns.bufferover.run/dns?q=.$url" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$url" | sort -u >> dnsbuffer_$url.txt 
curl -s "https://tls.bufferover.run/dns?q=.$url" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$url"| sort -u >> dnsbuffer_$url.txt 
sort -u dnsbuffer_$url.txt -o /app/sub6
echo "[+] Dns.bufferover.run Over => $(wc -l /app/sub6|awk '{ print $url}')"

curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$url"|jq -r '.subdomains' 2>/dev/null |grep -o "\w.*$url" > /app/sub7
echo "[+] Threatcrowd.org Over => $(wc -l /app/sub7|awk '{ print $url}')"
  
curl -s "https://api.hackertarget.com/hostsearch/?q=$url"|grep -o "\w.*$url"> /app/sub8
echo "[+] Hackertarget.com Over => $(wc -l /app/sub8 | awk '{ print $url}')"

curl -s "https://certspotter.com/api/v0/certs?domain=$url" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$url" | sort -u > /app/sub9
echo "[+] Certspotter.com Over => $(wc -l /app/sub9 | awk '{ print $url}')"

curl -s "https://www.virustotal.com/ui/domains/$url/subdomains?limit=40"|jq -r '.' 2>/dev/null |grep id|grep -o "\w.*$url"|cut -d '"' -f3|egrep -v " " > /app/sub10
echo "[+] Virustotal Over => $(wc -l /app/sub10|awk '{ print $url}')"
    
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$url/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$url"|sort -u > /app/sub11
echo "[+] Alienvault(otx) Over => $(wc -l /app/sub11|awk '{ print $url}')"
    
curl -s "https://urlscan.io/api/v1/search/?q=domain:$url"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$url"|sort -u > /app/sub12
echo "[+] Urlscan.io Over => $(wc -l /app/sub12|awk '{ print $url}')"
  
curl -s "https://api.threatminer.org/v2/domain.php?q=$url&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$url"|sort -u > /app/sub13
echo "[+] Threatminer Over => $(wc -l /app/sub13|awk '{ print $url}')"
  
curl -s "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=$url&includeExpired=false&exactMatch=false&limit=5000" | jq -r '.[].subjectDN' 2>/dev/null |sed 's/cn=//g'|grep -o "\w.*$url"|sort -u > /app/sub14
echo "[+] Entrust.com Over => $(wc -l /app/sub14|awk '{ print $url}')"
  
/app/modules/binaries/assetfinder --subs-only $url > /app/sub15
echo "[+] Assetfinder Over => $(wc -l  /app/sub15|awk '{ print $url}')"
  
  
echo "7) SUBDOMAINS" >> /app/results/$url-output.txt
printf "\n\n" >> /app/results/$url-output.txt

sort /app/sub1 /app/sub2 /app/sub3 /app/sub4 /app/sub5 /app/sub6 /app/sub7 /app/sub8 /app/sub9 /app/sub10 /app/sub11 /app/sub12 /app/sub13 /app/sub14 /app/sub15 | uniq | tee /app/$url-subs
sort /app/sub1 /app/sub2 /app/sub3 /app/sub4 /app/sub5 /app/sub6 /app/sub7 /app/sub8 /app/sub9 /app/sub10 /app/sub11 /app/sub12 /app/sub13 /app/sub14 /app/sub15 | uniq | tee -a /app/results/$url-output.txt

printf "\n\n\n" >> /app/results/$url-output.txt
printf "##########################################################################################\n" >> /app/results/$url-output.txt
printf "##########################################################################################" >> /app/results/$url-output.txt
printf "\n\n\n" >> /app/results/$url-output.txt
