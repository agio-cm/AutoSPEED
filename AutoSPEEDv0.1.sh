#!/bin/bash

# some quick colors
RED="\033[1;31m"
BLUE="\033[1;34m"
BLUE2="\033[0;34m"
RESET="\033[0m"
BOLD="\e[1m"

# heading!

echo -e "${RED}"
echo -e "###############################################################################"
echo -e "#${BLUE}                                                                            ${RED} #"
echo -e "#${BLUE}                AAA                                  iiii                   ${RED} #"
echo -e "#${BLUE}               A:::A                                i::::i                  ${RED} #"
echo -e "#${BLUE}              A:::::A                                iiii                   ${RED} #"
echo -e "#${BLUE}             A:::::::A                                                      ${RED} #"
echo -e "#${BLUE}            A:::::::::A           ggggggggg   gggggiiiiiii    ooooooooooo   ${RED} #"
echo -e "#${BLUE}           A:::::A:::::A         g:::::::::ggg::::gi:::::i  oo:::::::::::oo ${RED} #"
echo -e "#${BLUE}          A:::::A A:::::A       g:::::::::::::::::g i::::i o:::::::::::::::o${RED} #"
echo -e "#${BLUE}         A:::::A   A:::::A     g::::::ggggg::::::gg i::::i o:::::ooooo:::::o${RED} #"
echo -e "#${BLUE}        A:::::A     A:::::A    g:::::g     g:::::g  i::::i o::::o     o::::o${RED} #"
echo -e "#${BLUE}       A:::::AAAAAAAAA:::::A   g:::::g     g:::::g  i::::i o::::o     o::::o${RED} #"
echo -e "#${BLUE}      A:::::::::::::::::::::A  g:::::g     g:::::g  i::::i o::::o     o::::o${RED} #"
echo -e "#${BLUE}     A:::::AAAAAAAAAAAAA:::::A g::::::g    g:::::g  i::::i o::::o     o::::o${RED} #"
echo -e "#${BLUE}    A:::::A             A:::::Ag:::::::ggggg:::::g i::::::io:::::ooooo:::::o${RED} #"
echo -e "#${BLUE}   A:::::A               A:::::Ag::::::::::::::::g i::::::io:::::::::::::::o${RED} #"
echo -e "#${BLUE}  A:::::A                 A:::::Agg::::::::::::::g i::::::i oo:::::::::::oo ${RED} #"
echo -e "#${BLUE} AAAAAAA                   AAAAAAA gggggggg::::::g iiiiiiii   ooooooooooo   ${RED} #"
echo -e "#${BLUE}                                           g:::::g                          ${RED} #"
echo -e "#${BLUE}                               gggggg      g:::::g                          ${RED} #"
echo -e "#${BLUE}                               g:::::gg   gg:::::g                          ${RED} #"
echo -e "#${BLUE}                                g::::::ggg:::::::g                          ${RED} #"
echo -e "#${BLUE}                                 gg:::::::::::::g                           ${RED} #"
echo -e "#${BLUE}                                   ggg::::::ggg                             ${RED} #"
echo -e "#${BLUE}                                      gggggg                                ${RED} #"
echo -e "#${BLUE}                                                                            ${RED} #"
echo -e "#${BLUE2}           ${BOLD}Auto${BLUE2}mated ${BOLD}S${BLUE2}can ${BOLD}P${BLUE2}arse ${BOLD}E${BLUE2}numerate ${BOLD}E${BLUE2}xploit ${BOLD}D${BLUE2}ata Collection ${RED}           #"
echo -e "#${BLUE2}                              Script Version 0.1 ${RED}                            #"
echo -e "#${BLUE}                                                                            ${RED} #"
echo -e "#${BLUE2}                         by Chris McMahon and Kyle Hoehn                    ${RED} #"
echo -e "#${BLUE}                                                                            ${RED} #"
echo -e "###############################################################################"
echo -e "${RESET}"

# root check

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo -e "[${RED}!${RESET}] Must be running as root. Quitting.\n"
    exit
fi

# processing options

while getopts 'c:t:s:e:h' opt; do
  case "$opt" in
    c)
      clientcode="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting client code to '$clientcode'"
      ;;
    t)
      targetfile="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting target file to '$targetfile'"
      ;;

    s)
      scantype="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting scan type to '$scantype'"
      ;;
      
    e)
      exclusions="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting exclusions file to '$exclusions'"
      ;;


    h)
      echo -e "[${BLUE}*${RESET}] Usage: $(basename $0) -c clientcode -t targetfile -s scantype [options]"
      echo -e "              -h:  print this help dialog"
      echo -e "              -c:  specify client code"
      echo -e "              -t:  specify target file with IP addresses or ranges to scan"
      echo -e "              -s:  specify scan type"
      echo -e "                   scan types:"
      echo -e "                   all:      full port TCP scan, UDP top 100 scan, egress scans"
      echo -e "                   top1000:  top 1000 TCP ports scan only, then continue"
      echo -e "                   egress:   egress scans only"
      echo -e "              -e:  specify exclusions file\n"
      exit 0
      ;;

    :)
      echo -e "[${RED}!${RESET}] Option requires an argument.\n\n    For usage, use $(basename $0) -h"
      exit 1
      ;;

    ?)
      echo -e "[${RED}!${RESET}] For usage, use $(basename $0) -h"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

sleep 2

echo -e "[${BLUE}*${RESET}] And away we go.....\n"
# Check for missing arguments

if [ -z "$targetfile" ] || [ -z "$scantype" ] || [ -z "$clientcode" ]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Missing required arguments.\n\n    For usage, use $(basename $0) -h"
        exit 1
fi

sleep 2

# checking for wrong scan argument

if [[ "$scantype" != "all" ]] && [[ "$scantype" != "top1000" ]] && [[ "$scantype" != "egress" ]]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Wrong scan type.\n"
        exit 1
fi

# check for exclusions file, creating temporary one if it doesn't exist

if [ -z "$exclusions" ]; then
        touch exclude.tmp
        exclusions=exclude.tmp        
fi


# make directory structure

scandir=./scans
echo -e "[${BLUE}*${RESET}] Creating 'scans' directory..."

if [ -d "$scandir" ];
then
    echo -e "[${RED}!${RESET}] Directory 'scans' already exists. Skipping.\n"
else
  mkdir ./scans
  echo -e "[${BLUE}*${RESET}] Directory 'scans' created successfully. Continuing.\n"
fi

sleep 2


# start scanning

if [[ "$scantype" == "all" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting full port TCP nmap scan...\n"
        tcpscanoutput="./scans/${clientcode}_tcp_fullport"
        tcpgreppable="./scans/${clientcode}_tcp_fullport.gnmap"
        nmap -iL $targetfile -p- --max-retries=2 --stats-every=2m --excludefile ${exclusions} -oA ${tcpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] Full port TCP nmap completed!\n"
        
        echo -e "[${BLUE}*${RESET}] Starting UDP top 100 port nmap scan...\n"
        udpscanoutput="./scans/${clientcode}_udp_top100"
        udpgreppable="./scans/${clientcode}_udp_top100.gnmap"
        nmap -iL $targetfile -sU --top-ports 100 --max-retries=2 --excludefile ${exclusions} --stats-every=2m -oA ${udpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] UDP top 100 ports nmap scan completed!\n"
        
        echo -e "[${BLUE}*${RESET}] Starting egress scans...\n"
        nmap -Pn -p- allports.exposed -oA ./scans/${clientcode}_egress_fullport
        nmap -Pn -p1-40 allports.exposed -oN ./scans/${clientcode}_egress_1-40
        nmap -Pn -p41-80 allports.exposed -oN ./scans/${clientcode}_egress_41-80
        nmap -Pn -p81-120 allports.exposed -oN ./scans/${clientcode}_egress_81-120
        echo -e "\n[${BLUE}*${RESET}] Egress scans completed! \n"
fi

if [[ "$scantype" == "top1000" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting top 1000 TCP nmap scan...\n"
        tcpscanoutput="./scans/${clientcode}_tcp_top1000"
        tcpgreppable="./scans/${clientcode}_tcp_top1000.gnmap"
        nmap -iL $targetfile --top-ports 1000 --max-retries=2 --stats-every=2m --excludefile ${exclusions} -oA ${tcpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] TCP top 1000 ports nmap scan completed!\n"
fi

if [[ "$scantype" == "egress" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting egress scans only...\n"
        nmap -Pn -p- allports.exposed -oA ./scans/${clientcode}_egress_fullport
        nmap -Pn -p1-40 allports.exposed -oN ./scans/${clientcode}_egress_1-40
        nmap -Pn -p41-80 allports.exposed -oN ./scans/${clientcode}_egress_41-80
        nmap -Pn -p81-120 allports.exposed -oN ./scans/${clientcode}_egress_81-120
        echo -e "\n[${BLUE}*${RESET}] Egress scans completed! \n"
        exit 0
fi

# remove temporary exclusions file

tempfile=exclude.tmp
if [ -f "$tempfile" ]; then
    rm exclude.tmp
fi


# parsing script

sleep 2

#  variables

varTempRandom=$(( ( RANDOM % 9999 ) + 1 ))
varTempFile="temp-nmp-$varTempRandom.txt"
if [ -f "$varTempFile" ]; then rm $varTempFile; fi
varDoSummary="Y"
varDoSplit="Y"
varRenameSplit="Y"
varDoWebUrl="Y"
varDoSmbUrl="Y"
varDoLiveHosts="Y"
varInFile=$tcpgreppable
varChangeOutDir="Y"
varCustomOut="./scans/${clientcode}_parsed"
varOutPath="${varCustomOut}/"

echo -e "[${BLUE}*${RESET}] Parsing nmap output "
echo -e "    File: ${tcpgreppable}"

    if [ ! -e "$varCustomOut" ]; then
      mkdir "$varCustomOut"
    else
      varFlagOutExists="Y"
    fi
sleep 2

# Read input file for up-hosts.txt
if [ "$varDoLiveHosts" = "Y" ]; then
  varLine=""
  varLastIP=""
  while read varLine; do
    varOutIP=""
    varOutIP=$(echo $varLine | grep 'Status: Up' | awk '{print $2}')
    if [ "$varOutIP" != "" ] && [ "$varOutIP" != "$varLastIP" ]; then echo "$varOutIP" >> ${varOutPath}up-hosts.txt; varLastIP=$varOutIP; fi
  done < $varInFile
fi

# Process each comma-separated open port result to the CSV temp file, with the host IP
varLine=""
while read varLine; do
  varCheckForOpen=""
  varCheckForOpen=$(echo $varLine | grep '/open/')
  if [ "$varCheckForOpen" != "" ]; then
    varLineHost=$(echo $varLine | awk '{print $2}')
    varLinePorts=$(echo $varLine | awk '{$1=$2=$3=$4=""; print $0}')
# Create temporary file to write each port result for this host
      varTempRandom2=$(( ( RANDOM % 9999 ) + 1 ))
      varTempFile2="temp-nmp2-$varTempRandom2.txt"
      if [ -f "$varTempFile2" ]; then rm $varTempFile2; fi
      echo "$varLinePorts" | tr "," "\n" | sed 's/^ *//g' >> $varOutPath$varTempFile2
# Read the per-host temp file to write each open port as a line to the CSV temp file
    while read varTempLine; do
      varCheckForOpen=""
      varCheckForOpen=$(echo $varTempLine | grep "/open/")
      if [ "$varCheckForOpen" != "" ]; then
        varLinePort=$(echo $varTempLine | awk -F '/' '{print $1}')
        varLineTCPUDP=$(echo $varTempLine | awk -F '/' '{print $3}')
        varLineProto=$(echo $varTempLine | awk -F '/' '{print $5}')
        varLineSvc=$(echo $varTempLine | awk -F '/' '{print $7}')
        echo "$varLineHost,$varLinePort,$varLineTCPUDP,$varLineProto,$varLineSvc" >> $varOutPath$varTempFile
      fi
    done < $varOutPath$varTempFile2
    rm $varOutPath$varTempFile2
  fi
done < $varInFile

mv $varOutPath$varTempFile ${varOutPath}unsorted.txt
cat ${varOutPath}unsorted.txt | sort -V | uniq > $varOutPath$varTempFile
rm ${varOutPath}unsorted.txt

# Create summary file
if [ "$varDoSummary" = "Y" ] && [ -e "$varOutPath$varTempFile" ]; then
  echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt
  printf "%-18s %-14s %-52.52s %-2s \n" "| HOST " "| OPEN PORT " "| PROTOCOL - SERVICE" " |" >> ${varOutPath}summary.txt
  varLastHost=""
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineTCPUDP=""
    varLineProto=""
    varLineSvc=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    varLineTCPUDP=$(echo $varLine | awk -F ',' '{print $3}')
    varLineProto=$(echo $varLine | awk -F ',' '{print $4}')
    varLineSvc=$(echo $varLine | awk -F ',' '{print $5}')
    if [ "$varLineHost" != "$varLastHost" ]; then echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt; fi
    if [ "$varLineSvc" = "" ]; then
      varLineSvc=""
    else
      varLineSvc="- $varLineSvc"
    fi
    printf "%-18s %-14s %-52.52s %-2s \n" "| $varLineHost " "| $varLinePort / $varLineTCPUDP " "| $varLineProto $varLineSvc" " |" >> ${varOutPath}summary.txt
    varLastHost="$varLineHost"
  done < $varOutPath$varTempFile
  echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt
fi

# Create split hosts files for each protocol
if [ "$varDoSplit" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineTCPUDP=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    varLineTCPUDP=$(echo $varLine | awk -F ',' '{print $3}')
    echo $varLineHost >> $varOutPath${varLinePort}-${varLineTCPUDP}-hosts.txt
  done < $varOutPath$varTempFile
fi

# Rename hosts files for common protocols
if [ "$varRenameSplit" = "Y" ]; then
  if [ -f "${varOutPath}21-tcp-hosts.txt" ]; then mv ${varOutPath}21-tcp-hosts.txt ${varOutPath}ftp-hosts.txt; fi
  if [ -f "${varOutPath}22-tcp-hosts.txt" ]; then mv ${varOutPath}22-tcp-hosts.txt ${varOutPath}ssh-hosts.txt; fi
  if [ -f "${varOutPath}23-tcp-hosts.txt" ]; then mv ${varOutPath}23-tcp-hosts.txt ${varOutPath}telnet-hosts.txt; fi
  if [ -f "${varOutPath}25-tcp-hosts.txt" ]; then mv ${varOutPath}25-tcp-hosts.txt ${varOutPath}smtp-hosts.txt; fi
  if [ -f "${varOutPath}53-tcp-hosts.txt" ]; then mv ${varOutPath}53-tcp-hosts.txt ${varOutPath}dns-tcp-hosts.txt; fi
  if [ -f "${varOutPath}53-udp-hosts.txt" ]; then mv ${varOutPath}53-udp-hosts.txt ${varOutPath}dns-udp-hosts.txt; fi
  if [ -f "${varOutPath}69-udp-hosts.txt" ]; then mv ${varOutPath}69-udp-hosts.txt ${varOutPath}tftp-hosts.txt; fi
  if [ -f "${varOutPath}80-tcp-hosts.txt" ]; then mv ${varOutPath}80-tcp-hosts.txt ${varOutPath}http-hosts.txt; fi
  if [ -f "${varOutPath}110-tcp-hosts.txt" ]; then mv ${varOutPath}110-tcp-hosts.txt ${varOutPath}pop3-hosts.txt; fi
  if [ -f "${varOutPath}123-udp-hosts.txt" ]; then mv ${varOutPath}123-udp-hosts.txt ${varOutPath}ntp-hosts.txt; fi
  if [ -f "${varOutPath}143-tcp-hosts.txt" ]; then mv ${varOutPath}143-tcp-hosts.txt ${varOutPath}imap-hosts.txt; fi
  if [ -f "${varOutPath}161-udp-hosts.txt" ]; then mv ${varOutPath}161-udp-hosts.txt ${varOutPath}snmp-hosts.txt; fi
  if [ -f "${varOutPath}162-udp-hosts.txt" ]; then mv ${varOutPath}162-udp-hosts.txt ${varOutPath}snmptrap-hosts.txt; fi
  if [ -f "${varOutPath}179-tcp-hosts.txt" ]; then mv ${varOutPath}179-tcp-hosts.txt ${varOutPath}bgp-hosts.txt; fi
  if [ -f "${varOutPath}389-tcp-hosts.txt" ]; then mv ${varOutPath}389-tcp-hosts.txt ${varOutPath}ldap-hosts.txt; fi
  if [ -f "${varOutPath}443-tcp-hosts.txt" ]; then mv ${varOutPath}443-tcp-hosts.txt ${varOutPath}https-hosts.txt; fi
  if [ -f "${varOutPath}445-tcp-hosts.txt" ]; then mv ${varOutPath}445-tcp-hosts.txt ${varOutPath}smb-hosts.txt; fi
  if [ -f "${varOutPath}465-tcp-hosts.txt" ]; then mv ${varOutPath}465-tcp-hosts.txt ${varOutPath}smtps-hosts.txt; fi
  if [ -f "${varOutPath}500-udp-hosts.txt" ]; then mv ${varOutPath}500-udp-hosts.txt ${varOutPath}ike-hosts.txt; fi
  if [ -f "${varOutPath}513-tcp-hosts.txt" ]; then mv ${varOutPath}513-tcp-hosts.txt ${varOutPath}rlogin-hosts.txt; fi
  if [ -f "${varOutPath}514-tcp-hosts.txt" ]; then mv ${varOutPath}514-tcp-hosts.txt ${varOutPath}remoteshell-hosts.txt; fi
  if [ -f "${varOutPath}636-tcp-hosts.txt" ]; then mv ${varOutPath}636-tcp-hosts.txt ${varOutPath}ldaps-hosts.txt; fi
  if [ -f "${varOutPath}873-tcp-hosts.txt" ]; then mv ${varOutPath}873-tcp-hosts.txt ${varOutPath}rsync-hosts.txt; fi
  if [ -f "${varOutPath}989-tcp-hosts.txt" ]; then mv ${varOutPath}989-tcp-hosts.txt ${varOutPath}ftps-data-hosts.txt; fi
  if [ -f "${varOutPath}990-tcp-hosts.txt" ]; then mv ${varOutPath}990-tcp-hosts.txt ${varOutPath}ftps-hosts.txt; fi
  if [ -f "${varOutPath}992-tcp-hosts.txt" ]; then mv ${varOutPath}992-tcp-hosts.txt ${varOutPath}telnets-hosts.txt; fi
  if [ -f "${varOutPath}993-tcp-hosts.txt" ]; then mv ${varOutPath}993-tcp-hosts.txt ${varOutPath}imaps-hosts.txt; fi
  if [ -f "${varOutPath}995-tcp-hosts.txt" ]; then mv ${varOutPath}995-tcp-hosts.txt ${varOutPath}pop3s-hosts.txt; fi
  if [ -f "${varOutPath}1433-tcp-hosts.txt" ]; then mv ${varOutPath}1433-tcp-hosts.txt ${varOutPath}mssql-hosts.txt; fi
  if [ -f "${varOutPath}3389-tcp-hosts.txt" ]; then mv ${varOutPath}3389-tcp-hosts.txt ${varOutPath}rdp-hosts.txt; fi
  if [ -f "${varOutPath}5432-tcp-hosts.txt" ]; then mv ${varOutPath}5432-tcp-hosts.txt ${varOutPath}postgresql-hosts.txt; fi
  if [ -f "${varOutPath}8080-tcp-hosts.txt" ]; then mv ${varOutPath}8080-tcp-hosts.txt ${varOutPath}http-8080-hosts.txt; fi
  if [ -f "${varOutPath}8443-tcp-hosts.txt" ]; then mv ${varOutPath}8443-tcp-hosts.txt ${varOutPath}http-8443-hosts.txt; fi
fi

# Create web-urls.txt
if [ "$varDoWebUrl" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    if [ "$varLinePort" = "80" ]; then echo "http://${varLineHost}/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "443" ]; then echo "https://${varLineHost}/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "8080" ]; then echo "http://${varLineHost}:8080/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "8443" ]; then echo "https://${varLineHost}:8443/" >> ${varOutPath}web-urls.txt; fi
  done < $varOutPath$varTempFile
fi

# Create smb-urls.txt
if [ "$varDoSmbUrl" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    if [ "$varLinePort" = "445" ]; then echo "smb://${varLineHost}/" >> ${varOutPath}smb-urls.txt; fi
  done < $varOutPath$varTempFile
fi

rm $varOutPath$varTempFile

# grep UDP for ipmi hosts

if [ -f "$udpgreppable" ]; then
  cat ${udpgreppable} | grep "623/open/udp" | cut -d ' ' -f 2 > ./scans/ipmi_hosts.txt
fi


echo -e "[${BLUE}*${RESET}] Parsing complete!\n"

sleep 2



# SMB Time!

echo -e "[${BLUE}*${RESET}] Starting SMB Enumeration!\n"

# make directory structure
sleep 2

smbdir=./smb
echo -e "[${BLUE}*${RESET}] Creating 'smb' directory..."

if [ -d "$smbdir" ];
then
    echo -e "[${RED}!${RESET}] Directory 'smb' already exists. Skipping.\n"
else
  mkdir ./smb
  echo -e "[${BLUE}*${RESET}] Directory 'smb' created successfully. Continuing.\n"
fi

sleep 2

# file check and crackmapexec

echo -e "[${BLUE}*${RESET}] Running Crackmapexec...\n"
smbhosts=${varOutPath}smb-hosts.txt
if [ -f "$smbhosts" ]; then
    crackmapexec smb ${varOutPath}smb-hosts.txt | tee ./smb/cme.out
    cat cme.out | grep "signing:False" > ./smb/no_signing.out
    cat cme.out | grep "SMBv1:True" > ./smb/smbv1.out
    cat ./smb/no_signing.out | cut -d ' ' -f 10 > ./smb/no_signing_hosts.txt
    cat ./smb/smbv1.out | cut -d ' ' -f 10 > ./smb/smbv1_hosts.txt
    echo -e "\n[${BLUE}*${RESET}] Crackmapexec completed. Check smb directory for results.\n"
else 
    echo -e "[${RED}!${RESET}] $smbhosts does not exist. Skipping SMB enumeration.\n"
fi


