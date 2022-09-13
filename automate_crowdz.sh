#!/bin/bash
#Author: Jignesh Popat <pjignesh@trellissoft.com>
#Automation Script for SQLMap scan.
#This script should be in same directry where, sqlmap.py resides

###############################################################################################
# Function to execute SQLMap scan for each target URL provided in target file.
# SQLMap will run with default technique and medium risk and levels.
# Successful injection (URL) will be reported on console &  written to HTML report file.
###############################################################################################

runSqlMap(){
local target_url=$1
local log_file=$2
python sqlmap.py --batch -u $target_url -v 3 --cookie=$AUTH_COOKIE --delay=2 --timeout=15 --retries=2 --threads=1 --level=3 --risk=3 --random-agent --ignore-proxy --hex --tamper=between --dbms=mssql --os=Windows --is-dba  --current-user --current-db 1> $result_Folder/$log_file &

local cpid=$!
while [ "$(ps a | awk '{print $1}' | grep $cpid)" ]; do
for a in \\ \| \/ -; do
echo -n -e "Scanning: $target_url \t [$a]\n"; sleep 0.2 ;
echo -n -e \\r
done
done

cat $result_Folder/$log_file | grep 'following injection point' &> /dev/null

if [ $? -eq 0 ]; then
	echo ""
	echo "<tr><td>$target_url  <div class="toggleDetails" onclick=\"toggle(this,'details$log_file')\">Click to Show Details</div><a class=\"toggleDetails\" href=\"$log_file\" target=\"_new\">Log File</a><div class=\"details\" id=\"details$log_file\" style=\"display:none;\">" >> $resultFile
	sed -n '/---/,/---/p' $result_Folder/$log_file >> $resultFile
	echo "</div></td><td class=\"fail\">Injection point found</td></tr>" >> $resultFile
else
	echo ""
	echo "<tr><td>$target_url </td><td class=\"success\">Injection point not found</td>" >> $resultFile
fi
}

##################################################################################################
# Converts supplied URL to encoded version to minimize the error in HTTP header.
# Get the target Application URL and login to extract JSESSIONID from HTTP header
# Upon sucessful authentication starts the function runSqlMAP() for each URL read from target file
###################################################################################################

URL=$1
TARGETS=$2
DEST=https://$URL/
ENCODED_DEST=`echo $DEST | perl -p -e 's/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg' | sed 's/%2E/./g' | sed 's/%0A//g'`
USERNAME=""
PASSWORD=""

#Check if command line arugments available
if [ "$#" -ne 2 ]; then
	echo -e "\nUsage: $0 <Hostname> <Filename>"
	echo -e "\nHostname: Target hostname to scan"
	echo -e "Filename: File containing list of URL to scan"
	echo -e "Make sure $0 & SQLMap resides in same directory."
	exit 0
fi

#Get authentication details for web application
echo -ne "Login to $URL \n"
while [ "$USERNAME" == "" ]; do
	read -p "Enter Username: " USERNAME
done
read -s -p "Enter Password: " PASSWORD
AUTH_URL="http://$URL/"

#Temporary files used by curl to store cookies and http headers
COOKIE_JAR=.cookieJar
HEADER_DUMP_DEST=.headers
ENCODED_USERNAME=`echo $USERNAME | perl -p -e 's/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg' | sed 's/%2E/./g' | sed 's/%0A//g'` \
ENCODED_PASSWORD=`echo $PASSWORD | perl -p -e 's/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg' | sed 's/%2E/./g' | sed 's/%0A//g'`

rm -rf $COOKIE_JAR 2> /dev/null
rm -rf $HEADER_DUMP_DEST 2> /dev/null
clear

#Verify IP Address/hostname is fine or not
echo -ne "[+] Verifying connection to $URL..."
curl -s -b $COOKIE_JAR -c $COOKIE_JAR -e $AUTH_URL $AUTH_URL > $HEADER_DUMP_DEST

if [ -s $HEADER_DUMP_DEST ]; then
	echo -e "\t\tDone!"  
else
	echo -e "\t\t\t\tFailed!"
	echo -e "[Exiting..] Verify hostname URL and check if host is up and then retry!"
	exit 0
fi

#Login with API to authenticate
echo -ne "[+] Authenticating..."
session="sessionid=$(cat $HEADER_DUMP_DEST | grep "sessionid" | awk '{printf $8}' | sed 's/^.*value=\s*//' | tr -d '"')"
echo "session is: $session"
curl --silent -k --data "$session&Email=$ENCODED_USERNAME&password=$ENCODED_PASSWORD" -i -b $COOKIE_JAR -c $COOKIE_JAR $AUTH_URL > $HEADER_DUMP_DEST
SESSION_ID=`cat $HEADER_DUMP_DEST | grep sessionid | awk {'print $2'}`
if [[ "$SESSION_ID" == "" ]]; then
	echo -e "\t\t\t\tFailed!"
	echo "Cant authenticate with $URL, Kindly check Username/Password and retry"
	exit 0
else
	AUTH_COOKIE="$SESSION_ID"
	echo -ne "\tAuth Cookie: $AUTH_COOKIE" 
	echo -e "\t\tDone!"
fi

#Initialize blank HTML report file
SITE_VERSION=""
result_Folder="$SITE_VERSION"SQLMap_Report_$(date +%Y_%m_%d__%H_%M_%S)
mkdir $result_Folder
resultFile=$result_Folder/"$result_Folder".html
echo "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\"> <head>" >> $resultFile
echo "<style type=\"text/css\"  > body{line-height:1.6em}h1,h2{color:#666;font-size:18px;line-height:1.6em;padding:10px;text-align:center}h2{font-size:16px;padding:0 5px 5px}#myStyle{font-family:\"Lucida Sans Unicode\",\"Lucida Grande\",Sans-Serif;font-size:12px;width:75%;margin:0 auto;border:1px solid #6cf;text-align:center;border-collapse:collapse}#myStyle th{padding:20px;font-weight:400;font-size:13px;color:#039;text-transform:uppercase;text-align:center;border:1px solid #0865C2}#myStyle td{padding:10px 20px;color:#669;border:1px solid #6CF}.success{font-family:\"Lucida Sans Unicode\",\"Lucida Grande\",Sans-Serif;text-align:center;color:green!important}.fail{font-family:\"Lucida Sans Unicode\",\"Lucida Grande\",Sans-Serif;text-align:center;color:red!important}#myStyle td .toggleDetails{margin:0 5px;cursor:pointer;display:block;float:right;clear:none;color:blue;}#myStyle td .details{white-space:pre-line;text-align:left;border:1px solid;margin:10px;display:none;padding:10px;clear: both;}</style>" >> $resultFile
echo "<script type=\"text/javascript\">function toggle(e,t){var n=document.getElementById(t);if(n){var r=n.style.display;if(r==\"none\"){n.style.display=\"block\";e.innerHTML=\"Click to Hide Details\"}else{n.style.display=\"none\";e.innerHTML=\"Click to Show Details\"}}}</script>" >> $resultFile
echo "<title>SQLMap HTML Report</title></head><body><h1>Report of SQLMap scan performed on URL(s) present in $TARGETS</h1><h2>Test started at: $(date) </h2><table id=\"myStyle\"><thead><tr><th scope=\"col\">Test URL</th><th scope=\"col\">Test Result</th></tr></thead><tbody>" >> $resultFile

#Cleanup old log files if any
echo -ne "[+] Cleaning old scan logs..."
python sqlmap.py --purge-output -v 2 2>&1 1> /dev/null
echo -e "\t\tDone!"

#Call runSqlMap function() for all URLs present in target.txt file.
echo "================================== Scan started with list of URL(s) from $TARGETS =================================="
echo "This will take several minutes or sometimes hours to complete depnding on scan technique and number of URL to Scan"
echo -e "_____________________________________________________________________________________________________________________\n"

while read line; do
	file_name=$(echo $line | grep -oP '(?<=://).*(?=\?)' | tr .:/- _).log
	runSqlMap $line $file_name
done < $TARGETS

#Upon completion of scan process, finalize the report file.
echo "================================== Scan Completed for list of URL(s) from $TARGETS =================================="
echo "<h2>Test ended at: $(date) </h2></tbody></table>" >> $resultFile
echo "Report generated and saved at $resultFile"

#Logout from web application after generating a report
echo -ne "[+] Logging out..."
	DJANGO_CSRF_TOKEN=""
	USERNAME=""
	PASSWORD=""
	SESSION_ID=""
	AUTH_COOKIE=""
	rm -rf $COOKIE_JAR 2> /dev/null
	rm -rf $HEADER_DUMP_DEST 2> /dev/null
echo -e "\t\tDone!"
