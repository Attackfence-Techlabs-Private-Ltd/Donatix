#!/bin/bash

#==========================================================================#
# Set Script Variables                                                     #
#==========================================================================#
installerLog="/tmp/donaticsLinuxInstallation.log"
GREEN='\033[0;92m'      #Green
NOCOLOR='\033[0;37m'         #White
ORANGE='\033[0;33'      #Orange
CurrentDir=$(pwd)

echo -e "=========================================" | tee -a ${installerLog}
echo -e "      Installing AttackFence Sensor      " | tee -a ${installerLog}
echo -e "=========================================" | tee -a ${installerLog}
echo -e "AttackFence>> Logging post install output and errors to: ${installerLog}"

# Clear log and timestamp the beginning
cat /dev/null > ${installerLog}
echo -e "=====================================================================" >> ${installerLog}
echo -e "            Log Started: $(date)                                     " >> ${installerLog}
echo -e "=====================================================================" >> ${installerLog}

# Check if tshark is already installed
if command -v tshark &> /dev/null; then
    echo -e "AttackFence>> tshark is already installed. Skipping installation." | tee -a ${installerLog}
else
    # Install tshark
    apt install tshark -y >> ${installerLog} 2>&1

    if [ $? -ne 0 ]; then
        echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${RED}FAILED${NOCOLOR}]" | tee -a ${installerLog}
        exit 1
    else
        echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${GREEN}SUCCESS${NOCOLOR}]" | tee -a ${installerLog}
    fi
fi

# Check if pip3 is already installed
if command -v pip3 &> /dev/null; then
    echo -e "AttackFence>> pip3 is already installed. Skipping installation." | tee -a ${installerLog}
else
    apt install python3-pip -y >> ${installerLog} 2>&1
fi

# Check if sqlite3 is already installed
if command -v sqlite3 &> /dev/null; then
    echo -e "AttackFence>> sqlite3 is already installed. Skipping installation." | tee -a ${installerLog}
else
    apt install sqlite3 -y >> ${installerLog} 2>&1
fi
# Check if expect is already installed
if command -v expect &> /dev/null; then
    echo -e "AttackFence>> expect is already installed. Skipping installation." | tee -a ${installerLog}
else
    apt install expect -y >> ${installerLog} 2>&1
fi
#==========================================================================#
# Pre-installation checks                                                  #
#==========================================================================#
# Ensure the user exexuting this installer is root #
if [ $(id --user) -ne 0 ]; then
  echo "AttackFence>> Error: this script must be run as root. Exiting now ..." >> ${installerLog}
  exit 1
fi
echo -e "AttackFence>> Installing Sensor Dependencies" | tee -a >> ${installerLog}

while :;do for s in / - \\ \|; do printf "\r\e[0KAttackFence>> Installing Sensor Dependencies Please wait ....$s";sleep 1;done;done &

if [ $? -ne 0 ]; then
    echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${RED}FAILED${NOCOLOR}]" | tee -a ${installerLog}
    exit 1
else
    echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${GREEN}SUCCESS${NOCOLOR}]" | tee -a ${installerLog}
fi

pip3 install aiohttp
# adding user.
sudo adduser attackfence
mkdir -p /opt/attackfence/NDR/tsharkQueryData/ >> ${installerLog} 2>&1
chown -R attackfence:attackfence /opt/attackfence
mv $CurrentDir/scripts/services/* /etc/systemd/system/
mv $CurrentDir/scripts/src/* /opt/attackfence/NDR/tsharkQueryData/
cd /etc/systemd/system/

# enable services
systemctl enable atf_tshark_query.service
systemctl enable atf_dga_evaluation.service
systemctl enable atf_ti_verdict.service
systemctl enable atf_dns_data_insertion.service
systemctl enable atf_beaconing_hosts.service

# start services
systemctl start atf_tshark_query.service
systemctl start atf_dga_evaluation.service
systemctl start atf_ti_verdict.service
systemctl start atf_dns_data_insertion.service
systemctl start atf_beaconing_hosts.service

kill $!; trap 'kill $!' SIGTERM
retval=$?
if [ $retval -ne 0 ]; then
    echo -e "\r\e[0KAttackFence>> Sensor Configurations Updation\t[${RED}FAILED${NOCOLOR}]" | tee -a ${installerLog}
    exit 1
else
    echo -e "\r\e[0KAttackFence>> Sensor Configurations Updation\t[${GREEN}SUCCESS${NOCOLOR}]" | tee -a ${installerLog}
fi
echo -e "AttackFence>> Attackfence Sensor Installed Successfully" | tee -a ${installerLog}
