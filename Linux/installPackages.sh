#!/bin/bash

#==========================================================================#
# Set Script Variables                                                     #
#==========================================================================#
installerLog="/tmp/donaticsLinuxInstallation.log"
GREEN='\033[0;92m'      #Green
NOCOLOR='\033[0;37m'         #White
ORANGE='\033[0;33m'     #Orange
RED='\033[0;91m'        #Red
CurrentDir=$(pwd)

# Ensure the user executing this installer is root, before anything is installed #
if [ $(id --user) -ne 0 ]; then
  echo "AttackFence>> Error: this script must be run as root. Exiting now ..."
  exit 1
fi

echo -e "=========================================" | tee -a ${installerLog}
echo -e "      Installing AttackFence Sensor      " | tee -a ${installerLog}
echo -e "=========================================" | tee -a ${installerLog}
echo -e "AttackFence>> Logging post install output and errors to: ${installerLog}"

# Clear log and timestamp the beginning
cat /dev/null > ${installerLog}
echo -e "=====================================================================" >> ${installerLog}
echo -e "            Log Started: $(date)                                     " >> ${installerLog}
echo -e "=====================================================================" >> ${installerLog}

# Refresh the package lists, with a stale list apt fails with "Unable to locate package"
apt update >> ${installerLog} 2>&1

# Let members of the wireshark group capture packets, the capture service does not run as root
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# Check if tshark is already installed
if command -v tshark &> /dev/null; then
    echo -e "AttackFence>> tshark is already installed. Skipping installation." | tee -a ${installerLog}
else
    # Install tshark
    DEBIAN_FRONTEND=noninteractive apt install tshark -y >> ${installerLog} 2>&1

    if [ $? -ne 0 ]; then
        echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${RED}FAILED${NOCOLOR}]" | tee -a ${installerLog}
        exit 1
    else
        echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${GREEN}SUCCESS${NOCOLOR}]" | tee -a ${installerLog}
    fi
fi
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common >> ${installerLog} 2>&1

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
echo -e "AttackFence>> Installing Sensor Dependencies" | tee -a >> ${installerLog}

while :;do for s in / - \\ \|; do printf "\r\e[0KAttackFence>> Installing Sensor Dependencies Please wait ....$s";sleep 1;done;done &

if [ $? -ne 0 ]; then
    echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${RED}FAILED${NOCOLOR}]" | tee -a ${installerLog}
    exit 1
else
    echo -e "\r\e[0KAttackFence>> Sensor Dependencies Installation\t[${GREEN}SUCCESS${NOCOLOR}]" | tee -a ${installerLog}
fi

# Check if the python packages are already installed
# pip3 refuses to install system wide on recent Debian/Ubuntu, use the distribution packages
for package in aiohttp matplotlib; do
    if python3 -c "import ${package}" &> /dev/null; then
        echo -e "AttackFence>> python3-${package} is already installed. Skipping installation." | tee -a ${installerLog}
    else
        apt install python3-${package} -y >> ${installerLog} 2>&1
        if ! python3 -c "import ${package}" &> /dev/null; then
            echo -e "\r\e[0KAttackFence>> python3-${package} Installation\t[${RED}FAILED${NOCOLOR}] see ${installerLog}" | tee -a ${installerLog}
        fi
    fi
done
# adding user.
id attackfence &> /dev/null || adduser --disabled-password --gecos "" attackfence >> ${installerLog} 2>&1
usermod -aG wireshark attackfence
mkdir -p /opt/attackfence/Donatix/Linux/scripts/src/ >> ${installerLog} 2>&1
# copy, not move: a move empties the checkout and a second run has nothing to install
cp -f $CurrentDir/scripts/services/* /etc/systemd/system/
# Everything except the database, which holds the captured traffic. Copying it would
# throw away the sensor's data on every reinstall; it is only seeded when absent.
for f in $CurrentDir/scripts/src/*; do
    case $(basename "$f") in
        networkdata.db|networkdata.db-wal|networkdata.db-shm|__pycache__) continue ;;
    esac
    # -r so the brand/ directory (logo and the bundled Inter faces) comes across too
    cp -rf "$f" /opt/attackfence/Donatix/Linux/scripts/src/
done
if [ ! -f /opt/attackfence/Donatix/Linux/scripts/src/networkdata.db ] \
   && [ -f $CurrentDir/scripts/src/networkdata.db ]; then
    cp -f $CurrentDir/scripts/src/networkdata.db /opt/attackfence/Donatix/Linux/scripts/src/
fi
chmod +x /opt/attackfence/Donatix/Linux/scripts/src/{tsharkQuery.sh,noname.py,dga_evaluate}
# the services run as attackfence and must be able to write the database
chown -R attackfence:attackfence /opt/attackfence
# holds the threat-intel licence key
chmod 600 /opt/attackfence/Donatix/Linux/scripts/src/ti_config.json
cd /etc/systemd/system/

# pick up unit files that changed since the last install
systemctl daemon-reload

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
