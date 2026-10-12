#!/bin/bash

#==========================================================================#
# Removes what installPackages.sh set up: the services, the scripts under  #
# /opt/attackfence and the attackfence user.                               #
#==========================================================================#
installDir="/opt/attackfence"
services="atf_tshark_query atf_dga_evaluation atf_ti_verdict atf_dns_data_insertion atf_beaconing_hosts"

# Ensure the user executing this script is root #
if [ $(id --user) -ne 0 ]; then
  echo "AttackFence>> Error: this script must be run as root. Exiting now ..."
  exit 1
fi

read -p "AttackFence>> Delete the captured DNS data as well? [y/N] " deleteData

# stop and remove services
for service in ${services}; do
    systemctl disable --now ${service}.service &> /dev/null
    rm -f /etc/systemd/system/${service}.service
done
systemctl daemon-reload
echo "AttackFence>> Services removed"

# remove the scripts, keep the database unless asked to delete it
if [[ "${deleteData}" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    rm -rf "${installDir}"
    echo "AttackFence>> ${installDir} removed, including the captured data"
else
    find "${installDir}" -type f ! -name 'networkdata.db*' -delete 2> /dev/null
    find "${installDir}" -type d -empty -delete 2> /dev/null
    echo "AttackFence>> Scripts removed, captured data kept in ${installDir}/Donatix/Linux/scripts/src"
fi

# remove the service user
if id attackfence &> /dev/null; then
    deluser --remove-home attackfence &> /dev/null
    echo "AttackFence>> User attackfence removed"
fi

echo "AttackFence>> Attackfence Donatix Uninstalled"
echo "AttackFence>> tshark, sqlite3, expect, pip3 and the python3 aiohttp and matplotlib packages were left installed"
