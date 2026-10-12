#!/bin/bash

#==========================================================================#
# Starts the Donatix services again after stopDonatix.sh stopped them.     #
# Captured data is kept, so the next report covers every run.              #
#==========================================================================#
services="atf_tshark_query atf_dga_evaluation atf_ti_verdict atf_dns_data_insertion atf_beaconing_hosts"

# Ensure the user executing this script is root #
if [ $(id --user) -ne 0 ]; then
  echo "AttackFence>> Error: this script must be run as root (sudo). Exiting now ..."
  exit 1
fi

if ! systemctl cat atf_tshark_query.service &> /dev/null; then
  echo "AttackFence>> Error: Donatix is not installed. Run sudo bash installPackages.sh first."
  exit 1
fi

for service in ${services}; do
    systemctl enable --now ${service}.service &> /dev/null
done
echo "AttackFence>> Donatix started. Run sudo bash stopDonatix.sh to stop it and get the report."
