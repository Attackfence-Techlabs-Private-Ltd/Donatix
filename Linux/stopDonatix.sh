#!/bin/bash

#==========================================================================#
# Stops the Donatix services and writes the report on everything they     #
# captured to the Downloads folder of the user who ran sudo.               #
#==========================================================================#
srcDir="/opt/attackfence/Donatix/Linux/scripts/src"
services="atf_tshark_query atf_dga_evaluation atf_ti_verdict atf_dns_data_insertion atf_beaconing_hosts"

# Ensure the user executing this script is root #
if [ $(id --user) -ne 0 ]; then
  echo "AttackFence>> Error: this script must be run as root (sudo). Exiting now ..."
  exit 1
fi

# disabled as well as stopped, so they do not come back on the next boot
for service in ${services}; do
    systemctl disable --now ${service}.service &> /dev/null
done
echo "AttackFence>> Donatix stopped. Run sudo bash startDonatix.sh to restart it."

user="${SUDO_USER:-root}"
downloads="$(getent passwd "${user}" | cut -d: -f6)/Downloads"
report="${downloads}/Donatix_Report_$(date +%F).pdf"

# Generated as attackfence: as root it would leave root-owned database files the services cannot write
tmp=$(mktemp -d)
chown attackfence "${tmp}"
echo "AttackFence>> Generating the report, this can take a minute..."
# sudo leaves HOME=/root, which matplotlib cannot write its settings and font cache to as attackfence
if ! runuser -u attackfence -- env HOME="$(getent passwd attackfence | cut -d: -f6)" \
        python3 "${srcDir}/generateReport.py" -o "${tmp}/report.pdf"; then
    rm -rf "${tmp}"
    echo "AttackFence>> Error: the report could not be generated, see the message above."
    exit 1
fi
runuser -u "${user}" -- mkdir -p "${downloads}"
install -m 644 -o "${user}" -g "$(id -gn "${user}")" "${tmp}/report.pdf" "${report}"
rm -rf "${tmp}"
echo "AttackFence>> Report written to ${report}"
# A server has no desktop to open it on: it is copied off from the user's own machine
echo "AttackFence>> To download it, run this on your own computer:"
echo "    scp ${user}@$(hostname -I | awk '{print $1}'):${report} ."
