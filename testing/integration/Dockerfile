FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y snmpd python3 && \
    rm -rf /var/lib/apt/lists/*

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY mib.py /usr/local/bin/mib.py
RUN chmod +x /usr/local/bin/mib.py && \
    echo "mibdirs:/usr/share/snmp/mibs" >> /etc/snmp/snmp.conf && \
    echo "mibs:ALL" >> /etc/snmp/snmp.conf

EXPOSE 161/udp

CMD ["snmpd", "-f", "-Lo", "-Ducd-snmp/pass,util_funcs", "-C", "-c", "/etc/snmp/snmpd.conf"]