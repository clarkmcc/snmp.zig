FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y snmpd python3 supervisor && \
    rm -rf /var/lib/apt/lists/*

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY snmpd-v3.conf /etc/snmp/snmpd-v3.conf
COPY mib.py /usr/local/bin/mib.py
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +x /usr/local/bin/mib.py && \
    echo "mibdirs:/usr/share/snmp/mibs" >> /etc/snmp/snmp.conf && \
    echo "mibs:ALL" >> /etc/snmp/snmp.conf

EXPOSE 161/udp 162/udp

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]