# Wazuh data extraction templates for pfSense

Wazuh is an open-source security platform designed for threat detection, visibility, and compliance across multiple environments. It collects and analyzes log data from systems, applications, and network devices, using rules and decoders to identify potential security threats and vulnerabilities. Wazuh offers real-time security monitoring, intrusion detection, and response capabilities.

**Prerequitits**

For this guide to work we need to set the Syslog format in psSense to `syslog (RFC 5424, with RFC 3339 microsecond-precision timestamps)`.

Furthermore we need to add this section to the `/var/ossec/etc/ossec.conf` on the Wazuh manager host:

```xml
<!-- Syslog for Firewall -->
<remote>
    <connection>syslog</connection>
    <port>5141</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.2.1/24</allowed-ips>
    <local_ip>192.168.2.2</local_ip>
</remote>
```

Adjust the IPs and the port as needed for your environment!

## Decoder

To ingest data, we need to decode the messages. Thatfor we need to add this into `/var/ossec/etc/decoders/custom_decoders.xml`:

```xml
<decoder name="pfsense-filterlog-ipv4">
  <prematch type="pcre2">filterlog.*,in,4,</prematch>
  <regex type="pcre2">\d+\s+(\d+-\d+-\d+T\d+:\d+:\d+.\d+\+\d+:\d+)\s+(pfSense\S+)\s+filterlog\s+\d+\s+-\s+-\s+\d+,,,\d+,(\w+),\w+,(\w+),(\w+),\d+,\w+,,\d+,\d+,\d+,\w+,\d+,(\w+),\d+,(\d+.\d+.\d+.\d+),(\d+.\d+.\d+.\d+),(\d+),(\d+),\d+</regex>
  <order>date,host,interface,action,direction,protocol,srcip,dstip,srcport,dstport</order>
</decoder>

<decoder name="pfsense-filterlog-ipv6">
  <prematch type="pcre2">filterlog.*,in,6,</prematch>
  <regex type="pcre2">\d+\s+(\d+-\d+-\d+T\d+:\d+:\d+.\d+\+\d+:\d+)\s+(pfSense\S+)\s+filterlog\s+\d+\s+-\s+-\s+\d+,,,\d+,(\w+),\w+,(\w+),(\w+),\d+,\w+,\w+,\d+,(\w+),\d+,\d+,([a-f\d]+:.*:[a-f\d]+),([a-f\d]+:.*:[a-f\d]+),(\d+),(\d+),\d+</regex>
  <order>date,host,interface,action,direction,protocol,srcip,dstip,srcport,dstport</order>
</decoder>

<decoder name="pfsense-suricata">
  <prematch>suricata</prematch>
  <regex type="pcre2">\d+\s+(\d+-\d+-\d+T\d+:\d+:\d+.\d+\+\d+:\d+)\s+(pfSense\S+)\s+suricata\s+\d+\s+-\s+-\s+\[\d+:\d+:\d+\]\s+(.+)\s+{(\S+)}\s+(\S+):(\d+)\s+->\s+(\S+):(\d+)</regex>
  <order>date,host,message,protocol,srcip,srcport,dstip,dstport</order>
</decoder>
```

Some Suriacata alerts where alredy picked up, will look into that later and update the file...

Other events like failed logins where picked up and propperly handled as an alert out of the box. So I add here only what was missing.

## Rules

Wazuh stores by default only relevant messages - after decoding the messages we need to create rules to store and alert on all blocked connections. Thatfor we need to add the following code to `var/ossec/etc/rules/local_rules.xml`:

```xml
<!-- Rule to alert on blocked incoming connections -->
<group name="local,remote,syslog,firewall">
   <rule id="100003" level="6">
      <decoded_as>pfsense-filterlog-ipv4</decoded_as>
      <match>,block,</match>
      <description>Blocked incoming connection</description>
      <group>firewall,</group>
   </rule>
</group>
<group name="local,remote,syslog,firewall">
   <rule id="100004" level="6">
      <decoded_as>pfsense-filterlog-ipv6</decoded_as>
      <match>,block,</match>
      <description>Blocked incoming connection</description>
      <group>firewall,</group>
   </rule>
</group>
```

After that, we can restart the wazuh manager with `systemctl restart wazuh-manager`