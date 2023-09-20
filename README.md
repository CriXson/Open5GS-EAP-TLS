## Open5GS with EAP-TLS

For my master's thesis, I successfully integrated the EAP-TLS authentication mechanism into the Open5GS core.

## Getting Started

To set up this on your machine, please refer to the [Build from Source Manual](https://open5gs.org/open5gs/docs/guide/02-building-open5gs-from-sources/) provided by Open5GS. Instead of using the open5GS repository, utilize the one specified here. The core in this repository is configured for local deployment following the instructions outlined in the manual.

## Test with Client

To perform EAP-TLS testing on the core, utilize the [N3IWF](https://github.com/CriXson/N3IWF-for-Open5GS) and the [UE](https://github.com/CriXson/non3GPP-access) repositories I configured for this use case. EAP-TLS was only tested via non-3GPP-access.

## Identifiers for the UE used

Despite the communication being conducted through non-3GPP access, the IMSI format is used instead of the NAI format, as NAI was not supported by Open5GS at that time. The file "imsis" contains the list of configured IMSIs, and while you can add new ones to the database, it's important to note that EAP-TLS authentication is hardcoded to specific IMSIs and cannot be used with newly added ones at this time.


## Capture Traffic

If you want to see the packets exchanged, use Wireshark and set ngap as the filter.

## System specification used

Ubuntu 20.04.5 LTS  
CPU: 2  
Memory: 6.00 GB 

- Open5GS Open Source files are made available under the terms of the GNU Affero General Public License ([GNU AGPL v3.0](https://www.gnu.org/licenses/agpl-3.0.html)).
- [Commercial licenses](https://open5gs.org/open5gs/support/) are also available from [NeoPlane](https://neoplane.io/)
