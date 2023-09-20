## Open5GS with EAP-TLS

For my master thesis I implemented the additional authentication mechanism EAP-TLS in the Open5GS core.

## Getting Started

To be able to run this on your machine follow the [Build from Source Manual](https://open5gs.org/open5gs/docs/guide/02-building-open5gs-from-sources/) from Open5GS. 
Just use this repository instead of the open5GS one.
The core is configured for a local deployment as described in the manual.

## Test with Client

If you want to test the core with EAP-TLS then use the [N3IWF](https://github.com/CriXson/N3IWF-for-Open5GS) and the [UE](https://github.com/CriXson/non3GPP-access), I worked with.

## Identifiers for the UE used

Even though the communication is done via the non-3GPP access, the IMSI format is used for and not the NAI format, as Open5GS did not support NAI at the time. The list of IMSIs configured can be found in the file imsis. You can add new ones to the database, but those do not work with EAP-TLS as it is hardcoded, which IMSIs are authenticated via EAP-TLS as of now.


## License

- Open5GS Open Source files are made available under the terms of the GNU Affero General Public License ([GNU AGPL v3.0](https://www.gnu.org/licenses/agpl-3.0.html)).
- [Commercial licenses](https://open5gs.org/open5gs/support/) are also available from [NeoPlane](https://neoplane.io/)
