# sigma2stix

A command line tool that converts the entire SigmaHQ Ruleset into STIX 2.1 Objects

## Overview

> Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. The rule format is very flexible, easy to write and applicable to any type of log file.

[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

Sigma Rules are written in a YAML format, and distributed as YAML files.

The public rules (approved by the Sigma team) are stored in the main Sigma repository, nested in the `rules*` directories, e.g.

`rules-emerging-threats/2023/Exploits/CVE-2023-20198/cisco_syslog_cve_2023_20198_ios_xe_web_ui.yml`

https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/Exploits/CVE-2023-20198/cisco_syslog_cve_2023_20198_ios_xe_web_ui.yml

Here at Signals Corps, most of the data we deal with is in STIX 2.1 format. This is because downstream threat intelligence tools understand STIX.

sigma2stix;

1. Downloads the latest SigmaHQ/sigma repository
2. Converts each rule in a `rules*` directory to a STIX object
3. Outputs a STIX bundle containing all the converted rules

## Installing the script

To install sigma2stix;

```shell
# clone the latest code
git clone https://github.com/signalscorps/sigma2stix
# create a venv
cd sigma2stix
python3 -m venv sigma2stix-venv
source sigma2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

## Running the script

```shell
python3 sigma2stix.py
```

On each run all objects will be recreated.

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [SigmaHQ on GitHub](https://github.com/SigmaHQ)

## Support

[Minimal support provided via Slack in the #support-oss channel](https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA).

## License

[Apache 2.0](/LICENSE).