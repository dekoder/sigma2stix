## The logic

### Data download

The public rules (approved by the Sigma team) are stored in the main Sigma repository, nested in the `rules*` directories, e.g.

`rules-emerging-threats/2023/Exploits/CVE-2023-20198/cisco_syslog_cve_2023_20198_ios_xe_web_ui.yml`

[View it here](cisco_syslog_cve_2023_20198_ios_xe_web_ui.yml).

sigma2stix considers the latest branch of the sigma repository when the script is run.

### Parsing the data

Each sigma rule is written in YAML. 

The Sigma specification defines the attributes that can be found in the YAML files, and some of the taxonomies used for the properties to populate them. [View the specification here](https://sigmahq.io/sigma-specification/).


```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<UUID V5>",
    "created_by_ref": "identity--a48f059c-934e-4a07-880e-24d460202fe9",
    "created": "<SIGMA RULE DATE FIELD, IF NONE SCRIPT RUN TIME>",
    "modified": "<SIGMA RULE MODIFIED FIELD, IF NONE SCRIPT CREATED>",
    "indicator_types": [
        "malicious-activity",
        "anomalous-activity"
    ],
    "name": "<SIGMA RULE TITLE>",
    "description": "<SIGMA RULE DESCRIPTION>. The following false positives can result from this detection; <SIGMA RULE FALSE POSITIVES 0>, <SIGMA RULE FALSE POSITIVES N>",
    "pattern": "<ENTIRE SIGMA RULE YAML>",
    "pattern_type": "sigma",
    "valid_from": "<CREATED TIME>",
    "labels": [
        "level: <LEVEL>",
        "status: <STATUS>",
        "author: <AUTHOR>",
        "license: <LICENSE>",
        "<TAG 1>",
        "<TAG N>"
    ],
    "external_references": [
        {
            "source_name": "rule",
            "url": "<GITHUB LINK TO RULE>"
        },
        {
            "source_name": "id",
            "url": "<SIGMA RULE ID>"
        },
        {
            "source_name": "reference",
            "url": "<SIGMA RULE REFERENCES FIELD[0]>"
        },
        {
            "source_name": "reference",
            "url": "<SIGMA RULE REFERENCES FIELD[N]>"
        }
    ],
    "object_marking_refs": [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "<MARKING DEFINITION IMPORTED>"
    ]      
}
```

The UUID part of the rule is generated using the namespaces `efccc0ba-d237-5c9a-ad41-4f8bb6791be4` and the Sigma Rule `ID+pattern_type` (from STIX object).

e.g. namespace = `efccc0ba-d237-5c9a-ad41-4f8bb6791be4` and value = `f305fd62-beca-47da-ad95-7690a0620084+sigma`

Note, a Sigma Rules can also contain a `related` property, that links it to another rule. For example,

```yaml
related:
    - id: f305fd62-beca-47da-ad95-7690a0620084
      type: similar
```

Or an example with two relationships;

```yaml
related:
    - id: 455b9d50-15a1-4b99-853f-8d37655a4c1b
      type: similar
    - id: 75df3b17-8bcc-4565-b89b-c9898acef911
      type: obsoletes
```

Where the `related` property with an `id` and `type` is found in a rule (as noted above, could be many), a STIX relationship object is also created to link the two rules as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--a48f059c-934e-4a07-880e-24d460202fe9",
    "created": "<CREATED FIELD OF SOURCE INDICATOR OBJECT>",
    "modified": "<MODIFIED FIELD OF SOURCE INDICATOR OBJECT>",
    "relationship_type": "<RELATED.TYPE VALUE>",
    "source_ref": "indicator--<ID OF OBJECT WITH RELATED FIELD>",
    "target_ref": "indicator--<RELATED FIELD ID>",
    "object_marking_refs": [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `efccc0ba-d237-5c9a-ad41-4f8bb6791be4` and `source_ref+target_ref` (e.g, `indicator--0ec4f75f-74c1-4f66-a6d0-f488b20072f1+indicator--4c188857-cbcd-4c76-98e4-90fc2f5a6ddf`).

The path to each rule (directory structure) also holds some significance, and should be represented as STIX 2.1 Grouping objects.

```json
{
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--<UUID V5>",
    "created_by_ref": "<IDENTITY IMPORTED>",
    "created": "<EARLIEST CREATED TIME OF OBJECT IN BUNDLE>",
    "modified": "<LATEST CREATED TIME OF OBJECT IN BUNDLE>",
    "name": "<DIRECTORY PATH>",
    "context": "suspicious-activity",
    "object_refs": [
        "indicator--<ID OF RULE IN DIRECTORY>",
        "indicator--<ID OF RULE IN DIRECTORY>"
    ],
    "object_marking_refs": [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `efccc0ba-d237-5c9a-ad41-4f8bb6791be4` and `name` property (e.g, `rules-threat-hunting/windows/file/file_event`).

For example, this directory path holds 3 rules: https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/windows/file/file_event, and thus 3 `object_refs` would exist in the grouping object representing it.

To support the `_ref`s created in the objects shown above, two other objects are imported by sigma2stix on the run;

* https://raw.githubusercontent.com/signalscorps/stix4signalscorps/main/objects/marking-definition/marking-definition--efccc0ba-d237-5c9a-ad41-4f8bb6791be4.json
* https://raw.githubusercontent.com/signalscorps/stix4signalscorps/main/objects/identity/identity--efccc0ba-d237-5c9a-ad41-4f8bb6791be4.json

sigma2stix also creates a STIX 2.1 Bundle JSON object containing all the other STIX 2.1 Objects created at each run. The Bundle takes the format;

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5 GENERATION LOGIC>",
    "objects": [
        "<ALL STIX JSON OBJECTS>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `efccc0ba-d237-5c9a-ad41-4f8bb6791be4` and `<MD5 HASH OF THE OBJECTS PAYLOAD IN BUNDLE JSON>`.

e.g.

```json
    "objects": [
        {
            "type": "indicator",
            ...
            "object_marking_refs": [
                "marking-definition--4e3d8530-c524-4637-a89a-043227d34cb0"
            ]
        },
        {
            "type": "indicator",
            ...
            "object_marking_refs": [
                "marking-definition--4e3d8530-c524-4637-a89a-043227d34cb0"
            ]
        },
        {
            "type": "indicator",
            ...
            "object_marking_refs": [
                "marking-definition--4e3d8530-c524-4637-a89a-043227d34cb0"
            ]
        }
    }
```

Would give an MD5 of `27c036a47398f4cd44228ae5d9cfb53d`.

Thus to generate the bundle ID would use the namespace `efccc0ba-d237-5c9a-ad41-4f8bb6791be4` and value `27c036a47398f4cd44228ae5d9cfb53d` = `bundle--ea1623fc-87df-5f3b-b82d-eb76f3acccf3`

### Storing the objects in the file store

To support a similar approach to object distribution as MITRE do for both ATT&CK and CAPEC (objects stored as json files on GihHub), this script also allows for the STIX 2.1 objects to be stored in the filesystem.

The objects are stored in the root directory. The directory structure is defined by the STIX 2 Library's filesystem API, [as described here](https://stix2.readthedocs.io/en/latest/guide/filesystem.html).

A static [STIX 2.1 Bundle file](https://stix2.readthedocs.io/en/latest/guide/creating.html#Creating-Bundles) (that contains all Objects for the latest version) is also created. This is so that there is a URL that never changes and always returns the most recent bundle of objects;

```shell
/stix2_objects/sigma-rule-bundle.json
```