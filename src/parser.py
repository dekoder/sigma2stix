import json

from stix2 import Indicator, Grouping, Relationship, parse, Identity
from datetime import datetime
from src import config
from src import utils
import uuid


class SigmaParser:
    @staticmethod
    def parse_indicator(data:dict, path:str) -> list:
        data_list = []
        if not config.fs.get(f"indicator--{data.get('id')}"):
            try:
                id = str(uuid.uuid5(config.namespace, f"{data.get('id')}+sigma"))
                indicator = Indicator(
                    id=f"indicator--{id}",
                    created_by_ref=utils.get_data_from_fs("identity")[0],
                    created=datetime.strptime(data.get('date'), "%Y/%m/%d"),
                    modified=datetime.strptime(data.get('modified') if data.get('modified') else data.get('date'), "%Y/%m/%d"),
                    indicator_types=["malicious-activity","anomalous-activity"],
                    name=data.get("title"),
                    description=f"{data.get('description')}. The following false positives can result from this detection; {', '.join(data.get('falsepositives',[]))}",
                    pattern=data,
                    pattern_type="sigma",
                    valid_from=datetime.strptime(data.get('date'), "%Y/%m/%d"),
                    labels=[
                        f"level: {data.get('level')}",
                        f"status: {data.get('status')}",
                        f"author: {data.get('author')}",
                        f"license: {data.get('license')}",

                    ] + data.get('tags', []),
                    external_references=[
                        {
                            "source_name": "rule",
                            "url": f"https://github.com/SigmaHQ/sigma/blob/master/{path[5:]}"
                        },
                        {
                            "source_name": "id",
                            "url": f"{data.get('id')}"
                        },
                    ] + utils.generate_all_references(data),
                    object_marking_refs=[
                        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                    ]+[utils.get_data_from_fs("marking-definition")[0]]
                )
                data_list.append(indicator)
                config.fs.add(indicator)
            except Exception as e:
                pass
        return data_list

    @staticmethod
    def parse_relationship(data:dict):
        data_list = []
        for relation in data.get("related", None): # type dict
            #id = f'indicator--{data.get("id")}+'+f'indicator--{relation.get("id")}'
            #id = str(uuid.uuid5(config.namespace, f"{id}"))
            source_object_id = uuid.uuid5(config.namespace, f"{data.get('id')}+sigma")
            target_object_id = uuid.uuid5(config.namespace, f"{relation.get('id')}+sigma")
            id = f'indicator--{source_object_id}+' + f'indicator--{target_object_id}'
            id = str(uuid.uuid5(config.namespace, f"{id}"))
            if not config.fs.get(f"relationship--{id}"):
                relation = Relationship(
                    id=f"relationship--{id}",
                    created_by_ref=utils.get_data_from_fs("identity")[0],
                    created=datetime.strptime(data.get('date'), "%Y/%m/%d"),
                    modified=datetime.strptime(data.get('modified') if data.get('modified') else data.get('date'), "%Y/%m/%d"),
                    relationship_type=relation.get('type'),
                    source_ref=f"indicator--{source_object_id}",
                    target_ref=f"indicator--{target_object_id}",
                    object_marking_refs=[
                        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                    ]+[utils.get_data_from_fs("marking-definition")[0]]
                )
                config.fs.add(relation)
                data_list.append(relation.serialize())
        return data_list

    @staticmethod
    def parse_grouping(data:dict)-> list:
        id = str(uuid.uuid5(config.namespace, f"{data.get('path')}"))
        grouping = Grouping(
            id=f"grouping--{id}",
            context="suspicious-activity",
            created_by_ref=utils.get_data_from_fs("identity")[0],
            created=config.fs.get(data.get("indicators")[0]).get("created"),
            modified=config.fs.get(data.get("indicators")[0]).get("modified"),
            name=f"{data.get('path')}",
            object_refs=data.get("indicators"),
            object_marking_refs=[
                        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                    ]+[utils.get_data_from_fs("marking-definition")[0]]
        )
        config.fs.add(grouping)
        return [grouping.serialize()]

    @staticmethod
    def parse_marking_definition():
        marking_definition = parse(
            json.loads(utils.load_file_from_url(config.marking_definition_url))
        )
        if not config.fs.get(marking_definition.get("id")):
            config.fs.add(marking_definition)
        return marking_definition

    @staticmethod
    def parse_identity():
        identity = parse(
            json.loads(utils.load_file_from_url(config.identity_url))
        )
        if not config.fs.get(identity.get("id")):
            config.fs.add(identity)
        return identity
