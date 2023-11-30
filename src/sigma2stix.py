import logging
from tqdm import tqdm
from src import config
from src import utils
from src.parser import SigmaParser


class Sigma2Stix:

    def __init__(self):
        self.parser = SigmaParser()
    #
    @staticmethod
    def prepare_bundle():
        utils.store_in_bundle(
            utils.append_data()
        )

    def run(self):
        utils.clean_filesystem(config.file_system_path)
        logging.info("Cloning start")
        utils.clone_github_repository(config.source_repo, config.temporary_path)
        logging.info("Cloning end")
        utils.delete_files_and_folders_except_rules()
        files = utils.get_all_yaml_files()
        self.parser.parse_marking_definition()
        self.parser.parse_identity()

        data_list = []
        for d in tqdm(files):
            temp_data = []
            for file in d.get(list(d.keys())[0]):
                data = utils.read_yaml_file(file)
                temp_data += self.parser.parse_indicator(data, file)
                data_list += temp_data
                if data.get("related", None):
                    data_list += self.parser.parse_relationship(data)

            if len(temp_data)>0:
                temp_data_ = []
                temp_data_ += [d.get("id") for d in temp_data]
                data_list += self.parser.parse_grouping({
                    "path": list(d.keys())[0][5:],
                    "indicators": temp_data_,
                })

        self.prepare_bundle()
        utils.clean_filesystem("data/")

