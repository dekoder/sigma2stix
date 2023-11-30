import logging
from uuid import UUID
from stix2 import FileSystemStore
from .utils import check_dir

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)

namespace = UUID("efccc0ba-d237-5c9a-ad41-4f8bb6791be4")
source_repo = "https://github.com/SigmaHQ/sigma.git"
temporary_path = "data"
file_system_path = "stix2_objects"
check_dir(file_system_path)
fs = FileSystemStore(file_system_path)
marking_definition_url="https://raw.githubusercontent.com/signalscorps/stix4signalscorps/main/objects/marking-definition/marking-definition--efccc0ba-d237-5c9a-ad41-4f8bb6791be4.json"
identity_url="https://raw.githubusercontent.com/signalscorps/stix4signalscorps/main/objects/identity/identity--efccc0ba-d237-5c9a-ad41-4f8bb6791be4.json"


