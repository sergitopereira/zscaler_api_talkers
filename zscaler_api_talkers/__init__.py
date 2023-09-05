from .client_connector.talker import ClientConnectorTalker, ZccTalker
from .zia.talker import ZiaTalker
from .zpa.talker import ZpaTalker
from .cloud_connector.talker import CloudConnectorTalker

__all__ = [
    "ZccTalker",  # Deprecated on 20230705.
    "ClientConnectorTalker",
    "ZiaTalker",
    "ZpaTalker",
    "CloudConnectorTalker",
]
