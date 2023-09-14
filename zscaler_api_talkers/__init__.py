from .client_connector.talker import ClientConnectorTalker, ZccTalker
from .client_connector.portal_talker import MobilePortalTalker
from .zdx.portal_talker import ZdxPortalTalker
from .zia.portal_talker import ZiaPortalTalker
from .zia.talker import ZiaTalker
from .zpa.portal_talker import ZpaPortalTalker
from .zpa.talker import ZpaTalker

__all__ = [
    "ZccTalker",  # Deprecated on 20230705.
    "ClientConnectorTalker",
    "ZdxPortalTalker",
    "ZiaTalker",
    "ZiaPortalTalker",
    "ZpaTalker",
    "ZpaPortalTalker",
    "MobilePortalTalker"
]
