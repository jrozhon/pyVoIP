from enum import Enum

import jinja2

from pyvoip.proto.RTP import PayloadType, TransmitType

vars = {
    "sdp_user": "pyvoip",
    "sdp_sess_id": "1",
    "sdp_sess_version": 3,
    "sdp_af": "IP4",
    "local_ip": "10.76.100.41",
    "sdp_ms": {
        12047: {8: PayloadType.PCMA, 0: PayloadType.PCMU, 101: PayloadType.EVENT}
    },
    "sdp_direction": TransmitType.SENDRECV,
}


class SIPBodyTemplate(Enum):
    SDP = """\
v=0
o={{ sdp_user }} {{ sdp_sess_id }} {{ sdp_sess_version }} IN {{ sdp_af }} {{ local_ip }}
s=call
c=IN {{ sdp_af }} {{ local_ip }}
t=0 0
{%- for sdp_rtp_port, rtp_dict in sdp_ms.items() %}
m=audio {{ sdp_rtp_port }} RTP/AVP {% for sdp_codec_code in rtp_dict.keys() %}{{sdp_codec_code}} {% endfor %}
{%- endfor %}
{%- for sdp_rtp_port, rtp_dict in sdp_ms.items() %}
{%- for sdp_codec_code,sdp_val in rtp_dict.items() %}
a=rtpmap:{{sdp_codec_code}} {{sdp_val}}/{{sdp_val.rate}}
{%- endfor %}
{%- endfor %}
a={{sdp_direction}}

"""


# a=ptime:20
# a=fmtp:101 0-15
# a=rtcp:{{ sdp_rtcp_port }}
# a=rtcp-mux
# a=rtcp-rsize
# a=ice-ufrag:{{ ice_ufrag }}
# a=ice-pwd:{{ ice_pwd }}
# a=candidate:{{ ice_cand_id }} 1 UDP {{ ice_cand_prio }} {{ local_ip }} {{ sdp_rtp_port }} typ host
# a=candidate:{{ ice_cand_id }} 2 UDP {{ ice_cand_prio }} {{ local_ip }} {{ sdp_rtcp_port }} typ host
# a=setup:actpass
# a=mid:audio
# a=msid:{{ msid }} {{ msid }}
# a=ssrc:{{ ssrc }} cname:{{ cname }}
# a=ssrc:{{ ssrc }} msid:{{ msid }} {{ msid }}
# a=ssrc:{{ ssrc }} mslabel:{{ msid }}
# a=ssrc:{{ ssrc }} label:{{ msid }}
if __name__ == "__main__":
    # print(SIPBodyTemplate.SDP.value)
    e = jinja2.Environment()
    t = e.from_string(SIPBodyTemplate["SDP"].value)
    msg = t.render(**vars).lstrip().replace("\n", "\r\n")
    print(msg)
