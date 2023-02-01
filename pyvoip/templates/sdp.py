SDP = """\
v=0
o={{ sdp_user }} {{ sdp_sess_id }} {{ sdp_sess_version }} IN {{ sdp_af }} {{ local_ip }}
s=call
c=IN {{ sdp_af }} {{ local_ip }}
t=0 0
m=audio {{ sdp_rtp_port }} RTP 0 8 101
a=rtpmap:0 pcmu/8000
a=rtpmap:8 pcma/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
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
    print(SDP)
