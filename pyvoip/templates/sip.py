from enum import Enum

import jinja2

from pyvoip.sock.transport import TransportMode


class SIPHeaderTemplate(Enum):
    # removed branch init string to be consistent with RESPONSE template
    REQUEST = """\
{{ method }} sip:{% if r_user %}{{ r_user }}@{% endif %}{{ r_domain }}{% if r_port %}:{{ r_port }}{% endif %} SIP/2.0
Via: SIP/2.0/{{ v_proto }} {{ v_addr }}{% if v_port %}:{{ v_port }}{% endif %}{% if rport is not none %}{% if rport=="" %};rport{% else %}={{ rport }}{% endif %}{% endif %};branch={{ branch }}
From: {% if f_name %}"{{ f_name }}" {% endif %}<sip:{% if f_user %}{{ f_user }}@{% endif %}{{ f_domain }}>;tag={{ f_tag }}
To: {% if t_name %}"{{ t_name }}" {% endif %}<sip:{% if t_user %}{{ t_user }}@{% endif %}{{ t_domain }}>{% if t_tag %};tag={{ t_tag }}{% endif %}
Call-ID: {{ call_id }}
CSeq: {{ cseq_num }} {{ method }}
{%- if subject %}{{"\n"}}Subject: {{ subject }}{% else %}{% endif %}
{%- if date %}{{"\n"}}Date: {{ date }}{% endif %}
{%- if c_domain %}{{"\n"}}Contact: <sip:{{ c_user }}@{{ c_domain }}{% if c_port %}:{{c_port}}{% endif %}{% if c_transport %};transport={{ c_transport }}{% endif %}>{% if c_params %};{{ c_params }}{% endif %}{% endif %}
{%- if allow %}{{"\n"}}Allow: {{ allow }}{% endif %}
{%- if expires is not none %}{{"\n"}}Expires: {{ expires }}{% endif %}
{%- if user_agent %}{{"\n"}}User-Agent: {{ user_agent }}{% endif %}
{%- if max_forwards %}{{"\n"}}Max-Forwards: {{ max_forwards }}{% endif %}
{%- if content_type %}{{"\n"}}Content-Type: {{ content_type }}{% endif %}
{%- if content_length is not none %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
{%- if authorization %}{{"\n"}}Authorization: {{ authorization }}{% endif %}

{% if body %}{{ body }}{% endif %}
"""
    RESPONSE = """\
SIP/2.0 {{ status_code }} {{ status_message }}
{%- for via in vias %}{{"\n"}}{{ via }}{% endfor %}
{%- if f_raw %}{{"\n"}}From: {{ f_raw }}{% else %}From: {% if f_name %}"{{ f_name }}" {% endif %}<sip:{% if f_user %}{{ f_user }}@{% endif %}{{ f_domain }}>;tag={{ f_tag }}{% endif %}
{%- if t_raw %}{{"\n"}}To: {{ t_raw }}{% else %}{{"\n"}}To: {% if t_name %}"{{ t_name }}" {% endif %}<sip:{% if t_user %}{{ t_user }}@{% endif %}{{ t_domain }}>{% if t_tag %};tag={{ t_tag }}{% endif %}{% endif %}
Call-ID: {{ call_id }}
CSeq: {{ cseq_num }} {{ method }}
{%- if subject %}{{"\n"}}Subject: {{ subject }}{% else %}{% endif %}
{%- if date %}{{"\n"}}Date: {{ date }}{% endif %}
{%- if c_domain %}{{"\n"}}Contact: <sip:{{ c_user }}@{{ c_domain }}{% if c_port %}:{{c_port}}{% endif %}{% if c_transport %};transport={{ c_transport }}{% endif %}>{% if c_params %};{{ c_params }}{% endif %}{% endif %}
{%- if allow %}{{"\n"}}Allow: {{ allow }}{% endif %}
{%- if expires %}{{"\n"}}Expires: {{ expires }}{% endif %}
{%- if user_agent %}{{"\n"}}User-Agent: {{ user_agent }}{% endif %}
{%- if max_forwards %}{{"\n"}}Max-Forwards: {{ max_forwards }}{% endif %}
{%- if content_type %}{{"\n"}}Content-Type: {{ content_type }}{% endif %}
{%- if content_length is not none %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
{%- if www_auth %}{{"\n"}}WWW-Authenticate: {{ www_auth }}{% endif %}

{% if body %}{{ body }}{% endif %}
"""
    # removed branch init string to allow multiple lines of Via header in responses
    RESPONSE_VIA = "Via: SIP/2.0/{{ v_proto }} {{ v_addr }}{% if v_port %}:{{ v_port }}{% endif %}{% if rport is not none %};rport={{ rport }}{% endif %};branch={{ branch }}"


# SIP/2.0 {{ status_code }} {{ status_message }}
# Via: SIP/2.0/{{ v_proto }} {{ v_addr }}{{ r_port }};branch=z9hG4bKSG.{{ branch }}
# From: {% if f_name %}"{{ f_name }}" {% endif %}<sip:{% if f_user %}{{ f_user }}@{% endif %}{{ f_domain }}>;tag={{ f_tag }}
# To: {% if t_name %}"{{ t_name }}" {% endif %}<sip:{% if t_user %}{{ t_user }}@{% endif %}{{ t_domain }}>;tag={{ t_tag }}
# Call-ID: {{ call_id }}
# CSeq: {{ cseq_num }} {{ method }}
# {%- if subject %}{{"\n"}}Subject: {{ subject }}{% endif %}
# {%- if date %}{{"\n"}}Date: {{ date }}{% endif %}
# {%- if c_uri %}{{"\n"}}c: {{ c_uri }}{% if c_params %};{{ c_params }}{% endif %}{% endif %}
# {%- if expires %}{{"\n"}}Expires: {{ expires }}{% endif %}
# {%- if user_agent %}{{"\n"}}User-Agent: {{ user_agent }}{% endif %}
# {%- if content_type %}{{"\n"}}Content-Type: {{ content_type }}{% endif %}
# {%- if content_length %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
# {%- if body %}{{{"\n\n"}}{ body }}{% endif %}

vars = {
    "status_code": 200,
    "status_message": "OK",
    "method": "BYE",
    "vias": [
        "Via: SIP/2.0/UDP 10.76.17.4:5060;branch=z9hG4bKPjb658bda6-f649-4d3f-9c5b-e75dc752877b"
    ],
    "f_raw": '"jro 401" <sip:401@10.76.17.4>;tag=0bdab654-ee0f-45b1-9111-639bcd70db48',
    "t_raw": "<sip:iptel402@10.76.100.41>;tag=5ea58816",
    "t_name": "",
    "t_user": "iptel402",
    "t_domain": "10.76.100.41",
    "t_tag": "5ea58816",
    "call_id": "5c33a61b-6aeb-4515-9b1e-3911b1eceef7",
    "cseq_num": 3338,
    "c_user": "iptel402",
    "c_domain": "10.76.100.41",
    "c_port": 5071,
    "c_transport": TransportMode.UDP,
    "c_params": None,
    "allow": "INVITE, ACK, BYE, CANCEL, OPTIONS",
    "expires": None,
    "user_agent": "pyvoip 0.1.2",
    "max_forwards": 70,
    "content_type": None,
    "content_length": 0,
    "authorization": None,
}

if __name__ == "__main__":
    e = jinja2.Environment()
    t = e.from_string(SIPHeaderTemplate.RESPONSE.value)
    msg = t.render(**vars).lstrip().replace("\n", "\r\n")
    print(msg)
