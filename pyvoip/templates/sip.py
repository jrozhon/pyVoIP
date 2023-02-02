from enum import Enum


class SIPHeaderTemplate(Enum):
    REQUEST = """\
{{ method }} sip:{% if r_user %}{{ r_user }}@{% endif %}{{ r_domain }}{% if r_port %}:{{ r_port }}{% endif %} SIP/2.0
Via: SIP/2.0/{{ v_proto }} {{ v_addr }}{% if v_port %}:{{ v_port }}{% endif %}{% if rport %}{{ rport }}{% endif %};branch=z9hG4bKSG.{{ branch }}
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
{%- if content_length %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
{%- if authorization %}{{"\n"}}Authorization: {{ authorization }}{% endif %}
{%- if body %}{{"\n\n"}}{{ body }}{% endif %}
"""
    RESPONSE = """\
SIP/2.0 {{ status_code }} {{ status_message }}
Via: SIP/2.0/{{ v_proto }} {{ v_addr }}{% if v_port %}:{{ v_port }}{% endif %}{% if rport %}{{ rport }}{% endif %};branch=z9hG4bKSG.{{ branch }}
From: {% if f_name %}"{{ f_name }}" {% endif %}<sip:{% if f_user %}{{ f_user }}@{% endif %}{{ f_domain }}>;tag={{ f_tag }}
To: {% if t_name %}"{{ t_name }}" {% endif %}<sip:{% if t_user %}{{ t_user }}@{% endif %}{{ t_domain }}>{% if t_tag %};tag={{ t_tag }}{% endif %}
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
{%- if content_length %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
{%- if www_auth %}{{"\n"}}WWW-Authenticate: {{ www_auth }}{% endif %}
{%- if body %}{{"\n\n"}}{{ body }}{% endif %}
"""


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


if __name__ == "__main__":
    print(SIPHeaderTemplate.REQUEST.value)
    print(SIPHeaderTemplate.RESPONSE.value)
    print(type(SIPHeaderTemplate.REQUEST.value))
    print(type(SIPHeaderTemplate.RESPONSE.value))
