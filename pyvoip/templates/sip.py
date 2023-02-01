SIP_REQUEST = """\
{{ method }} {{ ruri }} SIP/2.0
Via: SIP/2.0/{{ via_proto }} {{ via_addr }}{{ r_port }};branch=z9hG4bKSG.{{ via_branch }}
From: {% if f_name %}"{{ f_name }}" {% endif %}<sip:{% if f_user %}{{ f_user }}@{% endif %}{{ f_domain }}>;tag={{ from_tag }}
To: {% if t_name %}"{{ t_name }}" {% endif %}<sip:{% if t_user %}{{ t_user }}@{% endif %}{{ t_domain }}>
Call-ID: {{ call_id }}
CSeq: {{ cseq_num }} {{ method }}
{%- if subject %}{{"\n"}}Subject: {{ subject }}{% else %}{% endif %}
{%- if date %}{{"\n"}}Date: {{ date }}{% endif %}
{%- if contact_uri %}{{"\n"}}Contact: {{ contact_uri }}{% if contact_params %};{{ contact_params }}{% endif %}{% endif %}
{%- if expires %}{{"\n"}}Expires: {{ expires }}{% endif %}
{%- if user_agent %}{{"\n"}}User-Agent: {{ user_agent }}{% endif %}
{%- if content_type %}{{"\n"}}Content-Type: {{ content_type }}{% endif %}
{%- if content_length %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
{%- if body %}{{"\n"}}{{ body }}{% endif %}
"""

SIP_RESPONSE = """\
SIP/2.0 {{ status_code }} {{ status_message }}
Via: SIP/2.0/{{ via_proto }} {{ via_addr }}{{ r_port }};branch=z9hG4bKSG.{{ via_branch }}
From: {% if f_name %}"{{ f_name }}" {% endif %}<sip:{% if f_user %}{{ f_user }}@{% endif %}{{ f_domain }}>;tag={{ from_tag }}
To: {% if t_name %}"{{ t_name }}" {% endif %}<sip:{% if t_user %}{{ t_user }}@{% endif %}{{ t_domain }}>;tag={{ to_tag }}
Call-ID: {{ call_id }}
CSeq: {{ cseq_num }} {{ method }}
{%- if subject %}{{"\n"}}Subject: {{ subject }}{% endif %}
{%- if date %}{{"\n"}}Date: {{ date }}{% endif %}
{%- if contact_uri %}{{"\n"}}Contact: {{ contact_uri }}{% if contact_params %};{{ contact_params }}{% endif %}{% endif %}
{%- if expires %}{{"\n"}}Expires: {{ expires }}{% endif %}
{%- if user_agent %}{{"\n"}}User-Agent: {{ user_agent }}{% endif %}
{%- if content_type %}{{"\n"}}Content-Type: {{ content_type }}{% endif %}
{%- if content_length %}{{"\n"}}Content-Length: {{ content_length }}{% endif %}
{%- if body %}{{{"\n\n"}}{ body }}{% endif %}
"""

if __name__ == "__main__":
    print(SIP_REQUEST)
    print(SIP_RESPONSE)
