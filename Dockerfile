FROM python:3.7.4

RUN pip install ldap3 rocketchat_API

COPY rocketchat_ldap_sync.py /

CMD [ "python", "/rocketchat_ldap_sync.py" ]
