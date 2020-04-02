FROM python:3.8.2

RUN pip install ldap3 rocketchat_API

COPY rocketchat_ldap_sync.py /

CMD [ "python", "/rocketchat_ldap_sync.py" ]
