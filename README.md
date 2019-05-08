# What is it

Small cli/cron tool to check and email you when your domains, stored in 
[PDNS](https://en.wikipedia.org/wiki/PowerDNS) & MySQL, are about to expire. 

Python 3 only.

## Install

```
git clone https://github.com/kilgoretrout1985/pdns-mysql-domain-exp.git
cd pdns-mysql-domain-exp/
python3 -m venv _env
source _env/bin/activate
pip3 install -r requirements.txt
cd pdns-mysql-domain-exp/
```

## Settings

Edit `settings.py` and at least configure your MySQL connection(s) to powerdns db 
and email to receive reports. All other settings are optional.

## Run

```
python3 domain_check.py
```

or better add to cron full path like so (do not loose your virtualenv!):

```
/home/user/scripts/pdns-mysql-domain-exp/_env/bin/python3 /home/user/scripts/pdns-mysql-domain-exp/pdns-mysql-domain-exp/domain_check.py
```
