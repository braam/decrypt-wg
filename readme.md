AES Key wrap code from - https://gist.github.com/kurtbrose/4243633

Watchguard Key info from https://serverfault.com/questions/790339/merge-vpns-of-two-watchguard-firewalls-into-one-firewall

This code takes a watchguard PSK from the exported XML config file and returns plaintext value.
PSKs starting with '+' character are able to be decrypted.



NEEDED:
- sudo apt install python2.7
- curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
- python2.7 get-pip.py
- sudo apt-get install python-dev
- sudo python2.7 -m pip install pycrypto
