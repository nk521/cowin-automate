# Cowin Automate

Depends on pyjwt, ntfy, pycryptodomex & requests

```python
python3 -m pip install virtualenv
python3 -m virtualenv <virtualenv-name>
pip install pyjwt ntfy[telegram] pycryptodomex requests

# configure ntfy now, if you want to use it.
# Else delete the code block which uses it.
# https://github.com/dschep/ntfy#telegram---telegram
ntfy -b telegram send "Telegram configured for ntfy"

# now just run the file
python cowin.py
```