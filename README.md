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

Note : The vaccine booking part is written blindly. I've yet to book a
vaccine but I can't as of now. I blindly trusted the cowin's API while
writing that block. If that block fails (high probability haha) then
I'll be rewriting and patching it ASAP.

Note : The login way is different bc the other two ways of logins that
cowin's provide doesn't work with other APIs. The token from
public/protected APIs listed on cowin API's documentation will just not
work on several public/private APIs. I reversed how the cowin's website
does it and implemented in that way.