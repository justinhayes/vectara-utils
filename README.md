# vectara-utils
A project that has scripts and libraries that help with using the Vectara platform.

Most scripts require you to use authentication related arguments, copied from the web console, to run successfully. To do this, create an App Client via the Authentication page, and then take note of the app client ID, the app client secret, and the authentication domain. You can get your customer ID from the top right section of the console. 

For example:
```
python3 vectara_query.py \
    --app-client-id "<COPY FROM VECTARA CONSOLE>" \
    --app-client-secret "<COPY FROM VECTARA CONSOLE>" \
    --customer-id <COPY FROM VECTARA CONSOLE> \
    --corpus-id <COPY FROM VECTARA CONSOLE> \
    --query "what is the meaning of life?"
```

