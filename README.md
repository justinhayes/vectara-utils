# vectara-eval
A project that has scripts and libraries that help with using the Vectara platform.

Most scripts require you to use authentication related arguments, copied from the web console, to run successfully. For example:

```
python3 vectara_query.py \
    --auth-url "<COPY FROM VECTARA CONSOLE>" \
    --app-client-id "<COPY FROM VECTARA CONSOLE>" \
    --app-client-secret "<COPY FROM VECTARA CONSOLE>" \
    --customer-id <COPY FROM VECTARA CONSOLE> \
    --corpus-id <COPY FROM VECTARA CONSOLE> \
    --query "what is the meaning of life?"
```

