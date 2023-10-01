# vectara-utils
A project that has scripts and libraries that help with using the Vectara platform.

Most scripts require you to use authentication related arguments, copied from the web console, to run successfully. To do this, create an App Client via the Authentication page, and then take note of the app client ID and the app client secret. You can get your customer ID from the top right section of the console where it shows your user name. 

For example:
```
python3 vectara_query.py \
    --app-client-id "<COPY FROM VECTARA CONSOLE>" \
    --app-client-secret "<COPY FROM VECTARA CONSOLE>" \
    --customer-id <COPY FROM VECTARA CONSOLE> \
    --corpus-id <COPY FROM VECTARA CONSOLE> \
    --query "what is the meaning of life?"
```

## Notes for vectara.file_upload.py

When using this script to upload files, you must include a `source` argument to indicate where the file are coming from. 
Valid values are `local`, `s3`, `gdrive`. You can also provide an `extensions` argument, with either `*` (upload all files)
or a comma-separated list of filename extensions to be included in the upload (e.g. `pdf` or `docx, doc, pdf`).

### Local File System Source (source=local)

You must provide one of the following arguments:
* `local-file-path` - path to a single file to be uploaded
* `local-dir-path` - path to a directory, whose contents (files and nested subdirectories) will all be uploaded

### Google Drive Source (source=gdrive):

You can learn more about accessing Google Drive via Python at this [quickstart documentation](https://developers.google.com/drive/api/quickstart/python). 
You must provide the following arguments:
* `gdrive-folder` - path to the folder within "My Drive" whose contents (files and nested subfolders) will all be uploaded. To upload from "My Drive/papers/transformers/" you would use `papers/transformers` for this argument.
* `gdrive-auth-mode` - how to authenticate to Google Drive. Valid values are 'oauth' and 'service-account' (the default). With 'oauth' mode the credentials file must be the client secret from an OAuth 2.0 Client ID. With 'service-account' mode the credentials file must the key downloaded from a Service Account.
* `gdrive-creds-file` - local file path to the credentials file to use for authentication to Google Drive. This can be for an OAuth 2.0 client ID, or service account. See the [Google Workspace OAuth setup steps](https://developers.google.com/drive/api/quickstart/python#configure_the_oauth_consent_screen) or the [Google Workspace Service Account Key steps] (https://cloud.google.com/docs/authentication/provide-credentials-adc#local-key) for more information.
* `gdrive_user_to_impersonate` - email address of user to impersonate when access Google. Drive via a service account. If not provided then the service account must be granted permissions directly to the required Google Drive resources.

If you are using Service Account authentication, there are two options for determining which folders/files the service account has access to.
- `Grant Google Drive permissions to the service account ID` - In this option you get the email address of the service account (Google Cloud dashboard --> APIs & Services --> Credentials --> Service Accounts --> Click on the appropriate service account) and explicitly grant it "Viewer" permissions on the relevant folders/files in Google Drive that are to be indexed. If using this option do **not** pass in a `gdrive_user_to_impersonate` argument.
- `Service account impersonation of another user` - In this option you enable service account delegation so that the specific service account that you are using is able to access Google Drive on behalf of another user account. This other account can be a person or (ideally) an account within your organization's domain that is dedicated to be used for ingesting data into Vectara (e.g. vectara-gdrive-indexer@yourcompany.com). The specific steps to follow are:
  - Create a service account ([Docs](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount)), making a copy of the `Unique ID` once it is created
  - Download the key for the service account. This is the `gdrive-creds-file` you will use 
  - Enable Domain Wide Delegation for the service account ([Docs](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)). In the `Client ID` field enter the `Unique ID` copied above. When entering the OAuth scopes, use the following `https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/drive.metadata.readonly,https://www.googleapis.com/auth/drive.readonly`.
  - When running the script, use the `gdrive_user_to_impersonate` argument to pass in the email address of the account to impersonate. If you do not provide this argument it will not attempt to use impersonation, and instead will fall back to the `Grant Google Drive permissions to the service account ID` mode.

### S3 Source (source=s3):

You must provide the `s3-bucket` argument, which is the name of the bucket to upload from (e.g. `mybucket`).
You can optionally provide a `s3-path-prefix` argument, which is the path from the root of the bucket 
to the sub folder where the files reside. This can be empty. Do not start or end with '/'. An example is `path/to/folder`.
This approach requires there to be an AWS credentials file for a user who is permitted to read contents within the specified bucket location. Save this file as `~/.aws/credentials`. See the [boto3 quickstart](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html#configuration) and [boto3 credentials guide] (https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials) for more information.
