""" This is an example of calling the Vectara API to upload files to be indexed.
It uses python and the REST API endpoint.
"""

import argparse
import logging
import json
import requests
import os
import pathlib
import io
import boto3

from authlib.integrations.requests_client import OAuth2Session

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload


def get_jwt_token(auth_url: str, app_client_id: str, app_client_secret: str):
    """Connect to the server and get a JWT token.
    Args:
        auth_url: Authorization URL for the OAuth2 server for this account
        app_client_id: ID of the app client used for authentication
        app_client_secret: Secret of the app client used for authentication

    Returns:
        JWT token for the authenticated app client
    """

    token_endpoint = f"{auth_url}/oauth2/token"
    session = OAuth2Session(
        app_client_id, app_client_secret, scope="")
    token = session.fetch_token(token_endpoint, grant_type="client_credentials")
    return token["access_token"]

def upload_file(customer_id: int, corpus_id: int, idx_address: str, filepath: str, extensions: str, jwt_token: str):
    """ Uploads a file from the local file system to the corpus.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        filepath: Path to a single file to be uploaded
        extensions: Filename extensions to restrict the upload to
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (response, False) in case of failure.
    """

    if skip_file_check(filepath, extensions):
        logging.info("Skipping " + filepath)
        return {"text": "Skipping " + filepath}, False

    logging.info("Uploading " + filepath)

    post_headers = {
        "Authorization": f"Bearer {jwt_token}"
    }
   
    #Example with only the file being posted 
    #files={"file": (filepath, open(filepath, 'rb'))}

    #Example with the file being posted and also a custom metadata attribute called 'filepath', 
    #passed in the json-encoded doc_metadata field.
    #First build the dictionary that will contain all the metadata fields.
    doc_metadata = {"filepath": f"{filepath}"}
    #Now encode it into a well-formatted JSON string
    doc_metadata_json = json.dumps(doc_metadata)
    #Now create the dictionary that stores the file being uploaded and also the metadata field
    files={"file": (filepath, open(filepath, 'rb')), "doc_metadata": f"{doc_metadata_json}"}

    #If using the "d=true" option in the REST URL below then the response will include a "document" object
    #that is the structured text that was generated during the extraction stage within the ingest pipeline.
    response = requests.post(
        f"https://h.{idx_address}/upload?c={customer_id}&o={corpus_id}&d=false",
        files=files,
        verify=True,
        headers=post_headers)

    #This code writes the response to a file. This is especially useful if using "d=true" in the URL above.
    #response_filepath = filepath + ".json"
    #logging.info("Writing response file to: %s", response_filepath)
    #parsed_file = open(filepath, "w")
    #parsed_file.write(response.text)
    #parsed_file.close()

    if response.status_code != 200:
        logging.error("REST upload failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

def upload_dir(customer_id: int, corpus_id: int, idx_address: str, dirpath: str, extensions: str, jwt_token: str):
    """ Uploads files from the local file system to the corpus. This traverses all nested directories.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        dirpath: Path to a directory whose files (and all nested subdirectories) are to be uploaded
        extensions: Filename extensions to restrict the upload to
        jwt_token: A valid Auth token.

    Returns:
        (responses, True) in case of success and returns (responses, False) in case of failure.
        The 'responses' item is an array containing the REST response object for each of the files
        that were processed to be uploaded.
    """

    responses = {}

    for subdir, dirs, files in os.walk(dirpath):
        for file in files:
            filepath = os.path.join(subdir, file)
            response, status = upload_file(customer_id,
                                      corpus_id,
                                      idx_address,
                                      filepath,
                                      extensions,
                                      jwt_token)
            logging.info("Upload file response: %s", response.text if status else response['text'])
            responses[filepath] = response
    
    return responses, True

def upload_s3file(customer_id: int, corpus_id: int, idx_address: str, s3bucket: str,
                  s3filepath: str, extensions: str, jwt_token: str):
    """ Upload a file from S3 to the corpus. This copies the file locally, uploads it, then deletes the local copy.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        s3bucket: S3 bucket name containing files to be uploaded
        s3filepath: Filepath to the file in S3 to upload
        extensions: Filename extensions to restrict the upload to
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (response, False) in case of failure.
    """

    if skip_file_check(s3filepath, extensions):
        logging.info("Skipping " + s3filepath)
        return {"text": "Skipping " + s3filepath}, False

    logging.info('Uploading ' + s3filepath)

    post_headers = {
        "Authorization": f"Bearer {jwt_token}"
    }

    s3 = boto3.client("s3")
    localfilename = '/tmp/' + os.path.basename(s3filepath)
    with open(localfilename, 'wb') as data:
        s3.download_fileobj(s3bucket, s3filepath, data)
        data.close()
        #logging.info('Copied s3 file locally for temporary usage: ' + localfilename)
    
    files={"file": (s3bucket + '/' + s3filepath, open(localfilename, 'rb'))}

    response = requests.post(
        f"https://h.{idx_address}/upload?c={customer_id}&o={corpus_id}",
        files=files,
        verify=True,
        headers=post_headers)

    os.remove(localfilename)
    #logging.info('Deleted locally copied s3 file: ' + localfilename)

    if response.status_code != 200:
        logging.error("REST upload failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

def upload_s3bucket(customer_id: int, corpus_id: int, idx_address: str, s3bucket: str,
                    s3pathprefix: str, extensions: str, jwt_token: str):
    """ Uploads file(s) from a S3 bucket to the corpus. This traverses all nested directories within the bucket.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        s3bucket: S3 bucket name containing files to be uploaded
        s3pathprefix: Path to the location within the S3 bucket to upload from
        extensions: Filename extensions to restrict the upload to
        jwt_token: A valid Auth token.

    Returns:
        (responses, True) in case of success and returns (responses, False) in case of failure.
        The 'responses' item is an array containing the REST response object for each of the files
        that were processed to be uploaded.
    """
    
    s3filepaths = []
    responses = {}

    s3 = boto3.client("s3")
    all_objects = s3.list_objects_v2(Bucket = s3bucket, Prefix = s3pathprefix, MaxKeys=1000)
    #logging.info(all_objects['Contents'])

    for s3object in all_objects['Contents']:
        if s3object['Key'][-1] != "/":
            s3filepaths.append(s3object['Key'])
    
    for s3filepath in s3filepaths:
        response, status = upload_s3file(customer_id,
                                         corpus_id,
                                         idx_address,
                                         s3bucket,
                                         s3filepath,
                                         extensions,
                                         jwt_token)
        logging.info("Upload file response: %s", response.text if status else response['text'])
        responses[s3filepath] = response
        logging.info('Uploaded ' + s3filepath)
    
    return responses, True

def gdrive_authentication(gdrive_creds_file: str, gdrive_auth_mode: str, gdrive_user_to_impersonate: str):
    """ Authenticates a client, using the provided credentials file, to Google Drive.
    Args:
        gdrive_creds_file: Path to local file that contains the Google Drive OAuth client ID credentials
        use_service_account: Boolean indicating whether or not to use service account authentication
    Returns:
        credentials object to be used in Google Drive API calls
    """
    # If modifying these scopes, delete the file gdrive_token.json.
    scopes = ['https://www.googleapis.com/auth/drive.metadata.readonly',
              'https://www.googleapis.com/auth/drive.readonly']

    creds = None

    if gdrive_auth_mode == 'service-account':
        creds = service_account.Credentials.from_service_account_file(
            gdrive_creds_file, scopes=scopes)

        if gdrive_user_to_impersonate:
            creds = creds.with_subject(gdrive_user_to_impersonate)

        return creds

    if gdrive_auth_mode == 'oauth':
        # The file gdrive_token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first time.
        if os.path.exists('gdrive_token.json'):
            creds = Credentials.from_authorized_user_file('gdrive_token.json', scopes)

        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    gdrive_creds_file, scopes)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open('gdrive_token.json', 'w') as token:
                token.write(creds.to_json())

        return creds

    return None

def find_base_folder(gdrive_service, base_folder_path: str):
    """ Takes a path to a potentially nested folder in the Google Drive "My Drive" location, and
    returns a dict containing info on how to locate that folder.
    Args:
        gdrive_service: A Google Drive service object
        base_folder_path: Path to the folder to upload from. Can be empty or "/", which means the root
        of the My Drive location, or can be a path that is one ore more levels deep.
    Returns:
        dict with 'id' (unique ID of the folder in Google Drive), 'name' (name of the base folder), and
        'path' (complete path to the base folder from the root of the My Drive location)
    """
    logging.info("Finding base folder for path '" + base_folder_path + "'")

    #see if it is the top level folder in My Drive that the user is uploading
    if base_folder_path is None or base_folder_path == "" or base_folder_path == "/":
        return ""

    #It's at least one level of subfolder down, so find that folder and figure out its ID.
    #We have to traverse each level of folder nesting, since Google Drive internally has
    #no concept of a hierarchical file system.

    folders = base_folder_path.split("/")
    last_folder = {}

    try:
        #traverse the folder(s) in the path
        for folder in folders:
            #logging.info("Handling folder part: " + folder)
            parent_query = ""
            if last_folder:
                parent_query = " and '" + last_folder['id'] + "' in parents"
            #logging.info("find_base_folder: parent_query=" + parent_query)
            results = gdrive_service.files().list(q="mimeType = 'application/vnd.google-apps.folder'" + parent_query,
                                       pageSize=10, fields="nextPageToken, files(id, name)").execute()
            items = results.get('files', [])
            if not items:
                #TODO if we get here, try finding the base folder via another way
                logging.info('No folders found in ' + folder)
                return {}
            #logging.info('Folders:')

            target_folder = {}
            #find the target subfolder in this current folder
            for item in items:
                if item['name'] == folder:
                    target_folder = item
                #logging.info(u'  {0} ({1})'.format(item['name'], item['id']))
            if not target_folder:
                raise Exception("No target folder found: " + folder)
                #return target_folder
            else:
                last_folder = target_folder
            #logging.info('  Setting last_folder=' + str(last_folder))

    except HttpError as error:
        logging.error(f'An error occurred when finding the Google Drive base folder to use: {error}')

    #remember the full path to this folder
    last_folder['path'] = "/" + base_folder_path

    return last_folder

def get_files_from_folder(gdrive_service, folder):
    """ Returns all files within a given Google Drive folder. This includes file in any nested
    subfolders within the specified folder.
    Args:
        gdrive_service: A Google Drive service object
        folder: Dictionary containing information on the folder from which to get the files
    Returns:
        List of dictionaries, each with 'id' (unique ID of the file in Google Drive), 'name' (name of the file), and
        'path' (complete path to the file from the root of the My Drive location)
    """
    logging.info("Getting list of files from folder " + str(folder))

    files = []

    parent_query = ""
    if folder:
        parent_query = " and '" + folder['id'] + "' in parents"

    try:
        #logging.info("get_files_from_folder: parent_query=" + parent_query)
        results = gdrive_service.files().list(q="mimeType != 'application/vnd.google-apps.folder'" + parent_query,
            pageSize=1000, fields="nextPageToken, files(id, name)").execute()
        items = results.get('files', [])

        if not items:
            logging.info('No files found in folder: ' + str(folder))
            return []
        #logging.info('Files:')
        for item in items:
            logging.info(u'{0} ({1})'.format(item['name'], item['id']))
            #remember the path to the folder that contains this file
            if folder is None or 'path' not in folder:
                item['path'] = "/"
            else:
                item['path'] = folder['path'] + folder['name'] + '/'
            #item['path'] = folder['path'] + folder['name'] if 'path' in folder else '/'
            files.append(item)
    except HttpError as error:
        logging.error(f'An error occurred when finding the Google Drive files within a folder: {error}')

    return files

def get_parent_folder(gdrive_service, item_id):
    item = gdrive_service.files().get(fileId=item_id, fields='id, parents, name').execute()
    logging.info("Item=" + str(item))
    if 'parents' not in item:
        return {"id": "", "name": "", "path": "/"}
    else:
        if len(item['parents']) > 1:
            logging.error("Parents list for item with ID " + item_id + " has " + len(item['parents']) + " parents.")
        parent_folder = gdrive_service.files().get(fileId=item['parents'][0], fields='id, parents, name').execute()
        logging.info("Parent of " + item_id + " is " + str(parent_folder))
        return parent_folder


def get_folders_from_folder(gdrive_service, folder, folder_id_to_parent_folder_map):
    """ Returns all folders within a given Google Drive folder. This includes folders in any nested
    subfolders within the specified folder.
    Args:
        gdrive_service: A Google Drive service object
        folder: Dictionary containing information on the folder from which to get the nested folders
        folder_id_to_parent_folder_map: mapping of gdrive folder/file ID to a dict representing the parent folder
    Returns:
        List of dictionaries, each with 'id' (unique ID of the folder in Google Drive), 'name' (name of the base
        folder), and 'path' (complete path to the base folder from the root of the My Drive location)
    """
    logging.info("Getting list of subfolders in folder " + ("/" if 'path' not in folder else (folder['path'] + folder['name'])))
    folders = []

    parent_query = ""
    if folder:
        parent_query = " and '" + folder['id'] + "' in parents"

        #get parent folder of this folder
        if folder["id"] not in folder_id_to_parent_folder_map:
            folder_id_to_parent_folder_map[folder["id"]] = get_parent_folder(gdrive_service, folder["id"])

    try:
        results = gdrive_service.files().list(q="mimeType = 'application/vnd.google-apps.folder'" + parent_query,
            pageSize=1000, fields="nextPageToken, files(id, name)").execute()
        items = results.get('files', [])

        if not items:
            #logging.info('No subfolders found in folder with id ' + str(folder))
            return []

        new_folders = []

        for item in items:
            #logging.info(u'  {0} ({1}) in folder {2}'.format(item['name'], item['id'], str(folder)))
            logging.info("Adding folder: " + str(item))

        for item in items:
            #logging.info(u'{0} ({1}) in folder {2}'.format(item['name'], item['id'], str(folder)))
            if 'path' not in folder:
                item['path'] = "/"
            else:
                item['path'] = folder['path'] + folder['name'] + '/'
            folders.append(item)
            #logging.info("Adding folder: " + str(item))
            #now recursively get any subfolder(s) in the current folder
            if item['id'] not in folder_id_to_parent_folder_map:
                logging.info("**** Haven't crawled this folder recursively yet: " + str(item))
                new_folders.extend(get_folders_from_folder(gdrive_service, item, folder_id_to_parent_folder_map))
        folders.extend(new_folders)
    except HttpError as error:
        logging.error(f'An error occurred when finding the Google Drive subfolders within a folder: {error}')

    return folders


def skip_file_check(filename: str, extensions: str):
    """ Determines whether to skip uploading a file, given its file name and a
    list of extensions to restrict the upload to.
    Args:
        filename: Name of the file being handled
        extensions: Comma-separated list of file name extensions to restrict this upload to. An empty value means
        that all files are skipped. A "*" value means that no files are skipped. "pdf" means that all files other
        than PDF files are skipped. "docx, pdf" means that all files other than PDF and .docx files are skipped.
    Returns:
        True if this file should be skipped
    """
    extensions_list = []
    if extensions:
        extensions_list = extensions.split(',')

    file_extension = pathlib.Path(filename).suffix
    if file_extension and file_extension.startswith('.'):
        file_extension = file_extension.lstrip('.')

    if file_extension not in extensions_list and "*" not in extensions_list:
        return True

    return False


def index_gdrive_files(customer_id: int, corpus_id: int, idx_address: str,
                       files: list, gdrive_service, extensions: str, jwt_token: str):
    """ Uploads file(s) from a Google Drive folder to the corpus. This traverses all nested directories within the folder.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        files: A list of dictionaries with information on each file to be uploaded
        gdrive_service: A Google Drive service object
        extensions: Filename extensions to restrict the upload to
        jwt_token: A valid Auth token.

    Returns:
        An array containing the REST response object for each of the files that were processed to be uploaded.
    """
    logging.info("Uploading identified files: ")

    responses = {}
    num_uploaded = 0
    num_failed = 0
    num_skipped = 0

    for file in files:
        if skip_file_check(file['name'], extensions):
            logging.info("Skipping " + file['path'] + "/" + file['name'])
            num_skipped += 1
            continue

        logging.info("Uploading " + file['path'] + "/" + file['name'])
        continue
        #first download the file locally

        try:
            request = gdrive_service.files().get_media(fileId=file['id'])
            file_data = io.BytesIO()
            downloader = MediaIoBaseDownload(file_data, request)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
                #logging.info(F'Download {int(status.progress() * 100)}%.')
        except HttpError as error:
            logging.error(f'An error occurred when downloading Google Drive file contents: {error}')

        localfilename = '/tmp/' + file['name']
        with open(localfilename, 'wb') as data:
            data.write(file_data.getbuffer())
            data.close()
            #logging.info('Copied Google Drive file locally for temporary usage: ' + localfilename)

        #now upload the file to Vectara

        post_headers = {
            "Authorization": f"Bearer {jwt_token}"
        }

        # Set some metadata fields to add to the document
        doc_metadata = {"filepath": file['path'], "filename": file['name'], "source": "Google Drive"}
        doc_metadata_json = json.dumps(doc_metadata)

        files = {"file": (file['name'], open(localfilename, 'rb')), "doc_metadata": f"{doc_metadata_json}"}

        response = requests.post(
            f"https://h.{idx_address}/upload?c={customer_id}&o={corpus_id}",
            files=files,
            verify=True,
            headers=post_headers)

        #now remove the locally downloaded file
        os.remove(localfilename)
        #logging.info('Deleted locally copied Google Drive file: ' + localfilename)

        if response.status_code != 200:
            logging.error("REST upload failed with code %d, reason %s, text %s",
                          response.status_code,
                          response.reason,
                          response.text)
            num_failed+= 1
        else:
            logging.info("Upload file response: %s", response.text)
            num_uploaded+= 1

        responses[file['id']] = response

    logging.info("Successfully uploaded %i files", num_uploaded)
    logging.info("Upload failed for %i files", num_failed)
    logging.info("Skipped %i files", num_skipped)

    return responses

def get_gdrive_item_path(folder_id_to_parent_folder_map, item_id):
    logging.info("    Getting path for " + item_id)
    path = ""
    parent_folder = folder_id_to_parent_folder_map[item_id]
    while parent_folder is not None:
        path = parent_folder["name"] + path
        parent_folder_id = parent_folder["parents"][0] if 'parents' in parent_folder else ""
        logging.info("      Parent is " + parent_folder["name"] + "; parent's parent is: " + parent_folder_id)
        if parent_folder_id is not None and parent_folder_id in folder_id_to_parent_folder_map:
            parent_folder = folder_id_to_parent_folder_map[parent_folder["parents"][0]]
            path = "/" + path
        else:
            parent_folder = None

    return "/" + path

def upload_gdrive_folder(customer_id: int, corpus_id: int, idx_address: str,
                         gdrive_folder: str, creds, extensions: str, jwt_token: str):
    """ Uploads file from a Google Drive folder to the corpus. This traverses all nested
    directories within the folder provided.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        gdrive_folder: Path to the base folder from which to upload files
        creds: Google Drive credentials object to be used in API calls
        extensions: Filename extensions to restrict the upload to
        jwt_token: A valid Auth token.

    Returns:
        (responses, True) in case of success and returns (responses, False) in case of failure.
        The 'responses' item is an array containing the REST response object for each of the files
        that were processed to be uploaded.
    """

    logging.info("Uploading files from Google Drive folder: " + gdrive_folder)

    responses = {}

    files = []
    folders = []

    try:
        gdrive_service = build('drive', 'v3', credentials=creds)

        # Get the ID of the folder being uploaded from. This will be empty if it's the
        # top level of the My Drive.
        base_folder = find_base_folder(gdrive_service, gdrive_folder)

        # Get a list of the files in the base folder
        #files.extend(get_files_from_folder(gdrive_service, base_folder))

        # Get a list of the (potentially nested) subfolder(s) within the base folder
        folder_id_to_parent_folder_map = {}
        folders.extend(get_folders_from_folder(gdrive_service, base_folder, folder_id_to_parent_folder_map))

        logging.info("Folder parent mapping:")
        for folder_id in folder_id_to_parent_folder_map:
            logging.info("  " + folder_id + "=" + str(folder_id_to_parent_folder_map[folder_id]))

        logging.info("Folders:")
        for folder in folders:
            logging.info("  [" + folder['id'] + "] - " +
                         get_gdrive_item_path(folder_id_to_parent_folder_map, folder['id'])
                         + "/" + folder['name'])

        # Get the files from within the (potentially nested) subfolder(s)
        #for folder in folders:
            #logging.info("Getting files from subfolder " + folder)
            #files.extend(get_files_from_folder(gdrive_service, folder))

        # Index all the files
        #responses = index_gdrive_files(customer_id, corpus_id, idx_address, files,
        #                               gdrive_service, extensions, jwt_token)
    except HttpError as error:
        logging.info(f'An error occurred when uploading from Google Drive: {error}')

    return responses, True

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser(description="Vectara REST API example for uploading files. "
                                                 "If uploading from S3, store your credentials in ~/.aws/credentials.")

    #Vectara related arguments
    parser.add_argument("--customer-id", type=int, required=True,
                        help="Customer ID from your Vectara account.")
    parser.add_argument("--corpus-id", type=int, required=True,
                        help="ID of the corpus in which data will be indexed.")
    parser.add_argument("--indexing-endpoint", help="The endpoint of indexing server.",
                        default="indexing.vectara.io")
    parser.add_argument("--app-client-id", required=True,
                        help="ID of an app client that has permission to index data in the corpus.")
    parser.add_argument("--app-client-secret", required=True,
                        help="Secret for an app client that has permission to index data in the corpus.")
    parser.add_argument("--auth-url", required=False,
                        help="The cognito auth url for this customer.")

    #generic file upload arguments
    parser.add_argument("--source", help="The data source to upload from. Valid values are 'local', 's3', 'gdrive'.",
                        default="local")
    parser.add_argument("--extensions", help="A comma-separated list of filename patterns to restrict this to. "
                                             "Examples are '' (no files), '*', (all files), 'pdf' (only PDFs), "
                                             "'docx,doc,pdf' (only Word docs and PDFs).",
                        default="*", required=False)

    # works with source=local
    parser.add_argument("--local-file-path", help="Relative path to the file to upload to the corpus.")
    parser.add_argument("--local-dir-path", help="Relative path to the directory to upload to the corpus.")

    # works with source=s3
    parser.add_argument("--s3-bucket", help="Bucket name to upload from. Just the name (e.g. mybucket) and "
                                            "not a full URI.")
    parser.add_argument("--s3-path-prefix", help="Path from the root of the bucket to the sub folder where the files "
                                                 "reside. Can be empty. Do not start or end with '/'. E.g. path/to/folder",
                        default="")

    # works with source=gdrive
    parser.add_argument("--gdrive-folder", help="Folder within the user's My Drive location in their Google Drive "
                                                "account from which to upload.")
    parser.add_argument("--gdrive-creds-file", help="Local file with credentials for the user's Google Drive account.")
    parser.add_argument("--gdrive-auth-mode", help="Manner of authentication to Google Drive. Valid values are 'oauth' "
                                                   "and 'service-account'.", default="service-account", required=False)
    parser.add_argument("--gdrive_user_to_impersonate", help="Email address of user to impersonate when access Google "
                                                             "Drive via a service account.", required=False)

    args = parser.parse_args()

    if args:
        auth_url = args.auth_url
        if auth_url == "" or auth_url is None:
            auth_url = f"https://vectara-prod-{args.customer_id}.auth.us-west-2.amazoncognito.com"
        token = get_jwt_token(auth_url, args.app_client_id, args.app_client_secret)

        if token:
            if args.source == 'local':
                if args.local_file_path:
                    result, status = upload_file(args.customer_id,
                                          args.corpus_id,
                                          args.indexing_endpoint,
                                          args.local_file_path,
                                          args.extensions,
                                          token)
                    logging.info("Upload file response: \n%s", result.text if status else result['text'])
                if args.local_dir_path:
                    result, status = upload_dir(args.customer_id,
                                          args.corpus_id,
                                          args.indexing_endpoint,
                                          args.local_dir_path,
                                          args.extensions,
                                          token)
                    logging.info("Upload directory response: \n%s", result)
            elif args.source == 's3':
                if args.s3_bucket:
                    result, status = upload_s3bucket(args.customer_id,
                                          args.corpus_id,
                                          args.indexing_endpoint,
                                          args.s3_bucket,
                                          args.s3_path_prefix,
                                          args.extensions,
                                          token)
                    logging.info("Upload S3 bucket response: \n%s", result)
            elif args.source == 'gdrive':
                if args.gdrive_folder is None or args.gdrive_creds_file is None:
                    logging.error("You must provide 'gdrive_folder' and 'gdrive_creds_file' "
                                  "arguments to upload from Google Drive")
                else:
                    creds = gdrive_authentication(args.gdrive_creds_file, args.gdrive_auth_mode,
                                                  args.gdrive_user_to_impersonate)
                    result, status = upload_gdrive_folder(args.customer_id,
                                          args.corpus_id,
                                          args.indexing_endpoint,
                                          args.gdrive_folder,
                                          creds,
                                          args.extensions,
                                          token)
                    logging.info("Upload Google Drive folder response: \n%s", result)
        else:
            logging.error("Could not generate an auth token. Please check your credentials.")
