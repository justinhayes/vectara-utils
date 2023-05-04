""" This is an example of calling the Vectara API to upload files to be indexed.
It uses python and the REST API endpoint. If using the option to upload data that
is stored on s3, you should have a "~/.aws/credentials" file that contains your
AWS credentials. See the following URL for more information:
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials
"""

import argparse
import logging
import json
import requests
import os
import boto3
from authlib.integrations.requests_client import OAuth2Session

def _get_jwt_token(auth_url: str, app_client_id: str, app_client_secret: str):
    """Connect to the server and get a JWT token."""
    token_endpoint = f"{auth_url}/oauth2/token"
    session = OAuth2Session(
        app_client_id, app_client_secret, scope="")
    token = session.fetch_token(token_endpoint, grant_type="client_credentials")
    return token["access_token"]

def _get_upload_file_json():
    """ Returns some example JSON file upload data. """
    document = {}
    document["document_id"] = "doc-id-1"
    # Note that the document ID must be unique for a given corpus
    document["title"] = "An example Title"
    document["metadata_json"] = json.dumps(
        {
            "book-name": "An example title",
            "collection": "Philosophy",
            "author": "Example Author"
        }
    )
    sections = []
    section = {}
    section["text"] = "An example text that needs to be indexed."
    sections.append(section)
    document["section"] = sections

    return json.dumps(document)

def upload_file(customer_id: int, corpus_id: int, idx_address: str, filepath: str, jwt_token: str):
    """ Uploads a file from the local file system to the corpus.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.

    """

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
    
    response = requests.post(
        f"https://h.{idx_address}/upload?c={customer_id}&o={corpus_id}",
        files=files,
        verify=True,
        headers=post_headers)

    if response.status_code != 200:
        logging.error("REST upload failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

def upload_dir(customer_id: int, corpus_id: int, idx_address: str, dirpath: str, jwt_token: str):
    """ Uploads files from the local file system to the corpus. This traverses all nested directories.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.

    """
    
    responses = {}

    for subdir, dirs, files in os.walk(dirpath):
        for file in files:
            filepath = os.path.join(subdir, file)
            print('\nUploading ' + filepath + '...')
            response, status = upload_file(customer_id,
                                      corpus_id,
                                      idx_address,
                                      filepath,
                                      jwt_token)
            logging.info("Upload File response: %s", response.text)
            responses[filepath] = response
            print('Uploaded ' + filepath)
    
    return responses, True

def upload_s3file(customer_id: int, corpus_id: int, idx_address: str, s3bucket: str, s3filepath: str, jwt_token: str):
    """ Upload a file from S3 to the corpus. This copies the file locally, uploads it, then deletes the local copy.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.

    """

    post_headers = {
        "Authorization": f"Bearer {jwt_token}"
    }

    s3 = boto3.client("s3")
    localfilename = '/tmp/' + os.path.basename(s3filepath)
    with open(localfilename, 'wb') as data:
        s3.download_fileobj(s3bucket, s3filepath, data)
        data.close()
        print('Copied s3 file locally for temporary usage: ' + localfilename)
    
    files={"file": (s3bucket + '/' + s3filepath, open(localfilename, 'rb'))}

    response = requests.post(
        f"https://h.{idx_address}/upload?c={customer_id}&o={corpus_id}",
        files=files,
        verify=True,
        headers=post_headers)

    os.remove(localfilename)
    print('Deleted locally copied s3 file: ' + localfilename)

    if response.status_code != 200:
        logging.error("REST upload failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

def upload_s3bucket(customer_id: int, corpus_id: int, idx_address: str, s3bucket: str, s3pathprefix: str, jwt_token: str):
    """ Uploads file from a S3 bucket to the corpus. This traverses all nested directories within the bucket.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        idx_address: Address of the indexing server. e.g., indexing.vectara.io
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.

    """
    
    s3filepaths = []
    responses = {}

    s3 = boto3.client("s3")
    all_objects = s3.list_objects_v2(Bucket = s3bucket, Prefix = s3pathprefix, MaxKeys=1000)
    #print(all_objects['Contents'])
    for s3object in all_objects['Contents']:
        if s3object['Key'][-1] != "/":
            s3filepaths.append(s3object['Key'])
    
    for s3filepath in s3filepaths:
        print('\nUploading ' + s3filepath + '...')
        response, status = upload_s3file(customer_id,
                                         corpus_id,
                                         idx_address,
                                         s3bucket,
                                         s3filepath,
                                         jwt_token)
        logging.info("Upload File response: %s", response.text)
        responses[s3filepath] = response
        print('Uploaded ' + s3filepath)
    
    return responses, True

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser(description="Vectara REST API example for uploading files. "
                                                 "If uploading from S3, store your credentials in ~/.aws/credentials.")

    parser.add_argument("--customer-id", type=int, required=True,
                        help="Unique customer ID in Vectara platform.")
    parser.add_argument("--corpus-id", type=int, required=True,
                        help="Corpus ID to which data will be indexed and queried from.")
    parser.add_argument("--indexing-endpoint", help="The endpoint of indexing server.",
                        default="indexing.vectara.io")
    parser.add_argument("--app-client-id",  required=True,
                        help="This app client should have enough rights.")
    parser.add_argument("--app-client-secret", required=True)
    parser.add_argument("--auth-url",  required=False,
                        help="The cognito auth url for this customer.")

    parser.add_argument("--local-file-path", help="Relative path to the file to upload to the corpus.")

    parser.add_argument("--local-dir-path", help="Relative path to the directory to upload to the corpus.")

    parser.add_argument("--s3-bucket", help="Bucket name to upload from. Just the name (e.g. mybucket) and "
                                            "not a full URI.")
    parser.add_argument("--s3-path-prefix", help="Path from the root of the bucket to the sub folder where the files "
                                                 "reside. Can be empty. Do not start or end with '/'. E.g. path/to/folder",
                        default="")

    args = parser.parse_args()

    if args:
        auth_url = args.auth_url
        if auth_url == "" or auth_url is None:
            auth_url = f"https://vectara-prod-{args.customer_id}.auth.us-west-2.amazoncognito.com"
        token = _get_jwt_token(auth_url, args.app_client_id, args.app_client_secret)

        if token:
            if args.local_file_path:
                error, status = upload_file(args.customer_id,
                                      args.corpus_id,
                                      args.indexing_endpoint,
                                      args.local_file_path,
                                      token)
                logging.info("Upload file response: %s", error.text)
            if args.local_dir_path:
                result, status = upload_dir(args.customer_id,
                                      args.corpus_id,
                                      args.indexing_endpoint,
                                      args.local_dir_path,
                                      token)
                logging.info("Upload directory response: %s", result)
            if args.s3_bucket:
                result, status = upload_s3bucket(args.customer_id,
                                      args.corpus_id,
                                      args.indexing_endpoint,
                                      args.s3_bucket,
                                      args.s3_path_prefix,
                                      token)
                logging.info("Upload S3 bucket response: %s", result)
        else:
            logging.error("Could not generate an auth token. Please check your credentials.")
