"""
This is an example of using custom dimensions to implement a document feedback strategy. Each document has
a 'votes' custom dimension, which represents the number of votes (upvotes or downvotes) that the users give
to a document. It also has a 'votes' metadata field to record the current number of votes.

Run this example via the following series of commands:

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --operation create --name FeedbackTest
#Take note of the Corpus ID that is shown in the output. You will use it below for the corpus-id values

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --corpus-id 1 --operation index --dirpath "earnings-call-docs"

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --corpus-id 1 --operation query --query-str "low levels of liquidity"
#Take note of the score and number of votes for the document with ID 'Q&A-WFC-Fri., October 14, 2022'

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --corpus-id 1 --operation vote --new-votes 1 --metadata-json '{"id": "Q&A-WFC-Fri., October 14, 2022", "votes": 0, "filepath": "earnings-call-docs/WFC.json"}'

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --corpus-id 1 --operation query --query-str "low levels of liquidity"
#Take note of the new score and new number of votes for the document with ID 'Q&A-WFC-Fri., October 14, 2022'

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --corpus-id 1 --operation vote --new-votes 1 --metadata-json '{"id": "Q&A-WFC-Fri., October 14, 2022", "votes": 1, "filepath": "earnings-call-docs/WFC.json"}'

python3 vectara_feedback.py --app-client-id "..." --app-client-secret "..." --customer-id 12345678 --corpus-id 1 --operation query --query-str "low levels of liquidity"
#Take note of the new score and new number of votes for the document with ID 'Q&A-WFC-Fri., October 14, 2022'
"""

import argparse
import logging
import json
import requests
import os

from authlib.integrations.requests_client import OAuth2Session

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

def create_corpus(customer_id: int, jwt_token: str, name: str):
    """This creates a corpus with the correct settings.
    Args:
        customer_id: Unique customer ID in vectara platform.
        jwt_token: A valid Auth token.
        name: Name of the corpus to create.
    """

    post_headers = {
        "customer-id": f"{customer_id}",
        "Authorization": f"Bearer {jwt_token}"
    }

    corpus = {}
    corpus["name"] = name
    corpus["description"] = "A corpus to be used in the document feedback example."

    dims = {"name": "votes", "description": "Number of votes a document has received.",
            "servingDefault": 0, "indexingDefault": 0}
    corpus["customDimensions"] = [dims]

    response = requests.post(
        "https://api.vectara.io/v1/create-corpus",
        data=json.dumps({"corpus": corpus}),
        verify=True,
        headers=post_headers)

    if response.status_code != 200:
        logging.error("Create Corpus failed with code %d, reason %s, text %s",
                      response.status_code,
                      response.reason,
                      response.text)
        return response, False

    results = json.loads(response.text)
    logging.info("Corpus ID = " + str(results["corpusId"]))

    return response, True

def upload_doc(customer_id: int, corpus_id: int, jwt_token: str, filepath: str, votes: int):
    """ Uploads a file from the local file system to the corpus, via the FileUpload API.
    It adds a 'votes' custom dimension.

    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        filepath: Path to a single file to be uploaded.
        votes: Number to set in the 'votes' custom dimension.

    Returns:
        (response, True) in case of success and returns (response, False) in case of failure.
    """

    logging.info("Uploading " + filepath)

    post_headers = {
        "Authorization": f"Bearer {jwt_token}"
    }

    doc_metadata = {"filepath": f"{filepath}"}

    #TODO: add 'votes' custom dimension on the file, once that is supported with the FileUpload API

    doc_metadata_json = json.dumps(doc_metadata)
    files={"file": (filepath.replace("/", "_"), open(filepath, 'rb')), "doc_metadata": f"{doc_metadata_json}"}

    #If using the "d=true" option in the REST URL below then the response will include a "document" object
    #that is the structured text that was generated during the extraction stage within the ingest pipeline.
    response = requests.post(
        f"https://api.vectara.io/v1/upload?c={customer_id}&o={corpus_id}&d=false",
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

def index_doc(customer_id: int, corpus_id: int, jwt_token: str, filepath: str, votes: int):
    """ Indexes a document into the corpus, via the Index API. The contents are loaded from
    a file in the local file system. It adds a 'votes' custom dimension.

    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        filepath: Path to a single file, which contains the data to be indexed via the Index API
        votes: Number to set in the 'votes' custom dimension.

    Returns:
        (response, True) in case of success and returns (response, False) in case of failure.
    """

    logging.info("Indexing document that is loaded from " + filepath)

    post_headers = {
        "Authorization": f"Bearer {jwt_token}",
        "customer-id": f"{customer_id}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    #open file and load contents as JSON
    with open(filepath) as file:
        document = json.loads(file.read())

    #find metadata_json field at the document level to add metadata fields
    doc_metadata = json.loads(document["metadata_json"])
    #'filepath' - lets us know where to find the document in case we need to re-index it if it gets an upvote/downvote
    doc_metadata["filepath"] = filepath
    #'votes' - set this to the value we will set in the custom dimension, so we can know at result display time what
    #the new votes value should be when someone upvotes/downvotes
    doc_metadata["votes"] = votes
    document["metadata_json"] = json.dumps(doc_metadata)

    #add on 'votes' custom dimension
    document["customDims"] = [ {"name": "votes", "value": votes} ]
    logging.info(doc_metadata["filepath"] + " " + str(document["customDims"][0]["name"]) + "=" + str(document["customDims"][0]["value"]))

    index_obj = {"customer_id": customer_id, "corpus_id": corpus_id, "document": document}

    #call the Index API
    response = requests.request("POST", "https://api.vectara.io/v1/index",
                                headers=post_headers, data=json.dumps(index_obj))

    if response.status_code != 200:
        logging.error("REST upload failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

def index_dir(customer_id: int, corpus_id: int, jwt_token: str, dirpath: str):
    """ Indexes documents using the Index API, where the contents of each document is loaded from the
    files within a directory from the local file system. This includes all nested subdirectories.

    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        dirpath: Path to the directory from which to upload.

    Returns:
        (response, True) in case of success and returns (response, False) in case of failure.
    """
    responses = {}

    for subdir, dirs, files in os.walk(dirpath):
        for file in files:
            filepath = os.path.join(subdir, file)
            response, status = index_doc(customer_id,
                                           corpus_id,
                                           jwt_token,
                                           filepath,
                                           0)
            logging.info("Index document response: %s", response.text if status else response['text'])
            responses[filepath] = response

    return responses, True

def upload_dir(customer_id: int, corpus_id: int, jwt_token: str, dirpath: str):
    """ Uploads all files within a directory from the local file system to the corpus, using the
    FileUpload API. This includes all nested subdirectories.

    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        dirpath: Path to the directory from which to upload.

    Returns:
        (response, True) in case of success and returns (response, False) in case of failure.
    """
    responses = {}

    for subdir, dirs, files in os.walk(dirpath):
        for file in files:
            filepath = os.path.join(subdir, file)
            response, status = upload_doc(customer_id,
                                           corpus_id,
                                           jwt_token,
                                           filepath,
                                           0)
            logging.info("Upload file response: %s", response.text if status else response['text'])
            responses[filepath] = response

    return responses, True

def query(customer_id: int, corpus_id: int, jwt_token: str, query_str: str):
    """This method queries the data.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        query: The query to execute.
    """

    post_headers = {
        "customer-id": f"{customer_id}",
        "Authorization": f"Bearer {jwt_token}"
    }

    query = {}
    query_obj = {}

    query_obj["query"] = query_str
    query_obj["num_results"] = 10

    corpus_key = {}
    corpus_key["customer_id"] = customer_id
    corpus_key["corpus_id"] = corpus_id
    corpus_key["dim"] = [{"name": "votes", "weight": 0.01}]

    query_obj["corpus_key"] = [ corpus_key ]
    query["query"] = [ query_obj ]

    response = requests.post(
        "https://api.vectara.io/v1/query",
        data=json.dumps(query),
        verify=True,
        headers=post_headers)

    logging.info("Results:")

    results = json.loads(response.text)
    response_obj = results["responseSet"][0]

    i = 0
    for one_result in response_obj['response']:
        i += 1
        doc_obj = response_obj['document'][one_result['documentIndex']]
        votes = -1
        filepath = ""
        for doc_metadata in doc_obj['metadata']:
            if doc_metadata['name'] == "votes":
                votes = doc_metadata['value']
            if doc_metadata['name'] == "filepath":
                filepath = doc_metadata['value']
        logging.info(str(i) + ". {From doc with ID '" + doc_obj['id'] +
              "', votes=" + str(votes) + ", filepath=" + filepath + "}:\n[" +
              str(one_result['score']) + "] " + one_result['text'] + "\n")

    return response, True

def process_vote(customer_id: int, corpus_id: int, jwt_token: str, new_votes: int, metadata: {}):
    """ Processed a single upvote for a document, by deleting the document then re-uploading it
    with the new votes value.

    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        votes: Number of votes to add to the document's current number of votes.
        metadata: Dictionary containing metadata about the document.

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.
    """

    logging.info("Processing vote: " + metadata['id'] + " votes: " + str(metadata['votes']) + ' --> ' + str(metadata['votes'] + new_votes))

    delete_doc(customer_id, args.corpus_id, token, metadata['id'])

    index_doc(customer_id, args.corpus_id, token, metadata['filepath'], new_votes + metadata['votes'])

    return None, True

def delete_doc(customer_id: int, corpus_id: int, jwt_token: str, docid: str):
    """ Deletes a document from the corpus.

    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token.
        docid: Unique ID of the document.
    """

    logging.info("Deleting document with ID " + docid)

    post_headers = {
        "Authorization": f"Bearer {jwt_token}",
        "customer-id": f"{customer_id}"
    }

    request = {}
    request['customer_id'] = customer_id
    request['corpus_id'] = corpus_id
    request['document_id'] = docid

    response = requests.post(
        "https://api.vectara.io/v1/delete-doc",
        data=json.dumps(request),
        verify=True,
        headers=post_headers)

    if response.status_code != 200:
        logging.error("REST delete document failed with code %d, reason %s, text %s",
                      response.status_code,
                      response.reason,
                      response.text)
        return response, False
    return response, True


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser(description="Vectara REST API example for uploading files. "
                                                 "If uploading from S3, store your credentials in ~/.aws/credentials.")

    parser.add_argument("--customer-id", type=int, required=True,
                        help="Customer ID from your Vectara account.")
    parser.add_argument("--corpus-id", type=int,
                        help="ID of the corpus in which data will be indexed.")
    parser.add_argument("--app-client-id", required=True,
                        help="ID of an app client that has permission to index data in the corpus.")
    parser.add_argument("--app-client-secret", required=True,
                        help="Secret for an app client that has permission to index data in the corpus.")

    parser.add_argument("--operation", help="Which operation is being done: "
                                            "'create', 'upload', 'index', 'query', 'vote'.", default="query")
    parser.add_argument("--name", help="Name of the corpus to create.")
    parser.add_argument("--dirpath", help="Path to local directory whose contents should be uploaded.")
    parser.add_argument("--query-str", help="Query to run.")
    parser.add_argument("--new-votes", type=int, help="Number of votes to add to the "
                                                      "document's current total. Can be negative.")
    parser.add_argument("--metadata-json", help="Metadata of a document that is having a vote recorded. This should"
                                               "be a serialized JSON string.")

    args = parser.parse_args()

    if args:
        auth_url = f"https://vectara-prod-{args.customer_id}.auth.us-west-2.amazoncognito.com"
        token = get_jwt_token(auth_url, args.app_client_id, args.app_client_secret)

        if token:
            if args.operation == 'create':
                result = create_corpus(args.customer_id,
                                       token,
                                       args.name)
                logging.info("Create corpus response: \n%s", result)
            elif args.operation == 'index':
                result = index_dir(args.customer_id,
                                    args.corpus_id,
                                    token,
                                    args.dirpath)
                logging.info("Index dir response: \n%s", result)
            elif args.operation == 'upload':
                result = upload_dir(args.customer_id,
                                    args.corpus_id,
                                    token,
                                    args.dirpath)
                logging.info("Upload dir response: \n%s", result)
            elif args.operation == 'query':
                result = query(args.customer_id,
                                    args.corpus_id,
                                    token,
                                    args.query_str)
                logging.info("Query response: \n%s", result)
            elif args.operation == 'vote':
                metadata = json.loads(args.metadata_json)
                result = process_vote(args.customer_id,
                                    args.corpus_id,
                                    token,
                                    args.new_votes,
                                    metadata)
                logging.info("Process vote response: \n%s", result)
