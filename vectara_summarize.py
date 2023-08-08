""" This is an example of calling the Vectara search API via python using HTTP/REST as communication protocol.
    There are options for returning just a list of query results, and for returning that and also a summary.
"""

import argparse
import logging
import json
import requests
from authlib.integrations.requests_client import OAuth2Session

def _get_jwt_token(auth_url: str, app_client_id: str, app_client_secret: str):
    """Connect to the server and get a JWT token."""
    token_endpoint = f"{auth_url}/oauth2/token"
    session = OAuth2Session(
        app_client_id, app_client_secret, scope="")
    token = session.fetch_token(token_endpoint, grant_type="client_credentials")
    return token["access_token"]

def _get_summarize_json(customer_id: int, corpus_id: int, query_value: str, lambda_val: float):
    """ Returns a summarize json. """
    query = {}
    query_obj = {}

    query_obj["query"] = query_value
    query_obj["num_results"] = 25

    corpus_key = {}
    corpus_key["customer_id"] = customer_id
    corpus_key["corpus_id"] = corpus_id

    lexical_interpolation_config = {}
    lexical_interpolation_config["lambda"] = lambda_val
    corpus_key["lexical_interpolation_config"] = lexical_interpolation_config

    query_obj["corpus_key"] = [ corpus_key ]

    context_config = {}
    context_config["sentences_before"] = 2
    context_config["sentences_after"] = 2
    context_config["start_tag"] = "<b>"
    context_config["end_tag"] = "</b>"

    query_obj["context_config"] = context_config

    summary = {}
    summary["summarizerPromptName"] = "vectara-summary-ext-v1.2.0"
    summary["maxSummarizedResults"] = 3
    summary["responseLang"] = "auto"

    query_obj["summary"] = summary

    query["query"] = [ query_obj ]
    return json.dumps(query)

def summarize(customer_id: int, corpus_id: int, jwt_token: str, query: str, lambda_val: float):
    """This method queries the data and returns a list of results as well as a summary.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        jwt_token: A valid Auth token
        query: The query to run

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.
    """
    post_headers = {
        "customer-id": f"{customer_id}",
        "Authorization": f"Bearer {jwt_token}",
        "grpc-timeout": "60S"
    }

    response = requests.post(
        "https://api.vectara.io/v1/query",
        data=_get_summarize_json(customer_id, corpus_id, query, lambda_val),
        verify=True,
        headers=post_headers)

    if response.status_code != 200:
        logging.error("Summarize failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser(description="Vectara gRPC example")

    parser.add_argument("--customer-id", type=int, required=True,
                        help="Unique customer ID in Vectara platform.")
    parser.add_argument("--corpus-id", type=int, required=True,
                        help="Corpus ID to which data will be indexed and queried from.")

    parser.add_argument("--app-client-id",  required=True,
                        help="This app client should have enough rights.")
    parser.add_argument("--app-client-secret", required=True)
    parser.add_argument("--auth-url",  required=False,
                        help="The cognito auth url for this customer.")

    parser.add_argument("--query", help="Query to run against the corpus to get a list of search results.",
                        default="Test query")
    parser.add_argument("--lambda-val", help="Float that controls how much to weight the hybrid search towards "
                                             "semantic matching vs keyword-style lexical matching. "
                                             "If lambda=0 then it is pure semantic. If lambda=1 then it is "
                                             "pure lexical. A good value to use is usually somewhere "
                                             "between 0.015 and 0.025.",
                        default=0.025)

    args = parser.parse_args()

    if args:
        auth_url = args.auth_url
        if auth_url == "" or auth_url is None:
            auth_url = f"https://vectara-prod-{args.customer_id}.auth.us-west-2.amazoncognito.com"

        token = _get_jwt_token(auth_url, args.app_client_id, args.app_client_secret)

        if token:
            if args.query:
                response, status = summarize(args.customer_id,
                                      args.corpus_id,
                                      token,
                                      args.query,
                                      args.lambda_val)
                text_file = open("results.json", "w")
                n = text_file.write(response.text)
                text_file.close()
                logging.info("Response written to results.json")
            else:
                logging.error("There is not a query to run.")
        else:
            logging.error("Could not generate an auth token. Please check your credentials.")
