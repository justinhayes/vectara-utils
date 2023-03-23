""" This is an example of calling the Vectara API to run a query.
It uses python and the REST API endpoint.
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

def _get_query_json(customer_id: int, corpus_id: int, query_value: str):
    """ Returns a query json. """
    query = {}
    query_obj = {}

    query_obj["query"] = query_value
    query_obj["num_results"] = 100

    corpus_key = {}
    corpus_key["customer_id"] = customer_id
    corpus_key["corpus_id"] = corpus_id

    query_obj["corpus_key"] = [ corpus_key ]
    query["query"] = [ query_obj ]
    return json.dumps(query)

def query(customer_id: int, corpus_id: int, query_address: str, jwt_token: str, query: str):
    """This method queries the data.
    Args:
        customer_id: Unique customer ID in vectara platform.
        corpus_id: ID of the corpus to which data needs to be indexed.
        query_address: Address of the querying server. e.g., serving.vectara.io
        jwt_token: A valid Auth token.

    Returns:
        (response, True) in case of success and returns (error, False) in case of failure.

    """

    post_headers = {
        "customer-id": f"{customer_id}",
        "Authorization": f"Bearer {jwt_token}"
    }

    response = requests.post(
        f"https://h.{query_address}/v1/query",
        data=_get_query_json(customer_id, corpus_id, query),
        verify=True,
        headers=post_headers)

    if response.status_code != 200:
        logging.error("Query failed with code %d, reason %s, text %s",
                       response.status_code,
                       response.reason,
                       response.text)
        return response, False
    return response, True

if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser(description="Vectara REST API example for executing a query")

    parser.add_argument("--customer-id", type=int, required=True,
                        help="Unique customer ID in Vectara platform.")
    parser.add_argument("--corpus-id", type=int, required=True,
                        help="Corpus ID to which data will be indexed and queried from.")
    parser.add_argument("--serving-endpoint", help="The endpoint of querying server.",
                        default="serving.vectara.io")
    parser.add_argument("--app-client-id",  required=True,
                        help="This app client should have enough rights.")
    parser.add_argument("--app-client-secret", required=True)
    parser.add_argument("--auth-url",  required=True,
                        help="The cognito auth url for this customer.")
    parser.add_argument("--query", help="Query to run against the corpus.", default="Test query")

    args = parser.parse_args()

    if args:
        token = _get_jwt_token(args.auth_url, args.app_client_id, args.app_client_secret)

        if token:
            error, status = query(args.customer_id,
                                  args.corpus_id,
                                  args.serving_endpoint,
                                  token,
                                  args.query)
            text_file = open("results.json", "w")
            n = text_file.write(error.text)
            text_file.close()
            logging.info("Query response written to results.json")
        else:
            logging.error("Could not generate an auth token. Please check your credentials.")
