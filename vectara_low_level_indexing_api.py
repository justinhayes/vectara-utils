import json
import requests


_CUSTOMER_ID=123456789
_CORPUS_ID=1
_API_KEY="zwt_..."

document = {}
document["document_id"] = "Book15.txt"
document["metadata_json"] = json.dumps(
        {
            "collection": "Mathematics",
            "author": "Justin"
        }
    )

parts = []

part = {}
part["text"] = "This was possibly the best purchase I have ever made."
part["metadata_json"] = json.dumps(
        {
            "reviewer": "Mike",
            "stars": 5
        }
    )
parts.append(part)

part = {}
part["text"] = "It is totally worth the wait!"
part["metadata_json"] = json.dumps(
        {
            "reviewer": "Susan",
            "stars": 4
        }
    )
parts.append(part)

document["parts"] = parts

request = {}
request['customer_id'] = _CUSTOMER_ID
request['corpus_id'] = _CORPUS_ID
request['document'] = document


post_headers = {
        "x-api-key": f"{_API_KEY}",
        "customer-id": f"{_CUSTOMER_ID}"
    }
response = requests.post(
    "https://api.vectara.io/v1/core/index",
    timeout=10,
    data=json.dumps(request),
    verify=True,
    headers=post_headers)

print(f"Response code {response.status_code}, reason {response.reason} text {response.text}")