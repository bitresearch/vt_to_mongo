import pymongo
import requests
import json

def VT_feed(sha256):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': '', 'resource': '', 'allinfo': '0'}
    params['resource'] = sha256

    response = requests.get(url, params=params)
    json_response = response.json()
    #print(json.dumps(json_response, sort_keys=False, indent=4))
    return json_response

def mongo_feeding(mongo_posts, json_object, sha256):
    try:
        result = mongo_posts.insert(json_object)
        print('one post: {0}'.format(result))
    except:
        print("insert error",sha256)
    return

def mongo_display(mongo_posts):
    file_info = mongo_posts.find()
    for post in file_info:
        print(post["sha256"])
        print(post)
    return

def main():
    client = pymongo.MongoClient('mongodb://localhost:27017')
    db = client.pymongo_vt_mongo
    mongo_posts = db.posts

    mongo_posts.create_index([('sha256', pymongo.ASCENDING)], unique=True)
    #mongo_display(mongo_posts)
    sha_fh = open("sha256.txt")
    while True:
        line = sha_fh.readline()
        #print(line)
        if not line:
            break
        json_object = VT_feed(line)
        if (json_object['response_code'] == 0):
            continue
        mongo_feeding(mongo_posts, json_object, line)

    sha_fh.close()
    mongo_display(mongo_posts)
    client.close()


if __name__ == "__main__":
    main()