from django.shortcuts import render
import datetime
import hashlib
import json
from uuid import uuid4
import socket
from urllib.parse import urlparse
from django.http import JsonResponse, HttpResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
import requests
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.contrib.auth import get_user_model
import socket

User = get_user_model()


def connecting_logged_in_users(request):
    users = User.objects.all().exclude(node_address='')
    print(users)
    data = '{"nodes":['
    for user in users:
        data += '"' + user.node_address + '",'

    host_name = socket.gethostname()
    host_ip = socket.gethostbyname(host_name)
    data += '"http://' + "127.0.0.1" + \
        ':8000/"'
    data += ']}'
    print(data)
    for user in users:
        print(user.node_address)
        requests.post(user.node_address +
                      'connect_node/', data=data)
    # return requests.get(user.node_address+'get_nodes/').json()
    return User.objects.all().exclude(node_address='')


def disconnecting(request):
    # Query all non-expired sessions
    # use timezone.now() instead of datetime.now() in latest versions of Django
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
    uid_list = []

    # Build a list of user ids from that query
    for session in sessions:
        data = session.get_decoded()
        uid_list.append(data.get('_auth_user_id', None))

    # Query all logged in users based on id list
    users = User.objects.filter(id__in=uid_list, is_superuser=False)
    users = User.objects.all().exclude(node_address='')
    print(users)
    data = '{"nodes":["' + request.user.node_address + '"]}'
    print(data)
    for user in users:
        requests.post(user.node_address +
                      'disconnect_node/', data=data)
    return requests.get(request.user.node_address+'get_nodes/').json()


class Blockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(nonce=1, previous_hash='0')
        self.nodes = set()
        self.univ_drugs = []
        self.inv_drugs = []

    def create_block(self, nonce, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'nonce': nonce,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions}
        self.transactions = []
        self.chain.append(block)
        return block

    def get_last_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_nonce):
        new_nonce = 1
        check_nonce = False
        while check_nonce is False:
            hash_operation = hashlib.sha256(
                str(new_nonce**2 - previous_nonce**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_nonce = True
            else:
                new_nonce += 1
        return new_nonce

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_nonce = previous_block['nonce']
            nonce = block['nonce']
            hash_operation = hashlib.sha256(
                str(nonce**2 - previous_nonce**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transaction(self, sender, receiver, drug_id):
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'drug_id': drug_id,
                                  'time': str(datetime.datetime.now())})
        previous_block = self.get_last_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        parsed_url = urlparse(address)
        print("NODES=", self.nodes)
        self.nodes.add(parsed_url.netloc)

    def remove_node(self, address):
        print("hiii")
        parsed_url = urlparse(address)
        self.nodes.discard(parsed_url.netloc)
        print("DISCARDED=", parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        print(network)
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain/')
            print(response)
            print(type(response.status_code))
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    print("Replaced")
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            print("!!!")
            self.chain = longest_chain
            return True
        return False


# Creating our Blockchain
blockchain = Blockchain()
# Creating an address for the node running our server
node_address = str(uuid4()).replace('-', '')
root_node = 'e36f0158f0aed45b3bc755dc52ed4560d'

# Mining a new block


def mine_block(request):
    if request.method == 'GET':
        previous_block = blockchain.get_last_block()
        previous_nonce = previous_block['nonce']
        nonce = blockchain.proof_of_work(previous_nonce)
        previous_hash = blockchain.hash(previous_block)
        block = blockchain.create_block(nonce, previous_hash)
        response = {'message': 'Congratulations, you just mined a block!',
                    'index': block['index'],
                    'timestamp': block['timestamp'],
                    'nonce': block['nonce'],
                    'previous_hash': block['previous_hash'],
                    'transactions': block['transactions']}
    return JsonResponse(response)

# Getting the full Blockchain


def get_chain(request):
    if request.method == 'GET':
        response = {'chain': blockchain.chain,
                    'length': len(blockchain.chain)}
    return JsonResponse(response)

# Checking if the Blockchain is valid


def is_valid(request):
    if request.method == 'GET':
        is_valid = blockchain.is_chain_valid(blockchain.chain)
        if is_valid:
            response = {'message': 'All good. The Blockchain is valid.'}
        else:
            response = {
                'message': 'Houston, we have a problem. The Blockchain is not valid.'}
    return JsonResponse(response)

# Adding a new transaction to the Blockchain
@csrf_exempt
def add_transaction(request):
    if request.method == 'POST':
        print(request.body)
        received_json = json.loads(request.body)
        print(received_json)
        transaction_keys = ['sender', 'receiver', 'drug_id']
        if not all(key in received_json for key in transaction_keys):
            return 'Some elements of the transaction are missing', HttpResponse(status=400)
        index = blockchain.add_transaction(
            received_json['sender'], received_json['receiver'], received_json['drug_id'])
        response = {
            'message': f'This transaction will be added to Block {index}'}
    return JsonResponse(response)

# Connecting new nodes
@csrf_exempt
def connect_node(request):
    if request.method == 'POST':
        received_json = json.loads(request.body)
        nodes = received_json.get('nodes')
        if nodes is None:
            return "No node", HttpResponse(status=400)

        for node in nodes:
            blockchain.add_node(node)
        response = {'message': 'All the nodes are now connected. The Sudocoin Blockchain now contains the following nodes:',
                    'total_nodes': list(blockchain.nodes)}
    return JsonResponse(response)

# Disconnecting new nodes
@csrf_exempt
def disconnect_node(request):
    if request.method == 'POST':
        received_json = json.loads(request.body)
        nodes = received_json.get('nodes')
        if nodes is None:
            return "No node", HttpResponse(status=400)
        for node in nodes:
            blockchain.remove_node(node)
        response = {'message': 'All the nodes are now connected. The Sudocoin Blockchain now contains the following nodes:',
                    'total_nodes': list(blockchain.nodes)}
    return JsonResponse(response)


@csrf_exempt
def add_to_univ(request):
    if request.method == 'POST':
        received_json = json.loads(request.body)
        drugs = received_json.get('drugs')
        if drugs is None:
            return "No drugs", HttpResponse(status=400)
        for drug in drugs:
            if drug not in blockchain.univ_drugs:
                blockchain.univ_drugs.append(drug)
        response = {'message': 'All drugs added to universal list.',
                    'drugs': list(blockchain.univ_drugs)}
    return JsonResponse(response)


@csrf_exempt
def get_nodes(request):
    return JsonResponse({"nodes": list(blockchain.nodes), })


# Replacing the chain by the longest chain if needed
@csrf_exempt
def replace_chain(request):
    if request.method == 'GET':
        is_chain_replaced = blockchain.replace_chain()
        resonse = {}
        if is_chain_replaced:
            response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                        'new_chain': blockchain.chain}
        else:
            response = {'message': 'All good. The chain is the largest one.',
                        'actual_chain': blockchain.chain}
    return JsonResponse(response)


# Connecting new nodes
@csrf_exempt
def add_to_inv(request):
    if request.method == 'POST':
        received_json = json.loads(request.body)
        drugs = received_json.get('drugs')
        if drugs is None:
            return "No drug", HttpResponse(status=400)

        for drug in drugs:
            blockchain.inv_drugs.append(drug)
        response = {'message': 'Drugs in inventory:',
                    'total_drugs': list(blockchain.inv_drugs)}
    return JsonResponse(response)


@csrf_exempt
def add_to_someones_inv(user, new_drugs):
    if user.node_address != '':
        for new_drug in new_drugs:
            data = '{"drugs":[{"drug_name": "' + new_drug["drug_name"] + '", "drug_id": "' + new_drug["drug_id"] + \
                '", "dom": "' + new_drug["dom"] + '", "doe": "' + \
                new_drug["dom"]
            data += '}}]}'
            print(data)
            print()
            requests.post(user.node_address+'add_to_inv/', data=data)
    response = {'message': 'Drug added in inventory:',
                'total_drugs': list(blockchain.inv_drugs)}
    return JsonResponse(response)


@csrf_exempt
def replace_chain_in_all_nodes():
    users = User.objects.all().exclude(node_address='')
    for user in users:
        requests.get(user.node_address +
                     'replace_chain/')

    host_name = socket.gethostname()
    host_ip = socket.gethostbyname(host_name)
    url = "http://" + "127.0.0.1" + \
        ":8000/"
    requests.post(url)


@csrf_exempt
def get_univ_drugs(request):
    return JsonResponse({"drugs": list(blockchain.univ_drugs), })




def track_product(request,drug_id):
    print(drug_id)
    data = requests.get(request.user.node_address+"get_nodes/")
    print(json.loads(data.text))
    json_obj = json.loads(data.text)
    if drug_id not in blockchain.univ_drugs:
        mylist = []
        for entry in blockchain.chain:
            for transaction in entry["transactions"]:
                if str(transaction["drug_id"]) == str(drug_id):
                    mylist.append(transaction)

        print(mylist)
        if len(mylist) != 0:
            return render(request, 'track_drug.html', { 
        'network': json_obj["nodes"], 'drug_id': drug_id , 'man_date': mylist[0]['time'].split(" ")[0] , 'response' : mylist })
    return render(request, 'track_drug.html', { 'drug_id': "N.A." , 'man_date': "N.A." , 'response' : mylist })
    
