from django.urls import path
from blockchain.utils import *
from blockchain.views import *

urlpatterns = [
    path('get_chain/', get_chain, name="get_chain"),
    path('mine_block/', mine_block, name="mine_block"),
    path('add_transaction/', add_transaction, name="add_transaction"),
    path('is_valid/', is_valid, name="is_valid"),
    path('connect_node/', connect_node, name="connect_node"),
    path('disconnect_node/', disconnect_node, name="disconnect_node"),
    path('replace_chain/', replace_chain, name="replace_chain"),
    path('get_nodes/', get_nodes, name="get_nodes"),
    path('home/', home, name="home"),
    path('login/', user_login, name="login"),
    path('join/', register, name="register"),
    path('logout/', logout, name="logout"),
    path('update_univ/', add_to_univ, name="add_to_univ"),
    path('get_univ_drugs/', get_univ_drugs, name="get_univ_drugs"),
    path('track/<str:drug_id>', track_product, name="track"),

    # Drug inventory management
    path('create_drug/', create_drug, name="create_drug"),
    path('add_to_inv/', add_to_inv, name="add_to_inv"),
    path('inventory/', inventory, name="inventory"),

    # transactions
    path('transfer/', transfer, name="transfer"),
    path('transactions/', transactions, name="transactions"),
    path('reports/', reports, name="reports"),
    path('', fp, name="fp"),

    path('news/', sitebreach, name="sitebreach"),
    
    path('search/', search, name="search"),
]
