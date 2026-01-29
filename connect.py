from neo4j import GraphDatabase

uri = ""  
username = ""
password = ""

driver = GraphDatabase.driver(uri, auth=(username, password))

def close_driver(driver):
    driver.close()


def find_nodes_byRelation_inner(type,name, relation,tx):
    query = f"MATCH (c:{type} {{name: '{name}'}})-[r:{relation}]->(p) RETURN p.name AS name"
    result = tx.run(query)
    node_names = [record["name"] for record in result]
    return node_names

def find_nodes_byRelation(type,name,relation):
    return lambda tx: find_nodes_byRelation_inner(type,name,relation, tx)

def find_iv_inner(name, vul, tx):
    query = """
    MATCH (n:variable_type2 {name: $name})-[r:transform]->(m)
    WITH m
    MATCH (m)-[r:indirect]->(p:vulnerability {name: $vul})
    RETURN m.name AS name
    """
    result = tx.run(query, name=name, vul=vul)
    node_names = [record["name"] for record in result]

    query1 = """
    MATCH (n:member_variables {name: $name})-[r:transform]->(m)
    WITH m
    MATCH (m)-[r:indirect]->(p:vulnerability {name: $vul})
    RETURN m.name AS name
    """
    result1 = tx.run(query1, name=name, vul=vul)
    node_names1 = [record["name"] for record in result1]
    node_names1=node_names1+node_names
    unique_list = list(set(node_names1))
    return unique_list

def find_iv(name,vul):
    return lambda tx: find_iv_inner(name,vul, tx)

def find_vul_direct_inner(name,tx):
    query = f"MATCH (c:variable_type2 {{name: '{name}'}})-[r:direct]->(p) RETURN p.name AS name"
    result = tx.run(query)
    node_names = [record["name"] for record in result]

    query1 = f"MATCH (c:member_variables {{name: '{name}'}})-[r:direct]->(p) RETURN p.name AS name"
    result1 = tx.run(query1)
    node_names1 = [record["name"] for record in result1]
    node_names1=node_names1+node_names
    unique_list = list(set(node_names1))
    return unique_list

def find_vul_direct(name):
    return lambda tx: find_vul_direct_inner(name, tx)


# Find indirect vulnerabilities
def find_vul_indirect_inner(name,tx):
    query = f"MATCH (n:variable_type2{{name:'{name}'}})-[r:transform]->(m) with m match(m) -[r:indirect]->(p) RETURN p.name AS name"
    result = tx.run(query)
    node_names = [record["name"] for record in result]

    query1 = f"MATCH (n:member_variables{{name:'{name}'}})-[r:transform]->(m) with m match(m) -[r:indirect]->(p) RETURN p.name AS name"
    result1 = tx.run(query1)
    node_names1 = [record["name"] for record in result1]
    node_names1=node_names1+node_names
    unique_list = list(set(node_names1))
    return unique_list

def find_vul_indirect(name):
    return lambda tx: find_vul_indirect_inner(name, tx)

def find_fix_direct_inner(name,vul,tx):
    query = f"MATCH (c:variable_type2 {{name: '{name}'}})-[r:add]->(p),(v:vulnerability {{name: '{vul}'}})<-[f:fixed]-(fixedNode) WHERE p = fixedNode  RETURN p.name AS name"
    result = tx.run(query)
    node_names = [record["name"] for record in result]

    query1 = f"MATCH (c:member_variables {{name: '{name}'}})-[r:add]->(p),(v:vulnerability {{name: '{vul}'}})<-[f:fixed]-(fixedNode) WHERE p = fixedNode  RETURN p.name AS name"
    result1 = tx.run(query1)
    node_names1 = [record["name"] for record in result1]


    node_names1=node_names1+node_names
    unique_list = list(set(node_names1))
    return unique_list

def find_fix_direct(name, vul):
    if isinstance(name, list):
        name=name[0]
        print(name)
    return lambda tx: find_fix_direct_inner(name, vul, tx)


def find_fix_indirect_inner(name,vul,tx):
    query = f"MATCH (c:intermediate_variables {{name: '{name}'}})-[r:add]->(p),(v:vulnerability {{name: '{vul}'}})<-[f:fixed]-(fixedNode) WHERE p = fixedNode  RETURN p.name AS name"
    result = tx.run(query)
    node_names = [record["name"] for record in result]
    return node_names

def find_fix_indirect(name,vul):
    return lambda tx: find_fix_indirect_inner(name, vul, tx)

def run(fun_name,*args):
    with driver.session() as session:
        connected_nodes = session.read_transaction(fun_name(*args))
    close_driver(driver)
    
    return connected_nodes 
