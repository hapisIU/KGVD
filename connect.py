from neo4j import GraphDatabase


# 替换为你的Neo4j服务器的IP地址、端口、用户名和密码
uri = "bolt://222.20.126.121:7687"  
username = "neo4j"
password = "aptxr5116"

# 创建驱动程序实例
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
                                    

 #查找vul 直接
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


# 查找vul 间接
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
# 查找修补 
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

# 执行查询
def run(fun_name,*args):
    with driver.session() as session:
        connected_nodes = session.read_transaction(fun_name(*args))
    close_driver(driver)
    
    return connected_nodes
# a=run(find_iv,"AAAA","Array out of bounds")

# # b=run(find_fix_indirect,a[0],"Array out of bounds")

# result=run(find_fix_indirect,"iv(integer)","Function operation out of bounds")
# print(result)

# a=run(find_vul_direct,"direct_definition")

# 基本类型
# variable_type2 {name: "Integer"}           
# variable_type2 {name: "integer pointer"}   
# variable_type2 {name: "char pointer"}     
# variable_type2 {name: "pointer to pointer"}
# variable_type2 {name: "struct pointer"}   
# variable_type2 {name: "integer array"}
# variable_type2 {name: "char array"}

# 成员变量
# member_variables {name: "sp_integer"}
# member_variables {name: "sp_struct"}
# member_variables {name: "st.i"}    
# member_variables {name: "sp_cp"}

# intermediate_variables 中间变量
# intermediate_variables {name: "iv(integer)"}     
# intermediate_variables {name: "iv(integer pointer)"}
# intermediate_variables {name: "iv(sp)"} 
